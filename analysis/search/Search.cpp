#include "analysis/search/Search.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <regex>
#include <unordered_map>

#include "core/ioctl/IoctlCodec.h"

namespace dasa::analysis {

const char* searchKindName(SearchKind k) {
    switch (k) {
    case SearchKind::Function: return "Function";
    case SearchKind::Import: return "Import";
    case SearchKind::Export: return "Export";
    case SearchKind::String: return "String";
    case SearchKind::Instruction: return "Instruction";
    case SearchKind::Ioctl: return "IOCTL";
    case SearchKind::Device: return "Device";
    case SearchKind::Finding: return "Finding";
    }
    return "";
}

namespace {

bool printable(std::uint32_t c) {
    return (c >= 0x20 && c < 0x7F) || c == '\t';
}

std::string hex(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

std::vector<FoundString> extractStrings(const core::pe::PEImage& image, std::size_t minLength) {
    std::vector<FoundString> out;
    for (const auto& sec : image.sections) {
        if (sec.isExecutable()) {
            continue;
        }
        const auto bytes = image.bytesAt(sec.virtualAddress);
        const std::size_t size = std::min<std::size_t>(bytes.size(), std::max(sec.virtualSize, sec.rawSize));
        // ASCII runs.
        std::size_t start = 0;
        for (std::size_t i = 0; i <= size; ++i) {
            if (i < size && printable(bytes[i])) {
                continue;
            }
            if (i - start >= minLength) {
                out.push_back({sec.virtualAddress + start,
                               std::string(reinterpret_cast<const char*>(bytes.data() + start), i - start), false,
                               sec.name});
            }
            start = i + 1;
        }
        // UTF-16LE runs (ASCII range), at even and odd alignment.
        for (std::size_t align = 0; align < 2; ++align) {
            std::string run;
            std::size_t runStart = align;
            for (std::size_t i = align; i + 1 < size + 2; i += 2) {
                const bool ok = i + 1 < size && printable(bytes[i]) && bytes[i + 1] == 0;
                if (ok) {
                    if (run.empty()) {
                        runStart = i;
                    }
                    run.push_back(static_cast<char>(bytes[i]));
                    continue;
                }
                if (run.size() >= minLength) {
                    out.push_back({sec.virtualAddress + runStart, run, true, sec.name});
                }
                run.clear();
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const FoundString& a, const FoundString& b) { return a.rva < b.rva; });
    return out;
}

SearchResults search(const AnalysisResult& r, const std::string& query, const SearchOptions& opt) {
    SearchResults res;
    if (query.empty()) {
        return res;
    }
    std::function<bool(const std::string&)> matches;
    std::regex re;
    if (opt.regex) {
        try {
            re = std::regex(query, opt.caseSensitive ? std::regex::ECMAScript
                                                     : std::regex::ECMAScript | std::regex::icase);
        } catch (const std::regex_error& e) {
            res.error = std::string("Invalid regular expression: ") + e.what();
            return res;
        }
        matches = [&](const std::string& s) { return std::regex_search(s, re); };
    } else if (opt.caseSensitive) {
        matches = [&](const std::string& s) { return s.find(query) != std::string::npos; };
    } else {
        const std::string q = lower(query);
        matches = [q](const std::string& s) { return lower(s).find(q) != std::string::npos; };
    }

    auto add = [&](SearchHit hit) {
        if (res.hits.size() >= opt.limit) {
            res.truncated = true;
            return false;
        }
        res.hits.push_back(std::move(hit));
        return true;
    };
    auto wanted = [&](SearchKind k) { return (opt.kinds & static_cast<std::uint32_t>(k)) != 0; };
    const auto& set = *r.functions;
    auto fnName = [&](std::uint64_t rva) {
        const auto* f = set.find(rva);
        return f ? f->name : hex(rva);
    };

    if (wanted(SearchKind::Function)) {
        for (const auto& f : set.functions) {
            if (matches(f.name) || matches(hex(f.rva))) {
                if (!add({SearchKind::Function, f.name, hex(f.rva), f.rva, f.rva})) return res;
            }
        }
    }

    // First function that calls each import, for context and navigation.
    std::unordered_map<std::string, std::uint64_t> firstCaller;
    for (const auto& f : set.functions) {
        for (const auto& c : f.calls) {
            if (!c.importName.empty()) {
                firstCaller.emplace(c.importName, f.rva);
            }
        }
    }
    if (wanted(SearchKind::Import)) {
        for (const auto& lib : r.image->imports) {
            for (const auto& fn : lib.functions) {
                const std::string name = fn.name.empty() ? "#" + std::to_string(fn.ordinal.value_or(0)) : fn.name;
                if (!matches(name)) {
                    continue;
                }
                const auto it = firstCaller.find(lib.name + "!" + name);
                SearchHit h{SearchKind::Import, name, lib.name, fn.iatRva, std::nullopt};
                if (it != firstCaller.end()) {
                    h.context += ", called in " + fnName(it->second);
                    h.function = it->second;
                } else {
                    h.context += ", no call site found";
                }
                if (!add(std::move(h))) return res;
            }
        }
    }
    if (wanted(SearchKind::Export)) {
        for (const auto& e : r.image->exports) {
            if (matches(e.name)) {
                if (!add({SearchKind::Export, e.name, "ordinal " + std::to_string(e.ordinal), e.rva,
                          set.find(e.rva) ? std::optional<std::uint64_t>(e.rva) : std::nullopt}))
                    return res;
            }
        }
    }
    if (wanted(SearchKind::String)) {
        std::unordered_map<std::uint64_t, std::uint64_t> referencedBy; // string RVA -> function
        for (const auto& f : set.functions) {
            for (const auto& i : f.instructions) {
                for (const auto& ref : {i.memoryRef, i.immediateRef}) {
                    if (ref) {
                        referencedBy.emplace(*ref, f.rva);
                    }
                }
            }
        }
        for (const auto& s : extractStrings(*r.image)) {
            if (!matches(s.text)) {
                continue;
            }
            SearchHit h{SearchKind::String, s.text, s.section + (s.utf16 ? " (UTF-16)" : " (ASCII)"), s.rva,
                        std::nullopt};
            if (const auto it = referencedBy.find(s.rva); it != referencedBy.end()) {
                h.context += ", used in " + fnName(it->second);
                h.function = it->second;
            }
            if (!add(std::move(h))) return res;
        }
    }
    if (wanted(SearchKind::Instruction)) {
        for (const auto& f : set.functions) {
            for (const auto& i : f.instructions) {
                const std::string text = i.text();
                if (matches(text)) {
                    if (!add({SearchKind::Instruction, text, f.name, i.rva, f.rva})) return res;
                }
            }
        }
    }
    if (wanted(SearchKind::Ioctl)) {
        for (const auto& e : r.ioctls->ioctls) {
            const std::string code = core::ioctl::hexCode(e.decoded.code);
            const std::string desc = code + " " + core::ioctl::methodName(e.decoded.method) + " " +
                                     core::ioctl::accessName(e.decoded.access);
            if (matches(desc) || matches(e.handler)) {
                if (!add({SearchKind::Ioctl, desc, e.handler + ", compared in " + fnName(e.comparedIn), e.at,
                          e.comparedIn}))
                    return res;
            }
        }
    }
    if (wanted(SearchKind::Device)) {
        for (const auto& d : r.devices->devices) {
            if (!d.name.empty() && matches(d.name)) {
                if (!add({SearchKind::Device, d.name, d.api + " in " + fnName(d.inFunction), d.at, d.inFunction}))
                    return res;
            }
        }
        for (const auto& l : r.devices->symbolicLinks) {
            if (!l.link.empty() && matches(l.link)) {
                if (!add({SearchKind::Device, l.link, "symbolic link (" + l.api + ")", std::nullopt, std::nullopt}))
                    return res;
            }
        }
    }
    if (wanted(SearchKind::Finding)) {
        for (const auto& f : r.findings->findings) {
            if (matches(f.title) || matches(f.ruleId) || matches(f.description)) {
                std::optional<std::uint64_t> fn, at;
                if (!f.evidence.empty() && !f.evidence.front().empty()) {
                    const auto& last = f.evidence.front().back();
                    fn = last.function;
                    at = last.rva;
                }
                if (!add({SearchKind::Finding, f.title, f.ruleId, at, fn})) return res;
            }
        }
    }
    return res;
}

} // namespace dasa::analysis
