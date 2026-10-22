#include "analysis/report/PlainLanguage.h"

#include <algorithm>
#include <map>
#include <set>

#include "core/security/ApiCatalog.h"

namespace dasa::analysis {

namespace fnd = core::findings;
namespace sec = core::security;

const char* verdictName(Verdict v) {
    switch (v) {
    case Verdict::Safe: return "Safe";
    case Verdict::WorthALook: return "Worth a look";
    case Verdict::Risky: return "Risky";
    case Verdict::Dangerous: return "Dangerous";
    }
    return "";
}

namespace {

// Same split as the finding rules: handlers that serve requests from
// user-mode programs, versus internal requests from other drivers.
bool isUserRequestRole(const std::string& role) {
    if (role.find("INTERNAL") != std::string::npos || role.find("Internal") != std::string::npos) {
        return false;
    }
    return role == "IRP_MJ_DEVICE_CONTROL" || role == "IRP_MJ_READ" || role == "IRP_MJ_WRITE" ||
           role.rfind("EvtIo", 0) == 0;
}

std::string seriousness(fnd::Severity s) {
    switch (s) {
    case fnd::Severity::Critical: return "Serious";
    case fnd::Severity::High: return "High";
    case fnd::Severity::Medium: return "Moderate";
    case fnd::Severity::Low: return "Minor";
    case fnd::Severity::Info: break;
    }
    return "Note";
}

// What a category of reachable capability lets the driver do, said plainly.
const char* capabilitySentence(sec::ApiCategory c) {
    switch (c) {
    case sec::ApiCategory::PhysicalMemory:
        return "Read or change your computer's physical memory - where everything, including Windows itself, lives.";
    case sec::ApiCategory::VirtualMemory:
        return "Read or change the memory of other programs or of Windows.";
    case sec::ApiCategory::Process:
        return "Open, inspect or stop other programs running on the PC.";
    case sec::ApiCategory::Token:
        return "Change what programs are allowed to do (their privileges).";
    case sec::ApiCategory::DriverLoading:
        return "Load other drivers into Windows.";
    case sec::ApiCategory::Hardware:
        return "Talk directly to hardware or change low-level processor settings.";
    case sec::ApiCategory::Registry:
        return "Read or change Windows settings in the registry.";
    case sec::ApiCategory::FileSystem:
        return "Read, change or delete files.";
    case sec::ApiCategory::Callbacks:
        return "Watch what happens on the system, such as programs starting or files being opened.";
    default:
        break;
    }
    return nullptr;
}

// The call or instruction a finding is about: the last Call/Instruction step
// of its first evidence chain (notes may follow it), without the
// "(instruction)" style suffix.
std::string sinkOf(const fnd::Finding& f) {
    if (f.evidence.empty()) {
        return {};
    }
    const auto& chain = f.evidence.front();
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        if (it->kind == fnd::EvidenceStep::Kind::Call || it->kind == fnd::EvidenceStep::Kind::Instruction) {
            std::string label = it->label;
            if (const auto paren = label.find(" ("); paren != std::string::npos) {
                label = label.substr(0, paren);
            }
            return label;
        }
    }
    return {};
}

// "MmMapIoSpace (maps physical memory ...)" / "a processor instruction that
// changes processor settings" - the sink described for a non-expert.
std::string describeSink(const fnd::Finding& f, const std::string& sink) {
    if (sink.empty()) {
        return "a powerful Windows function";
    }
    const std::string m = sink.substr(0, sink.find(' '));
    if (m == "wrmsr" || m == "rdmsr") return "a processor instruction that reads or changes processor settings";
    if (m == "in" || m == "out" || m.rfind("ins", 0) == 0 || m.rfind("outs", 0) == 0)
        return "an instruction that talks directly to hardware";
    if (m == "mov") return "an instruction that changes core processor settings";
    if (m == "lgdt" || m == "lidt" || m == "cli" || m == "hlt") return "a low-level processor instruction";
    const auto info = core::security::classifyApi(sink);
    (void)f;
    if (const char* sentence = capabilitySentence(info.category)) {
        // "Read or change ... lives." -> "lets it read or change ... lives"
        std::string s = sentence;
        s[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));
        if (!s.empty() && s.back() == '.') s.pop_back();
        return "the Windows function " + sink + ", which lets it " + s;
    }
    return "the Windows function " + sink;
}

bool hasNote(const fnd::Finding& f, const std::string& label) {
    for (const auto& chain : f.evidence) {
        for (const auto& step : chain) {
            if (step.kind == fnd::EvidenceStep::Kind::Note && step.label == label) {
                return true;
            }
        }
    }
    return false;
}

// A reachability finding whose call data flow already proved controllable
// (there is a DASA-TAINT finding for it) - the same problem said twice.
bool coveredByDataFlow(const fnd::Finding& f) {
    if (f.ruleId.rfind("DASA-REACH", 0) != 0) {
        return false;
    }
    for (const auto& chain : f.evidence) {
        for (const auto& step : chain) {
            if (step.kind == fnd::EvidenceStep::Kind::Note &&
                step.label == "Data flow: request data reaches this operation") {
                return true;
            }
        }
    }
    return false;
}

PlainProblem plainFor(const fnd::Finding& f, std::size_t index) {
    PlainProblem p;
    p.seriousness = seriousness(f.severity);
    p.findingIndex = index;
    const std::string& id = f.ruleId;
    const std::string sink = sinkOf(f);

    if (id == "DASA-TAINT-API") {
        p.headline = "Programs can control a sensitive Windows function this driver uses.";
        p.explanation = "Data that a program sends to the driver is passed into " + describeSink(f, sink) +
                        ". As far as DASA can tell there is no check in between, so the driver " +
                        [&] {
                            // Flow impacts read "maps physical memory at an address the caller chooses".
                            std::string impact = f.description.substr(0, f.description.find('.'));
                            const auto pos = impact.find("the caller");
                            if (pos != std::string::npos) impact.replace(pos, 10, "the program");
                            return impact + ".";
                        }();
        p.consequence = "Depending on the function, malware could read or change memory it should never touch and "
                        "possibly take full control of the PC.";
    } else if (id == "DASA-TAINT-INSTRUCTION") {
        p.headline = "Programs can change low-level processor settings through this driver.";
        p.explanation = "Values sent by a program end up in " + describeSink(f, sink) +
                        " - something normally only Windows itself should do.";
        p.consequence = "This can let malware run its own code with the highest privileges, or crash the PC.";
    } else if (id == "DASA-TAINT-WRITE") {
        p.headline = "Programs can make this driver write to any place in memory.";
        p.explanation = "The driver takes a memory address from the data a program sends and writes to it.";
        p.consequence = "This is one of the most serious kinds of driver bug: malware can use it to take full "
                        "control of the PC.";
    } else if (id == "DASA-TAINT-READ") {
        p.headline = "Programs can make this driver read from any place in memory.";
        p.explanation = "The driver takes a memory address from the data a program sends and reads from it.";
        p.consequence = "This can leak passwords and other secrets and helps attackers break other protections.";
    } else if (id == "DASA-UNPROBED-USER-POINTER") {
        p.headline = "The driver trusts memory addresses from programs without checking them.";
        p.explanation = "A program can hand the driver an address, and the driver uses it without the standard "
                        "safety check that it really belongs to that program.";
        p.consequence = "A program could pass an address inside Windows itself - crashing the PC or reading/changing "
                        "protected memory.";
    } else if (id == "DASA-REACH-CRITICAL" || id == "DASA-REACH-HIGH") {
        p.headline = "The driver has a powerful ability that programs can trigger.";
        p.explanation = "It uses " + describeSink(f, sink) + ", in code that runs when a program sends it a request.";
        p.consequence = hasNote(f, "Data flow: the arguments are constants")
                            ? "DASA checked the values it uses: they are fixed inside the driver, so a program can "
                              "trigger it but not steer it. Still worth knowing about."
                            : "If a program can influence what it does, malware could abuse it. DASA did not find "
                              "proof of that - see the technical details.";
    } else if (id == "DASA-REACH-INTERNAL") {
        p.headline = "Other drivers can trigger a powerful ability of this driver.";
        p.explanation = "It uses " + describeSink(f, sink) +
                        ", in code that handles requests from other drivers (not directly from programs).";
        p.consequence = "Lower risk: only software already running inside Windows can reach it.";
    } else if (id == "DASA-DEVICE-NO-SECURE-OPEN") {
        p.headline = "The driver's access protection has a known gap.";
        p.explanation = "It creates its device without an option that makes Windows apply the same access rules to "
                        "every way of opening it.";
        p.consequence = "Programs that shouldn't be allowed in may be able to open the driver through a side path.";
    } else if (id == "DASA-DEVICE-DEFAULT-ACL") {
        p.headline = "Anyone on this PC may be able to talk to this driver.";
        p.explanation = "It has a public name, and its code sets no restriction on who may open it - Windows' "
                        "default rules then usually let every program in.";
        p.consequence = "Every other problem in this list could then be triggered by any program, not just by "
                        "administrators.";
    } else if (id == "DASA-UNPROTECTED-SYMLINK") {
        p.headline = "The driver's public name isn't protected.";
        p.explanation = "It creates its public name in a way that lets other software replace or redirect it.";
        p.consequence = "Programs could be tricked into talking to something else.";
    } else if (id == "DASA-METHOD-NEITHER") {
        p.headline = "The driver handles program data in a risky way.";
        p.explanation = "For some requests it reads and writes the program's memory directly instead of letting "
                        "Windows copy the data safely.";
        p.consequence = "This is easy to get wrong and a common source of serious driver bugs.";
    } else if (id == "DASA-ANY-ACCESS") {
        p.headline = "Some requests don't require any permission.";
        p.explanation = "A program that opened the driver without asking for read or write rights can still send "
                        "these requests.";
        p.consequence = "It removes one layer of protection; it matters when combined with the problems above.";
    } else if (id == "DASA-RUNTIME-RESOLVED") {
        p.headline = "The driver looks up Windows functions by name while it runs.";
        p.explanation = "Instead of listing everything it uses up front, it finds some functions at run time.";
        p.consequence = "This is sometimes used to hide what a driver does; often it's harmless compatibility code.";
    } else if (id == "DASA-SYSTEM-CALLBACKS") {
        p.headline = "The driver watches activity on the whole system.";
        p.explanation = "It asks Windows to notify it when, for example, programs start or files are opened.";
        p.consequence = "Normal for antivirus and monitoring tools; worth questioning for anything else.";
    } else if (id == "DASA-UNCALLED-CRITICAL-IMPORT") {
        p.headline = "The driver includes a powerful function it doesn't seem to use.";
        p.explanation = "It lists " + describeSink(f, sink) + ", but DASA found no place where it's used.";
        p.consequence = "Probably leftover code; it could also be called in a way DASA can't see.";
    } else if (id == "DASA-WX-SECTION") {
        p.headline = "Part of the driver can be changed while it runs.";
        p.explanation = "One section of the file is both writable and executable.";
        p.consequence = "That makes it easier for an attacker to plant code.";
    } else if (id == "DASA-NO-NX" || id == "DASA-NO-ASLR") {
        p.headline = "The driver was built without a standard security protection.";
        p.explanation = id == "DASA-NO-NX" ? "It isn't marked to keep code and data strictly separate (NX)."
                                           : "It isn't marked for address randomisation (ASLR).";
        p.consequence = "It doesn't create a hole by itself but makes other bugs easier to exploit.";
    } else if (id == "DASA-NO-EMBEDDED-SIGNATURE") {
        p.headline = "The file isn't signed inside.";
        p.explanation = "There is no digital signature in the file. Windows can also trust drivers through "
                        "separate catalog signatures, which DASA can't see.";
        p.consequence = "Unsigned drivers normally can't be loaded unless signature checks are turned off.";
    } else {
        p.headline = f.title;
        p.explanation = f.description;
        p.consequence = f.recommendation;
    }
    return p;
}

} // namespace

PlainSummary explain(const AnalysisResult& r) {
    PlainSummary s;
    const auto& level = r.findings->risk.level;
    s.verdict = level == "Critical" ? Verdict::Dangerous
                : level == "High"   ? Verdict::Risky
                : level == "Medium" ? Verdict::WorthALook
                                    : Verdict::Safe;

    // What it can do: capabilities reachable from program requests, plus
    // what the data-flow analysis proved programs can control.
    std::set<sec::ApiCategory> categories;
    for (const auto& api : r.kernelApis->apis) {
        if (api.info.risk < sec::ApiRisk::High) {
            continue;
        }
        if (std::any_of(api.reachableFrom.begin(), api.reachableFrom.end(), isUserRequestRole)) {
            categories.insert(api.info.category);
        }
    }
    for (const auto& p : r.kernelApis->privileged) {
        if (p.risk >= sec::ApiRisk::High &&
            std::any_of(p.reachableFrom.begin(), p.reachableFrom.end(), isUserRequestRole)) {
            categories.insert(sec::ApiCategory::Hardware);
        }
    }
    for (auto c : categories) {
        if (const char* sentence = capabilitySentence(c)) {
            s.canDo.push_back(sentence);
        }
    }
    const auto& flows = r.dataflow->flows;
    const bool writeAnywhere = std::any_of(flows.begin(), flows.end(), [](const auto& f) {
        return f.kind == core::dataflow::SinkKind::MemoryWrite && !f.requestorModeChecked;
    });
    if (writeAnywhere) {
        s.canDo.insert(s.canDo.begin(), "Write to any part of memory when a program asks it to.");
    }
    if (s.canDo.empty()) {
        s.canDo.push_back("Nothing dangerous that programs can trigger was found.");
    }

    // Who can use it.
    const auto& dev = *r.devices;
    bool publicName = !dev.interfaces.empty();
    for (const auto& l : dev.symbolicLinks) {
        publicName = publicName || !l.link.empty();
    }
    bool restricted = false;
    for (const auto& d : dev.devices) {
        restricted = restricted || !d.sddl.empty();
    }
    if (!publicName) {
        s.whoCanUse = "Programs can't find it directly by name - it's most likely used by Windows itself or by other "
                      "drivers.";
    } else if (restricted) {
        s.whoCanUse = "Only programs allowed by its security settings - typically administrators and Windows "
                      "services.";
    } else {
        s.whoCanUse = "Probably any program on this PC, even without administrator rights: it has a public name and "
                      "its code sets no access restriction.";
    }

    switch (s.verdict) {
    case Verdict::Dangerous:
        s.verdictLine = "This driver has serious problems that malicious programs could use.";
        s.whatToDo = {
            "If you don't need the device or software that installed this driver, uninstall it.",
            "Check the maker's website for an updated version.",
            "Turn on Memory integrity (Windows Security > Device security > Core isolation): it also blocks drivers "
            "Microsoft knows to be vulnerable.",
            "Share the exported report with the maker or your IT/security team."};
        break;
    case Verdict::Risky:
        s.verdictLine = "This driver has weaknesses worth taking seriously.";
        s.whatToDo = {"Keep it only if you need it, and keep it updated.",
                      "Turn on Memory integrity (Windows Security > Device security > Core isolation).",
                      "Ask someone technical to look at the problems below, or share the exported report."};
        break;
    case Verdict::WorthALook:
        s.verdictLine = "Nothing urgent, but a few things could be better.";
        s.whatToDo = {"No immediate action needed; keep the driver updated."};
        break;
    case Verdict::Safe:
        s.verdictLine = "No significant problems were found.";
        s.whatToDo = {"No action needed."};
        break;
    }

    const auto& findings = r.findings->findings;
    for (std::size_t i = 0; i < findings.size(); ++i) {
        if (!coveredByDataFlow(findings[i])) {
            s.problems.push_back(plainFor(findings[i], i));
        }
    }
    return s;
}

const std::vector<GlossaryEntry>& glossary() {
    static const std::vector<GlossaryEntry> g = {
        {"Driver", "A program that runs inside Windows itself (in the kernel) with full access to the computer, "
                   "usually to operate a piece of hardware."},
        {"Kernel", "The core of Windows. Code running there can do anything on the machine."},
        {"Device / device name", "The named \"door\" a driver opens so programs can talk to it, e.g. "
                                 "\\\\.\\MyDriver."},
        {"Symbolic link", "A public alias for a device name that ordinary programs can open."},
        {"IOCTL", "A numbered request a program sends to a driver (\"I/O control code\"). Each number asks the "
                  "driver to do something different."},
        {"IRP", "The package Windows uses to deliver a request (open, read, write, IOCTL...) to a driver."},
        {"IRP_MJ_DEVICE_CONTROL", "The part of a driver that handles IOCTL requests from programs."},
        {"METHOD_NEITHER", "An IOCTL style where the driver touches the program's memory directly instead of a "
                           "safe copy - easy to get wrong."},
        {"FILE_ANY_ACCESS", "An IOCTL that doesn't require read or write permission on the open handle."},
        {"ProbeForRead / ProbeForWrite", "The standard check that a memory address given by a program really "
                                        "belongs to that program."},
        {"SDDL / ACL", "The rules that say which users and programs may open a device."},
        {"FILE_DEVICE_SECURE_OPEN", "An option that makes Windows apply a device's access rules to every way of "
                                    "opening it."},
        {"Physical memory", "The computer's actual RAM. Access to it means access to everything."},
        {"MSR", "A processor setting register. Changing some of them can let code take over the CPU."},
        {"Data flow", "Following a value from where a program supplies it to where the driver uses it."},
        {"Function", "A piece of the driver's code that does one job. DASA names unknown ones sub_<address>."},
        {"RVA", "An address inside the driver file, counted from its start."},
        {"KMDF / WDM", "Two ways of writing Windows drivers: the newer framework (KMDF) and the classic model (WDM)."},
        {"Risk score", "0-100, a weighted sum of the problems found. It's for sorting drivers, not a proof of "
                       "exploitability."},
    };
    return g;
}

} // namespace dasa::analysis
