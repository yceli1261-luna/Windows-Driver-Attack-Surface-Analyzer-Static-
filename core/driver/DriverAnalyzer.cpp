#include "core/driver/DriverAnalyzer.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <string_view>

#include <spdlog/spdlog.h>

#include "core/driver/ValueTracker.h"
#include "core/driver/WdfFunctionTable.h"

namespace dasa::core::driver {

using disasm::Operand;
using disasm::Reg;
using functions::Function;
using Kind = Value::Kind;

// ------------------------------------------------------------- names ----

const char* modelName(ModelKind kind) {
    switch (kind) {
    case ModelKind::Wdm: return "WDM";
    case ModelKind::Kmdf: return "KMDF";
    case ModelKind::Minifilter: return "File system minifilter";
    case ModelKind::NdisMiniport: return "NDIS miniport";
    case ModelKind::NdisFilter: return "NDIS filter";
    case ModelKind::NdisProtocol: return "NDIS protocol";
    case ModelKind::Storport: return "Storport miniport";
    case ModelKind::ScsiPort: return "SCSI port miniport";
    case ModelKind::HidMinidriver: return "HID minidriver";
    case ModelKind::KernelStreaming: return "Kernel Streaming (AVStream)";
    case ModelKind::Unknown: break;
    }
    return "Unknown";
}

const char* confidenceName(Confidence c) {
    switch (c) {
    case Confidence::High: return "high";
    case Confidence::Medium: return "medium";
    case Confidence::Low: break;
    }
    return "low";
}

const char* irpMajorName(unsigned major) {
    static const char* const kNames[] = {
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    };
    return major <= kIrpMjMaximum ? kNames[major] : "IRP_MJ_?";
}

namespace {

constexpr unsigned kMajorCount = kIrpMjMaximum + 1;

// DRIVER_OBJECT layout (wdm.h).
struct DriverObjectLayout {
    std::int64_t driverExtension, driverInit, driverStartIo, driverUnload, majorFunction, ptr,
        addDeviceInExtension;
};
constexpr DriverObjectLayout kX64{0x30, 0x58, 0x60, 0x68, 0x70, 8, 0x08};
constexpr DriverObjectLayout kX86{0x18, 0x2C, 0x30, 0x34, 0x38, 4, 0x04};

std::string fieldName(const DriverObjectLayout& l, std::int64_t off) {
    if (off == l.driverExtension) return "DriverExtension";
    if (off == l.driverInit) return "DriverInit";
    if (off == l.driverStartIo) return "DriverStartIo";
    if (off == l.driverUnload) return "DriverUnload";
    if (l.ptr == 8) {
        switch (off) {
        case 0x08: return "DeviceObject";
        case 0x10: return "Flags";
        case 0x18: return "DriverStart";
        case 0x20: return "DriverSize";
        case 0x28: return "DriverSection";
        case 0x38: return "DriverName";
        case 0x48: return "HardwareDatabase";
        case 0x50: return "FastIoDispatch";
        default: break;
        }
    } else {
        switch (off) {
        case 0x04: return "DeviceObject";
        case 0x08: return "Flags";
        case 0x0C: return "DriverStart";
        case 0x10: return "DriverSize";
        case 0x14: return "DriverSection";
        case 0x1C: return "DriverName";
        case 0x24: return "HardwareDatabase";
        case 0x28: return "FastIoDispatch";
        default: break;
        }
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "+0x%llX", static_cast<long long>(off));
    return buf;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::string hex(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// "dll!name" (dll lower-cased) for every named import.
std::set<std::string> importSet(const pe::PEImage& image) {
    std::set<std::string> out;
    for (const auto& lib : image.imports) {
        const std::string dll = lower(lib.name);
        for (const auto& fn : lib.functions) {
            if (!fn.name.empty()) {
                out.insert(dll + "!" + fn.name);
            }
        }
    }
    return out;
}

bool importsFunction(const std::set<std::string>& imports, std::string_view name) {
    for (const auto& entry : imports) {
        if (endsWith(entry, std::string("!") + std::string(name))) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------- bind info ----

std::uint64_t readPtr(std::span<const std::uint8_t> bytes, bool x64) {
    std::uint64_t v = 0;
    const std::size_t n = x64 ? 8 : 4;
    if (bytes.size() < n) {
        return 0;
    }
    for (std::size_t i = 0; i < n; ++i) {
        v |= static_cast<std::uint64_t>(bytes[i]) << (8 * i);
    }
    return v;
}

std::uint32_t readU32(std::span<const std::uint8_t> bytes) {
    return bytes.size() < 4 ? 0 : static_cast<std::uint32_t>(readPtr(bytes, false));
}

// Finds WDF_BIND_INFO by its Component pointer to L"KmdfLibrary".
// Layout (fxldr.h): Size, Component, Version{Major,Minor,Build}, FuncCount,
// FuncTable, Module - x64 offsets 0/8/0x10/0x1C/0x20, x86 0/4/8/0x14/0x18.
std::optional<WdfBindInfo> findBindInfo(const pe::PEImage& image) {
    if (!image.mappedImage) {
        return std::nullopt;
    }
    const auto& mem = *image.mappedImage;
    const bool x64 = image.machine == 0x8664;
    static const char kComponent[] = "KmdfLibrary";
    std::vector<std::uint8_t> needle;
    for (const char* p = kComponent; *p != '\0'; ++p) {
        needle.push_back(static_cast<std::uint8_t>(*p));
        needle.push_back(0);
    }
    needle.push_back(0);
    needle.push_back(0);

    auto it = std::search(mem.begin(), mem.end(), needle.begin(), needle.end());
    while (it != mem.end()) {
        const std::uint64_t stringRva = static_cast<std::uint64_t>(it - mem.begin());
        const std::uint64_t stringVa = image.imageBase + stringRva;
        const std::size_t ptrSize = x64 ? 8 : 4;
        // Scan for an aligned pointer to the string.
        for (std::size_t at = 0; at + ptrSize <= mem.size(); at += ptrSize) {
            if (readPtr(std::span(mem).subspan(at), x64) != stringVa || at < ptrSize) {
                continue;
            }
            const std::size_t base = at - ptrSize;
            const auto view = std::span(mem).subspan(base);
            WdfBindInfo info;
            info.rva = base;
            info.size = readU32(view);
            const std::size_t ver = x64 ? 0x10 : 0x08;
            info.major = readU32(view.subspan(ver));
            info.minor = readU32(view.subspan(ver + 4));
            info.build = readU32(view.subspan(ver + 8));
            info.functionCount = readU32(view.subspan(ver + 12));
            const std::uint64_t tableVa = readPtr(view.subspan(x64 ? 0x20 : 0x18), x64);
            if (info.major != 1 || info.size < (x64 ? 0x30u : 0x20u) || info.size > 0x200 ||
                tableVa < image.imageBase || tableVa >= image.imageBase + image.sizeOfImage) {
                continue;
            }
            info.functionTableVariable = tableVa - image.imageBase;
            return info;
        }
        it = std::search(it + 1, mem.end(), needle.begin(), needle.end());
    }
    return std::nullopt;
}

// ------------------------------------------------------- DriverEntry ----

TrackerState entryState(bool x64) {
    TrackerState s;
    if (x64) {
        s.reg(Reg::Rcx) = Value::make(Kind::DriverObject);
        s.reg(Reg::Rdx) = Value::make(Kind::RegistryPath);
    } else {
        // stdcall: arguments above the return address (entry-relative keys).
        s.stack[{Reg::Rsp, 4}] = Value::make(Kind::DriverObject);
        s.stack[{Reg::Rsp, 8}] = Value::make(Kind::RegistryPath);
    }
    return s;
}

struct ForwardingCalls : TrackerHooks {
    std::vector<std::uint64_t> forwardTargets; // in address order
    std::vector<std::uint64_t> forwardSites;
    std::optional<std::uint64_t> versionBindSite;
    std::size_t directCalls = 0;

    void onCall(const disasm::Instruction& insn, const CallInfo& info, const TrackerState& state) override {
        if (endsWith(info.importName, "!WdfVersionBind")) {
            versionBindSite = insn.rva;
        }
        if (!info.target) {
            return;
        }
        ++directCalls;
        if (state.reg(Reg::Rcx).is(Kind::DriverObject) && state.reg(Reg::Rdx).is(Kind::RegistryPath)) {
            forwardTargets.push_back(*info.target);
            forwardSites.push_back(insn.rva);
        }
    }
};

void resolveDriverEntry(const pe::PEImage& image, const functions::FunctionSet& set,
                        const TrackerContext& ctx, DriverAnalysis& out) {
    const Function* cur = set.find(image.entryPointRva);
    if (cur == nullptr) {
        out.driverEntryNote = "The PE entry point is not a discovered function.";
        return;
    }
    out.entryChain.push_back(cur->rva);
    if (!ctx.x64) {
        out.driverEntry = cur->rva;
        out.driverEntryNote = "x86: the entry point is reported as DriverEntry; stepping through "
                              "/GS and WDF stubs is implemented for x64 only.";
        return;
    }

    for (int depth = 0; depth < 3; ++depth) {
        ForwardingCalls calls;
        TrackerState state = entryState(true);
        trackFunction(*cur, ctx, state, calls);

        std::optional<std::uint64_t> next;
        std::string why;
        if (calls.versionBindSite) {
            // FxDriverEntryWorker: the client DriverEntry is the forwarding
            // call made after the framework has been bound.
            for (std::size_t i = 0; i < calls.forwardTargets.size(); ++i) {
                if (calls.forwardSites[i] > *calls.versionBindSite) {
                    next = calls.forwardTargets[i];
                    break;
                }
            }
            why = "after WdfVersionBind (KMDF FxDriverEntry stub)";
        } else if (cur->instructions.size() <= 40 && calls.directCalls <= 2 && !calls.forwardTargets.empty()) {
            // GsDriverEntry / FxDriverEntry: init the /GS cookie, then pass
            // (DriverObject, RegistryPath) straight on.
            next = calls.forwardTargets.back();
            why = "argument-forwarding stub (e.g. GsDriverEntry)";
        }
        if (!next || set.find(*next) == nullptr) {
            break;
        }
        cur = set.find(*next);
        out.entryChain.push_back(cur->rva);
        out.driverEntryNote += (out.driverEntryNote.empty() ? "" : "; ") + hex(out.entryChain[out.entryChain.size() - 2]) +
                               " forwards to " + hex(cur->rva) + " " + why;
    }
    out.driverEntry = cur->rva;
    if (out.entryChain.size() == 1) {
        out.driverEntryNote = "The PE entry point is DriverEntry (no forwarding stub found).";
    }
}

// --------------------------------------------------------------- WDM ----

struct DispatchCollector : TrackerHooks {
    DispatchCollector(const DriverObjectLayout& layout, const functions::FunctionSet& set)
        : l(layout), functions(set) {}

    const DriverObjectLayout& l;
    const functions::FunctionSet& functions;
    std::uint64_t currentFunction = 0;
    std::map<unsigned, DispatchEntry> majors;
    std::vector<DriverObjectWrite> writes;
    std::vector<std::pair<std::uint64_t, Reg>> calleesWithDriverObject;

    void setMajor(unsigned major, const Value& v, const disasm::Instruction& insn, const char* how) {
        if (major >= kMajorCount || !v.is(Kind::Address)) {
            return;
        }
        DispatchEntry e;
        e.major = major;
        e.handler = static_cast<std::uint64_t>(v.a);
        e.setAt = insn.rva;
        e.inFunction = currentFunction;
        e.how = how;
        e.handlerIsFunction = functions.find(e.handler) != nullptr;
        majors[major] = e; // later stores win
    }

    void recordField(std::int64_t offset, const std::string& name, const Value& v, const disasm::Instruction& insn) {
        DriverObjectWrite w;
        w.offset = static_cast<std::uint32_t>(offset);
        w.field = name;
        if (v.is(Kind::Address)) {
            w.value = static_cast<std::uint64_t>(v.a);
        }
        w.setAt = insn.rva;
        w.inFunction = currentFunction;
        writes.push_back(std::move(w));
    }

    void storeAt(std::int64_t offset, const Operand& dst, const Value& v, const disasm::Instruction& insn) {
        const std::int64_t mfEnd = l.majorFunction + l.ptr * kMajorCount;
        if (dst.index != Reg::None) {
            // MajorFunction[i] = handler inside a loop: every slot.
            if (offset == l.majorFunction && dst.scale == l.ptr) {
                for (unsigned m = 0; m < kMajorCount; ++m) {
                    setMajor(m, v, insn, "loop over all entries");
                }
            }
            return;
        }
        if (offset >= l.majorFunction && offset < mfEnd && (offset - l.majorFunction) % l.ptr == 0) {
            setMajor(static_cast<unsigned>((offset - l.majorFunction) / l.ptr), v, insn, "direct store");
        } else if (offset >= 0 && offset < l.majorFunction) {
            recordField(offset, fieldName(l, offset), v, insn);
        }
    }

    void onStore(const disasm::Instruction& insn, const Operand& dst, const Value& base,
                 const Value& stored) override {
        if (base.is(Kind::DriverObject)) {
            storeAt(dst.disp, dst, stored, insn);
        } else if (base.is(Kind::DriverObjectAt)) {
            storeAt(base.a + dst.disp, dst, stored, insn);
        } else if (base.is(Kind::DriverExtension) && dst.disp == l.addDeviceInExtension && dst.index == Reg::None) {
            recordField(l.driverExtension, "DriverExtension->AddDevice", stored, insn);
        }
    }

    void onRepStos(const disasm::Instruction& insn, const Value& rdi, const Value& rax, const Value& rcx) override {
        if (rdi.is(Kind::DriverObjectAt) && rdi.a == l.majorFunction && rax.is(Kind::Address)) {
            const std::int64_t n = rcx.is(Kind::Immediate) ? std::min<std::int64_t>(rcx.a, kMajorCount) : kMajorCount;
            for (std::int64_t m = 0; m < n; ++m) {
                setMajor(static_cast<unsigned>(m), rax, insn, "rep stos");
            }
        }
    }

    void onCall(const disasm::Instruction&, const CallInfo& info, const TrackerState& state) override {
        if (!info.target) {
            return;
        }
        for (Reg r : {Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9}) {
            if (state.reg(r).is(Kind::DriverObject)) {
                calleesWithDriverObject.emplace_back(*info.target, r);
                return;
            }
        }
    }
};

void recoverWdmDispatch(const functions::FunctionSet& set, const TrackerContext& ctx, DriverAnalysis& out) {
    if (!out.driverEntry) {
        return;
    }
    const DriverObjectLayout& layout = ctx.x64 ? kX64 : kX86;
    DispatchCollector collector(layout, set);

    // Breadth-first over DriverEntry and the functions it hands DriverObject
    // to, three calls deep.
    std::deque<std::tuple<std::uint64_t, Reg, int>> work{{*out.driverEntry, Reg::Rcx, 0}};
    std::set<std::uint64_t> visited;
    while (!work.empty()) {
        auto [rva, reg, depth] = work.front();
        work.pop_front();
        const Function* fn = set.find(rva);
        if (fn == nullptr || !visited.insert(rva).second) {
            continue;
        }
        TrackerState state = entryState(ctx.x64);
        if (rva != *out.driverEntry && ctx.x64) {
            state = TrackerState{};
            state.reg(reg) = Value::make(Kind::DriverObject);
        }
        collector.currentFunction = rva;
        collector.calleesWithDriverObject.clear();
        trackFunction(*fn, ctx, state, collector);
        if (depth < 3) {
            for (const auto& [callee, r] : collector.calleesWithDriverObject) {
                work.emplace_back(callee, r, depth + 1);
            }
        }
    }

    for (auto& [major, entry] : collector.majors) {
        out.majorFunctions.push_back(entry);
    }
    out.driverObjectWrites = std::move(collector.writes);
}

// -------------------------------------------------------------- KMDF ----

struct WdfCollector : TrackerHooks {
    explicit WdfCollector(const functions::FunctionSet& set) : functions(set) {}

    const functions::FunctionSet& functions;
    std::uint64_t currentFunction = 0;
    DriverAnalysis* out = nullptr;

    WdfCallback callback(const char* name, const Value& v) const {
        WdfCallback cb;
        cb.name = name;
        cb.function = static_cast<std::uint64_t>(v.a);
        cb.isFunction = functions.find(cb.function) != nullptr;
        return cb;
    }

    void onCall(const disasm::Instruction& insn, const CallInfo& info, const TrackerState& state) override {
        if (!info.wdfIndex) {
            return;
        }
        WdfCall call;
        call.rva = insn.rva;
        call.inFunction = currentFunction;
        call.index = *info.wdfIndex;
        const char* name = wdfFunctionName(call.index);
        call.name = name ? name : "WdfFunctions[" + std::to_string(call.index) + "]";
        out->wdfCalls.push_back(call);

        if (call.index == wdf_index::kIoQueueCreate) {
            // WdfIoQueueCreate(Globals, Device, Config, Attributes, Queue)
            WdfQueue q;
            q.createCall = insn.rva;
            q.inFunction = currentFunction;
            const Value cfg = state.reg(Reg::R8);
            q.configResolved = cfg.is(Kind::Stack);
            q.dispatchType = "unknown";
            if (q.configResolved) {
                const Value type = state.field(cfg, 0x04);
                if (type.is(Kind::Immediate)) {
                    switch (type.a) {
                    case 1: q.dispatchType = "Sequential"; break;
                    case 2: q.dispatchType = "Parallel"; break;
                    case 3: q.dispatchType = "Manual"; break;
                    default: break;
                    }
                }
                const Value def = state.field(cfg, 0x0D);
                if (def.is(Kind::Immediate)) {
                    q.defaultQueue = (def.a & 0xFF) != 0;
                }
                // WDF_IO_QUEUE_CONFIG (wdfio.h), x64 offsets.
                static const std::pair<std::int64_t, const char*> kFields[] = {
                    {0x10, "EvtIoDefault"},       {0x18, "EvtIoRead"},
                    {0x20, "EvtIoWrite"},         {0x28, "EvtIoDeviceControl"},
                    {0x30, "EvtIoInternalDeviceControl"}, {0x38, "EvtIoStop"},
                    {0x40, "EvtIoResume"},        {0x48, "EvtIoCanceledOnQueue"},
                };
                for (const auto& [off, fieldName] : kFields) {
                    const Value v = state.field(cfg, off);
                    if (v.is(Kind::Address)) {
                        q.callbacks.push_back(callback(fieldName, v));
                    }
                }
            }
            out->wdfQueues.push_back(std::move(q));
        } else if (call.index == wdf_index::kDriverCreate) {
            // WdfDriverCreate(Globals, DriverObject, RegistryPath, Attributes,
            //                 DriverConfig, Driver): config is the 5th argument.
            WdfDriverRegistration d;
            d.createCall = insn.rva;
            d.inFunction = currentFunction;
            const Value cfg = state.stackArg(0x20);
            d.configResolved = cfg.is(Kind::Stack);
            if (d.configResolved) {
                // WDF_DRIVER_CONFIG (wdfdriver.h), x64 offsets.
                const Value add = state.field(cfg, 0x08);
                const Value unload = state.field(cfg, 0x10);
                if (add.is(Kind::Address)) {
                    d.callbacks.push_back(callback("EvtDriverDeviceAdd", add));
                }
                if (unload.is(Kind::Address)) {
                    d.callbacks.push_back(callback("EvtDriverUnload", unload));
                }
            }
            out->wdfDrivers.push_back(std::move(d));
        } else if (call.index == wdf_index::kDeviceInitSetIoType) {
            // WdfDeviceInitSetIoType(Globals, DeviceInit, IoType)
            WdfIoTypeSetting s;
            s.call = insn.rva;
            s.ioType = "unknown";
            const Value t = state.reg(Reg::R8);
            if (t.is(Kind::Immediate)) {
                switch (t.a) {
                case 1: s.ioType = "Neither"; break;
                case 2: s.ioType = "Buffered"; break;
                case 3: s.ioType = "Direct"; break;
                case 4: s.ioType = "BufferedOrDirect"; break;
                default: break;
                }
            }
            out->wdfIoTypes.push_back(s);
        }
    }
};

void recoverWdf(const functions::FunctionSet& set, TrackerContext& ctx, DriverAnalysis& out) {
    if (!out.wdfBind) {
        return;
    }
    ctx.wdfTableVariable = out.wdfBind->functionTableVariable;
    if (!ctx.x64) {
        out.notes.push_back("KMDF on x86: WDF calls are labelled, but queue and driver config "
                            "structures are only decoded for x64.");
    }
    WdfCollector collector(set);
    collector.out = &out;
    for (const auto& fn : set.functions) {
        TrackerState state;
        collector.currentFunction = fn.rva;
        trackFunction(fn, ctx, state, collector);
    }
    for (const auto& q : out.wdfQueues) {
        if (!q.configResolved) {
            out.notes.push_back("WdfIoQueueCreate at " + hex(q.createCall) +
                                ": the queue config wasn't traced to a local structure (built "
                                "elsewhere or passed in), so its callbacks are not listed.");
        }
    }
}

// ------------------------------------------------------------- model ----

void classify(const pe::PEImage& image, const std::set<std::string>& imports, DriverAnalysis& out) {
    DriverModel& m = out.model;
    struct Framework {
        ModelKind kind;
        const char* api;
    };
    static const Framework kFrameworks[] = {
        {ModelKind::Minifilter, "FltRegisterFilter"},
        {ModelKind::NdisMiniport, "NdisMRegisterMiniportDriver"},
        {ModelKind::NdisFilter, "NdisFRegisterFilterDriver"},
        {ModelKind::NdisProtocol, "NdisRegisterProtocolDriver"},
        {ModelKind::Storport, "StorPortInitialize"},
        {ModelKind::ScsiPort, "ScsiPortInitialize"},
        {ModelKind::HidMinidriver, "HidRegisterMinidriver"},
        {ModelKind::KernelStreaming, "KsInitializeDriver"},
    };

    const bool kmdfImport = importsFunction(imports, "WdfVersionBind");
    std::vector<ModelKind> ports;
    for (const auto& f : kFrameworks) {
        if (importsFunction(imports, f.api)) {
            ports.push_back(f.kind);
            m.evidence.push_back(std::string("Imports ") + f.api + " (" + modelName(f.kind) +
                                 " registration).");
        }
    }

    if (kmdfImport || out.wdfBind) {
        m.kind = ModelKind::Kmdf;
        if (kmdfImport) {
            m.evidence.insert(m.evidence.begin(), "Imports WDFLDR.SYS!WdfVersionBind (the KMDF loader bind call).");
        }
        if (out.wdfBind) {
            const auto& b = *out.wdfBind;
            m.evidence.push_back("WDF_BIND_INFO at " + hex(b.rva) + ": KmdfLibrary " + std::to_string(b.major) +
                                 "." + std::to_string(b.minor) + "." + std::to_string(b.build) + ", " +
                                 std::to_string(b.functionCount) + " functions, function table pointer at " +
                                 hex(b.functionTableVariable) + ".");
        }
        if (!out.wdfCalls.empty()) {
            m.evidence.push_back(std::to_string(out.wdfCalls.size()) +
                                 " calls through the WDF function table were found in the code.");
        }
        m.confidence = (kmdfImport && out.wdfBind && !out.wdfCalls.empty()) ? Confidence::High
                       : (kmdfImport && out.wdfBind)                       ? Confidence::Medium
                                                                           : Confidence::Low;
        m.additionalFrameworks = ports;
        return;
    }
    if (!ports.empty()) {
        m.kind = ports.front();
        m.confidence = Confidence::High;
        m.additionalFrameworks.assign(ports.begin() + 1, ports.end());
        out.notes.push_back(std::string("This is a ") + modelName(m.kind) +
                            ": the port/framework driver owns IRP dispatch and calls the "
                            "registered callbacks. Decoding those callback structures is not "
                            "implemented yet.");
        return;
    }

    const bool kernelImports = importsFunction(imports, "IoCreateDevice") ||
                               std::any_of(image.imports.begin(), image.imports.end(), [](const auto& lib) {
                                   const std::string n = lower(lib.name);
                                   return n == "ntoskrnl.exe" || n == "hal.dll";
                               });
    if (!out.majorFunctions.empty()) {
        m.kind = ModelKind::Wdm;
        m.confidence = Confidence::High;
        m.evidence.push_back(std::to_string(out.majorFunctions.size()) +
                             " DriverObject->MajorFunction[] entries are set by the driver's own code.");
        m.evidence.push_back("No framework (KMDF, Filter Manager, NDIS, Storport, ...) registration imports.");
    } else if (kernelImports || image.subsystem == 1) {
        m.kind = ModelKind::Wdm;
        m.confidence = Confidence::Low;
        m.evidence.push_back("Native kernel image with no framework registration imports.");
        m.evidence.push_back("No MajorFunction[] stores were recovered, so this is a default rather "
                             "than a confirmed WDM dispatch model.");
    }
}

} // namespace

DriverAnalysis analyzeDriver(const pe::PEImage& image, const functions::FunctionSet& functions) {
    DriverAnalysis out;
    if (image.machine != 0x8664 && image.machine != 0x014C) {
        out.notes.push_back("Driver model analysis supports x86/x64 only.");
        return out;
    }
    TrackerContext ctx = makeTrackerContext(image, functions);
    const std::set<std::string> imports = importSet(image);

    out.wdfBind = findBindInfo(image);
    if (importsFunction(imports, "WdfVersionBind") && !out.wdfBind) {
        out.notes.push_back("Imports WdfVersionBind but no WDF_BIND_INFO was found, so calls "
                            "through the WDF function table can't be labelled.");
    }

    resolveDriverEntry(image, functions, ctx, out);
    recoverWdf(functions, ctx, out);
    if (!out.wdfBind) {
        recoverWdmDispatch(functions, ctx, out);
    }
    classify(image, imports, out);

    spdlog::info("Driver model for {}: {} ({} confidence); DriverEntry {}; {} MajorFunction entries, "
                 "{} WDF calls, {} queues",
                 image.fileName, modelName(out.model.kind), confidenceName(out.model.confidence),
                 out.driverEntry ? hex(*out.driverEntry) : std::string("not found"),
                 out.majorFunctions.size(), out.wdfCalls.size(), out.wdfQueues.size());
    return out;
}

} // namespace dasa::core::driver
