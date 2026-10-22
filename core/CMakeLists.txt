# core: the analysis engine. No Qt dependency anywhere in this target so it
# stays independently testable and reusable from a future headless CLI.
#
# Each module subdirectory (pe/, disasm/, functions/, cfg/, callgraph/,
# driver/, ioctl/, dataflow/, security/, findings/, database/) is the layout
# agreed in the architecture proposal; empty ones keep a .gitkeep until the
# phase that populates them. Phase 2 adds pe/, Phase 3 disasm/ and
# functions/, Phase 4 driver/, Phase 5 ioctl/ and driver/DeviceObjects,
# Phase 6 security/, Phase 7 findings/, Phase 8 database/, Phase 9 cfg/
# and callgraph/, Phase 10 dataflow/.

add_library(dasa_core STATIC
    Version.cpp
    pe/PEImage.h
    pe/PEParser.h
    pe/PEParser.cpp
    pe/ImageStrings.h
    pe/ImageStrings.cpp
    disasm/Instruction.h
    disasm/Disassembler.h
    disasm/Disassembler.cpp
    functions/Function.h
    functions/FunctionDiscoverer.h
    functions/FunctionDiscoverer.cpp
    driver/DriverModel.h
    driver/DriverAnalyzer.h
    driver/DriverAnalyzer.cpp
    driver/ValueTracker.h
    driver/ValueTracker.cpp
    driver/WdfFunctionTable.h
    driver/WdfFunctionTable.cpp
    driver/DeviceObjects.h
    driver/DeviceObjects.cpp
    ioctl/IoctlCodec.h
    ioctl/IoctlCodec.cpp
    ioctl/IoctlExtractor.h
    ioctl/IoctlExtractor.cpp
    security/ApiCatalog.h
    security/ApiCatalog.cpp
    security/KernelApiAnalyzer.h
    security/KernelApiAnalyzer.cpp
    findings/Finding.h
    findings/Finding.cpp
    database/AnalysisDatabase.h
    database/AnalysisDatabase.cpp
    cfg/GraphLayout.h
    cfg/GraphLayout.cpp
    cfg/ControlFlowGraph.h
    cfg/ControlFlowGraph.cpp
    callgraph/CallGraph.h
    callgraph/CallGraph.cpp
    dataflow/TaintAnalyzer.h
    dataflow/TaintAnalyzer.cpp
)

target_include_directories(dasa_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(dasa_core
    PUBLIC
        spdlog::spdlog
    PRIVATE
        # LIEF, mbedTLS and Capstone stay private: the public headers expose
        # plain structs, so consumers of dasa_core never see their types.
        LIEF::LIEF
        MbedTLS::mbedcrypto
        capstone::capstone
        unofficial::sqlite3::sqlite3
)

target_compile_features(dasa_core PUBLIC cxx_std_20)
