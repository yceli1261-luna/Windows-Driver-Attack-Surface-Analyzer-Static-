# analysis: orchestration over core/ (static pipeline, heuristic rule
# implementations, the Ghidra headless backend). Depends on dasa_core only
# - never on ui/ or app/.
#
# static/StaticAnalysisPipeline is the one entry point the app calls; each
# phase adds its stage there. heuristics/ holds the finding rules (Phase
# 7); report/ the JSON/HTML reports and database save (Phase 8); search/
# (Phase 11); ghidra/ and signatures/ are populated by later phases.

add_library(dasa_analysis STATIC
    static/StaticAnalysisPipeline.h
    static/StaticAnalysisPipeline.cpp
    heuristics/FindingRules.h
    heuristics/FindingRules.cpp
    report/ReportWriter.h
    report/ReportWriter.cpp
    search/Search.h
    search/Search.cpp
    diff/AnalysisDiff.h
    diff/AnalysisDiff.cpp
    report/Assessment.h
    report/Assessment.cpp
)

target_link_libraries(dasa_analysis
    PUBLIC
        dasa_core
    PRIVATE
        nlohmann_json::nlohmann_json
)

target_compile_features(dasa_analysis PUBLIC cxx_std_20)
