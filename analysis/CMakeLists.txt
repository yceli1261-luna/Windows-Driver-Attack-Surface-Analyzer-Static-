# analysis: orchestration over core/ (static pipeline, heuristic rule
# implementations, the Ghidra headless backend). Depends on dasa_core only
# - never on ui/ or app/.
#
# static/StaticAnalysisPipeline is the one entry point the app calls; each
# phase adds its stage there. heuristics/, ghidra/ and signatures/ are
# populated by later phases.

add_library(dasa_analysis STATIC
    static/StaticAnalysisPipeline.h
    static/StaticAnalysisPipeline.cpp
)

target_link_libraries(dasa_analysis
    PUBLIC
        dasa_core
)

target_compile_features(dasa_analysis PUBLIC cxx_std_20)
