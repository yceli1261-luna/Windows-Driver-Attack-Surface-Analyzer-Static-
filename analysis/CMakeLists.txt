# analysis: orchestration over core/ (static pipeline, heuristic rule
# implementations, the Ghidra headless backend). Depends on dasa_core only
# - never on ui/ or app/.
#
# Phase 1: an empty INTERFACE-backed static target so the rest of the build
# graph (app/ will link against it once analysis/static/StaticAnalysisPipeline
# exists in Phase 2+) already has a stable target name to depend on.

add_library(dasa_analysis STATIC
    _phase1_placeholder.cpp
)

target_link_libraries(dasa_analysis
    PUBLIC
        dasa_core
)

target_compile_features(dasa_analysis PUBLIC cxx_std_20)
