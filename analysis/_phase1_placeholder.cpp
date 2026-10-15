// Phase 1 only establishes the dasa_analysis target and its link graph
// (-> dasa_core) so app/ has something real to depend on. The orchestration
// code (analysis/static/StaticAnalysisPipeline, heuristics/, ghidra/) lands
// starting Phase 2/6/8 per the architecture proposal; this file is removed
// the moment the directory has real translation units of its own.

namespace dasa::analysis {

const char* phase() {
    return "phase-1-scaffold";
}

} // namespace dasa::analysis
