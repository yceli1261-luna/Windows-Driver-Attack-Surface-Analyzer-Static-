# core: the analysis engine. No Qt dependency anywhere in this target so it
# stays independently testable and reusable from a future headless CLI.
#
# Phase 1 only builds Version.{h,cpp} - everything else (pe/, disasm/,
# functions/, cfg/, callgraph/, driver/, ioctl/, dataflow/, security/,
# findings/, database/) is the module layout agreed in the architecture
# proposal, populated starting Phase 2. Each subdirectory's .gitkeep marks
# it as reserved so later phases add files to an existing tree rather than
# inventing paths as they go.

add_library(dasa_core STATIC
    Version.cpp
)

target_include_directories(dasa_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(dasa_core
    PUBLIC
        spdlog::spdlog
)

target_compile_features(dasa_core PUBLIC cxx_std_20)
