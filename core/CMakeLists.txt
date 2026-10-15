# core: the analysis engine. No Qt dependency anywhere in this target so it
# stays independently testable and reusable from a future headless CLI.
#
# Each module subdirectory (pe/, disasm/, functions/, cfg/, callgraph/,
# driver/, ioctl/, dataflow/, security/, findings/, database/) is the layout
# agreed in the architecture proposal; empty ones keep a .gitkeep until the
# phase that populates them. Phase 2 adds pe/.

add_library(dasa_core STATIC
    Version.cpp
    pe/PEImage.h
    pe/PEParser.h
    pe/PEParser.cpp
)

target_include_directories(dasa_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(dasa_core
    PUBLIC
        spdlog::spdlog
    PRIVATE
        # LIEF and mbedTLS stay private: PEImage.h exposes plain structs, so
        # consumers of dasa_core never see LIEF types.
        LIEF::LIEF
        MbedTLS::mbedcrypto
)

target_compile_features(dasa_core PUBLIC cxx_std_20)
