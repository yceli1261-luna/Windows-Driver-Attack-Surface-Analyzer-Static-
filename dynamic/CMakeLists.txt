# dynamic: WinDbg/Driver Verifier/Hyper-V VM/ETW integration. Depends on
# dasa_core (to write evidence back into findings/database) but is otherwise
# isolated, so it can be stubbed out independently in tests. Nothing here
# launches a VM or touches a kernel debugger until Phase 10.

add_library(dasa_dynamic STATIC
    _phase1_placeholder.cpp
)

target_link_libraries(dasa_dynamic
    PUBLIC
        dasa_core
)

target_compile_features(dasa_dynamic PUBLIC cxx_std_20)
