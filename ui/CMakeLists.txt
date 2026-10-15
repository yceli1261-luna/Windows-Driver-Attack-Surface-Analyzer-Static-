# ui: Qt widgets for each workspace view (one subdirectory per view, per the
# architecture proposal). Views are presentational: they receive finished
# analysis results and never run analysis themselves. Phase 2 adds
# dashboard/, Phase 3 function_view/, Phase 4 driver_view/, Phase 5
# ioctl_view/ and driver_view/DevicesWidget, Phase 6 security_view/.

add_library(dasa_ui STATIC
    dashboard/DashboardWidget.h
    dashboard/DashboardWidget.cpp
    function_view/FunctionsWidget.h
    function_view/FunctionsWidget.cpp
    driver_view/DriverModelWidget.h
    driver_view/DriverModelWidget.cpp
    driver_view/DevicesWidget.h
    driver_view/DevicesWidget.cpp
    ioctl_view/IoctlWidget.h
    ioctl_view/IoctlWidget.cpp
    security_view/KernelApiWidget.h
    security_view/KernelApiWidget.cpp
)

target_include_directories(dasa_ui
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(dasa_ui
    PUBLIC
        Qt6::Widgets
        dasa_core
        dasa_analysis
)

target_compile_features(dasa_ui PUBLIC cxx_std_20)
