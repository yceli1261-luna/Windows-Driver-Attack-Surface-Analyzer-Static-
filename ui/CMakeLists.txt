# ui: Qt widgets for each workspace view (one subdirectory per view, per the
# architecture proposal). Views are presentational: they receive finished
# analysis results and never run analysis themselves. Phase 2 adds
# dashboard/, Phase 3 function_view/, Phase 4 driver_view/, Phase 5
# ioctl_view/ and driver_view/DevicesWidget, Phase 6 security_view/, Phase 7 findings_view/,
# Phase 8 database_view/ and report_view/, Phase 9 graph_view/.

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
    findings_view/SeverityColors.h
    findings_view/FindingsWidget.h
    findings_view/FindingsWidget.cpp
    findings_view/EvidenceWidget.h
    findings_view/EvidenceWidget.cpp
    database_view/ComparisonHtml.h
    database_view/ComparisonHtml.cpp
    database_view/HistoryWidget.h
    database_view/HistoryWidget.cpp
    database_view/CompareWidget.h
    database_view/CompareWidget.cpp
    report_view/ExportWidget.h
    report_view/ExportWidget.cpp
    graph_view/GraphView.h
    graph_view/GraphView.cpp
    graph_view/GraphUtil.h
    graph_view/GraphUtil.cpp
    graph_view/ControlFlowWidget.h
    graph_view/ControlFlowWidget.cpp
    graph_view/CallGraphWidget.h
    graph_view/CallGraphWidget.cpp
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
