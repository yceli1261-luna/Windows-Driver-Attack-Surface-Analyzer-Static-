# ui: Qt widgets for each workspace view (one subdirectory per view, per the
# architecture proposal). Views are presentational: they receive finished
# analysis results and never run analysis themselves. Phase 2 adds
# dashboard/, Phase 3 function_view/.

add_library(dasa_ui STATIC
    dashboard/DashboardWidget.h
    dashboard/DashboardWidget.cpp
    function_view/FunctionsWidget.h
    function_view/FunctionsWidget.cpp
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
