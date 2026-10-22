# app: the Qt 6 executable. Window chrome, docking, job scheduling, theming.
# Analysis itself is never invoked here directly in later phases - only
# through JobManager onto a worker thread, so the GUI thread never blocks.

qt_add_executable(dasa_app
    main.cpp
    MainWindow.h
    MainWindow.cpp
    ThemeManager.h
    ThemeManager.cpp
)

set_target_properties(dasa_app PROPERTIES
    OUTPUT_NAME "dasa"
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(dasa_app
    PRIVATE
        Qt6::Widgets
        Qt6::Core
        Qt6::Gui
        dasa_core
        dasa_ui
        dasa_analysis
        spdlog::spdlog
)

target_include_directories(dasa_app
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_features(dasa_app PRIVATE cxx_std_20)

qt_add_resources(dasa_app "dasa_resources"
    PREFIX "/"
    BASE ${CMAKE_SOURCE_DIR}/resources
    FILES
        ${CMAKE_SOURCE_DIR}/resources/qss/dark_theme.qss
)

# Qt can't start without its platform plugin next to the exe
# (<exe dir>/platforms/qwindows*.dll). vcpkg's applocal step copies the Qt
# DLLs but not plugins, so deploy the one we need after every build. The
# theme uses the built-in Fusion style, so no styles/ plugin is required.
if(WIN32)
    add_custom_command(TARGET dasa_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:dasa_app>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:Qt6::QWindowsIntegrationPlugin>"
            "$<TARGET_FILE_DIR:dasa_app>/platforms/"
        VERBATIM
    )
endif()
