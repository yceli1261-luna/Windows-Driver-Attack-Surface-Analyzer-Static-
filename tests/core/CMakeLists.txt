add_executable(dasa_core_tests
    VersionTest.cpp
    PEParserTest.cpp
)

target_link_libraries(dasa_core_tests
    PRIVATE
        dasa_core
        GTest::gtest
        GTest::gtest_main
)

target_compile_definitions(dasa_core_tests
    PRIVATE
        DASA_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures"
)

target_compile_features(dasa_core_tests PRIVATE cxx_std_20)

gtest_discover_tests(dasa_core_tests)
