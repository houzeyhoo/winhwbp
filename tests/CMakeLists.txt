include(CTest)

add_executable(winhwbp_tests main.c)

target_link_libraries(winhwbp_tests PRIVATE winhwbp)

target_include_directories(winhwbp_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_test(NAME winhwbp_test_get COMMAND winhwbp_tests get)
add_test(NAME winhwbp_test_set COMMAND winhwbp_tests set)
add_test(NAME winhwbp_test_set_auto COMMAND winhwbp_tests set_auto)
add_test(NAME winhwbp_test_clear COMMAND winhwbp_tests clear)
add_test(NAME winhwbp_test_clear_all COMMAND winhwbp_tests clear_all)
add_test(NAME winhwbp_test_end_to_end COMMAND winhwbp_tests end_to_end)
