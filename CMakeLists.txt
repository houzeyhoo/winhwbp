cmake_minimum_required(VERSION 3.28)
project(winhwbp LANGUAGES C VERSION 0.1.0)

option(BUILD_SHARED_LIBS "Build DLL" OFF)
option(WINHWBP_BUILD_TESTS "Build test suite" OFF)
option(WINHWBP_BUILD_EXAMPLE "Build example program" OFF)
option(WINHWBP_INSTALL "Create install target" ${PROJECT_IS_TOP_LEVEL})

if (NOT WIN32)
    message(FATAL_ERROR "WinHwBp can only be built on Windows")
endif()

add_library(winhwbp src/winhwbp.c src/drx.h)
add_library(winhwbp::winhwbp ALIAS winhwbp)

if (BUILD_SHARED_LIBS)
    target_compile_definitions(winhwbp PRIVATE WINHWBP_EXPORTS)
else()
    target_compile_definitions(winhwbp PUBLIC WINHWBP_STATIC)
endif()

target_include_directories(winhwbp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if (WINHWBP_BUILD_TESTS)
    # enable_testing() must be called in the top level CMakeLists.txt for VS 
    # Code's CMake Tools extension to discover tests properly
    enable_testing()
    add_subdirectory(tests)
endif()

if (WINHWBP_BUILD_EXAMPLE)
    add_subdirectory(example)
endif()

if (WINHWBP_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(TARGETS winhwbp
        EXPORT winhwbpTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/winhwbpConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/winhwbpConfig.cmake"
        "include(\"\${CMAKE_CURRENT_LIST_DIR}/winhwbpTargets.cmake\")\n"
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/winhwbpConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/winhwbpConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/winhwbp
    )

    install(EXPORT winhwbpTargets
        FILE winhwbpTargets.cmake
        NAMESPACE winhwbp::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/winhwbp
    )
endif()
