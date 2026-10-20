cmake_minimum_required(VERSION 3.16)

project(openback-app-auth-cpp
    VERSION 1.0.0
    DESCRIPTION "C++ SDK of the OpenBack App authenticator (user pools): sign-in, sessions, OIDC, token verification"
    HOMEPAGE_URL "https://github.com/GexyLab/openback-plugins-community"
    LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(OPENBACK_APP_AUTH_TOP_LEVEL ON)
else()
    set(OPENBACK_APP_AUTH_TOP_LEVEL OFF)
endif()

option(OPENBACK_APP_AUTH_WITH_CURL "Build the default HTTP transport (libcurl)" ON)
option(OPENBACK_APP_AUTH_BUILD_TESTS "Build the unit tests (Catch2 v3)" ${OPENBACK_APP_AUTH_TOP_LEVEL})
option(OPENBACK_APP_AUTH_BUILD_EXAMPLES "Build the examples" OFF)
option(OPENBACK_APP_AUTH_INSTALL "Generate the install target" ${OPENBACK_APP_AUTH_TOP_LEVEL})

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json 3.9 REQUIRED)
if(OPENBACK_APP_AUTH_WITH_CURL)
    find_package(CURL REQUIRED)
endif()

add_library(openback_app_auth
    src/client.cpp
    src/curl_transport.cpp
    src/error.cpp
    src/guard.cpp
    src/http.cpp
    src/jwt.cpp
    src/oidc.cpp
    src/storage.cpp
    src/types.cpp
    src/util.cpp
    src/verifier.cpp
    src/web_client.cpp)
add_library(openback::app_auth ALIAS openback_app_auth)

set_target_properties(openback_app_auth PROPERTIES
    OUTPUT_NAME openback-app-auth
    EXPORT_NAME app_auth
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS ON)

target_compile_features(openback_app_auth PUBLIC cxx_std_17)
target_include_directories(openback_app_auth
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(openback_app_auth
    PUBLIC nlohmann_json::nlohmann_json Threads::Threads
    PRIVATE OpenSSL::Crypto)
if(OPENBACK_APP_AUTH_WITH_CURL)
    target_link_libraries(openback_app_auth PRIVATE CURL::libcurl)
    target_compile_definitions(openback_app_auth PRIVATE OPENBACK_APP_AUTH_WITH_CURL=1)
else()
    target_compile_definitions(openback_app_auth PRIVATE OPENBACK_APP_AUTH_WITH_CURL=0)
endif()
if(MSVC)
    target_compile_options(openback_app_auth PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(openback_app_auth PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(OPENBACK_APP_AUTH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OPENBACK_APP_AUTH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(OPENBACK_APP_AUTH_INSTALL)
    set(OPENBACK_APP_AUTH_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/openback-app-auth-cpp)

    install(TARGETS openback_app_auth
        EXPORT openback-app-auth-cpp-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.hpp")
    install(EXPORT openback-app-auth-cpp-targets
        NAMESPACE openback::
        FILE openback-app-auth-cpp-targets.cmake
        DESTINATION ${OPENBACK_APP_AUTH_CMAKE_DIR})

    configure_package_config_file(
        cmake/openback-app-auth-cpp-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/openback-app-auth-cpp-config.cmake
        INSTALL_DESTINATION ${OPENBACK_APP_AUTH_CMAKE_DIR})
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/openback-app-auth-cpp-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/openback-app-auth-cpp-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/openback-app-auth-cpp-config-version.cmake
        DESTINATION ${OPENBACK_APP_AUTH_CMAKE_DIR})
    install(FILES LICENSE README.md CHANGELOG.md DESTINATION ${CMAKE_INSTALL_DATADIR}/openback-app-auth-cpp)
endif()
