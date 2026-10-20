find_package(Catch2 3 REQUIRED)

add_executable(openback_app_auth_tests
    test_support.cpp
    test_jwt_oidc.cpp
    test_verifier.cpp
    test_guard.cpp
    test_client.cpp
    test_web_client.cpp)

target_include_directories(openback_app_auth_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(openback_app_auth_tests
    PRIVATE
        openback::app_auth
        OpenSSL::Crypto
        Threads::Threads
        Catch2::Catch2WithMain)
target_compile_features(openback_app_auth_tests PRIVATE cxx_std_17)

# The tests never touch the network: every request goes to a FakeTransport.
add_test(NAME openback_app_auth_tests COMMAND openback_app_auth_tests)
