cmake_minimum_required(VERSION 3.16)

# Built with the library (-DOPENBACK_APP_AUTH_BUILD_EXAMPLES=ON) or on its own against an installed package:
#   cmake -S examples -B build-examples -DCMAKE_PREFIX_PATH=<install prefix>
if(NOT TARGET openback::app_auth)
    project(openback-app-auth-cpp-examples LANGUAGES CXX)
    find_package(openback-app-auth-cpp 1.0 REQUIRED)
endif()

add_executable(password_sign_in password_sign_in.cpp)
target_link_libraries(password_sign_in PRIVATE openback::app_auth)
target_compile_features(password_sign_in PRIVATE cxx_std_17)

add_executable(verify_token_server verify_token_server.cpp)
target_link_libraries(verify_token_server PRIVATE openback::app_auth)
target_compile_features(verify_token_server PRIVATE cxx_std_17)
