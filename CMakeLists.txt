cmake_minimum_required(VERSION 3.16)
project(shadowtls-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wno-deprecated-declarations)

find_package(OpenSSL REQUIRED)

add_executable(shadowtls
    src/main.cpp
    src/protocol.cpp
)
target_include_directories(shadowtls PRIVATE src)
target_link_libraries(shadowtls PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    foreach(test_name basic integration fuzz bench)
        add_executable(test_${test_name}
            tests/test_${test_name}.cpp
            src/main.cpp
            src/protocol.cpp
        )
        target_include_directories(test_${test_name} PRIVATE src)
        target_compile_definitions(test_${test_name} PRIVATE TESTING)
        target_link_libraries(test_${test_name} PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
        add_test(NAME ${test_name} COMMAND test_${test_name})
    endforeach()
endif()

install(TARGETS shadowtls RUNTIME DESTINATION bin)
