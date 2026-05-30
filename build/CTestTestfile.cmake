# CMake generated Testfile for 
# Source directory: /home/bym/shadowtls-cpp
# Build directory: /home/bym/shadowtls-cpp/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(basic "/home/bym/shadowtls-cpp/build/test_basic")
set_tests_properties(basic PROPERTIES  _BACKTRACE_TRIPLES "/home/bym/shadowtls-cpp/CMakeLists.txt;30;add_test;/home/bym/shadowtls-cpp/CMakeLists.txt;0;")
add_test(integration "/home/bym/shadowtls-cpp/build/test_integration")
set_tests_properties(integration PROPERTIES  _BACKTRACE_TRIPLES "/home/bym/shadowtls-cpp/CMakeLists.txt;30;add_test;/home/bym/shadowtls-cpp/CMakeLists.txt;0;")
add_test(fuzz "/home/bym/shadowtls-cpp/build/test_fuzz")
set_tests_properties(fuzz PROPERTIES  _BACKTRACE_TRIPLES "/home/bym/shadowtls-cpp/CMakeLists.txt;30;add_test;/home/bym/shadowtls-cpp/CMakeLists.txt;0;")
add_test(bench "/home/bym/shadowtls-cpp/build/test_bench")
set_tests_properties(bench PROPERTIES  _BACKTRACE_TRIPLES "/home/bym/shadowtls-cpp/CMakeLists.txt;30;add_test;/home/bym/shadowtls-cpp/CMakeLists.txt;0;")
