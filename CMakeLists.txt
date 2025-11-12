cmake_minimum_required(VERSION 3.28)

project(cango.aes)

aux_source_directory(src lib_sources)
add_library(cango.aes ${lib_sources})
add_library(cango::aes ALIAS cango.aes)
target_include_directories(cango.aes PUBLIC include)
set_target_properties(cango.aes PROPERTIES CXX_STANDARD 20)

if (CANGO_AES_BUILD_TESTS)
    message(STATUS "为 cango.aes 库启用测试构建")
    add_subdirectory(test)
endif()
