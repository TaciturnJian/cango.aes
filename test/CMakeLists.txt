# add test programs for cango.aes library

# if it's windows and gcc-15, set LIB_STDCPPEXP to stdc++exp
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 14)
    set(LIB_STDCPPEXP "stdc++exp")
endif()

function(cango_aes_add_test test_name)
    add_executable(cango_aes_${test_name} ${test_name}.cpp)
    target_link_libraries(cango_aes_${test_name} PRIVATE cango::aes ${LIB_STDCPPEXP})
    set_target_properties(cango_aes_${test_name} PROPERTIES CXX_STANDARD 26)
    add_test(NAME cango_aes_${test_name} COMMAND cango_aes_${test_name})
endfunction()

cango_aes_add_test(test_cryptors)
