# add test programs for cango.aes library

function(cango_aes_add_test test_name)
    add_executable(cango_aes_${test_name} ${test_name}.cpp)
    target_link_libraries(cango_aes_${test_name} PRIVATE cango::aes)
    set_target_properties(cango_aes_${test_name} PROPERTIES CXX_STANDARD 23)
    add_test(NAME cango_aes_${test_name} COMMAND cango_aes_${test_name})
endfunction()

cango_aes_add_test(test_round_key)
cango_aes_add_test(test_utils)
cango_aes_add_test(test_aes128)
cango_aes_add_test(test_example)
