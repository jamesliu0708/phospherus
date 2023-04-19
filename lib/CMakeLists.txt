include_directories(${CMAKE_CURRENT_LIST_DIR}/../include)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/cplplate cplplate)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/rtstd rtstd)

add_library(rtstd STATIC ${rtstd} ${cplplate})
target_link_libraries(rtstd pthread)