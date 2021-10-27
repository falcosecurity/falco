# This list is populated at cmake time, not build time
file(GLOB test_conf_files
	"${CMAKE_CURRENT_SOURCE_DIR}/*.yaml")

foreach(conf_file_path ${test_conf_files})
	get_filename_component(conf_file ${conf_file_path} NAME)
	add_custom_target(test-conf-${conf_file} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${conf_file})
	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${conf_file}
		COMMAND sed -e s!BUILD_DIR!${CMAKE_BINARY_DIR}! < ${CMAKE_CURRENT_SOURCE_DIR}/${conf_file} > ${CMAKE_CURRENT_BINARY_DIR}/${conf_file}
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${conf_file})
	list(APPEND PLUGINS_CONF_FILES_TARGETS test-conf-${conf_file})
endforeach()

add_custom_target(conf-files-plugins ALL)
add_dependencies(conf-files-plugins ${PLUGINS_CONF_FILES_TARGETS})
