# Note: list of rules is created at cmake time, not build time
file(GLOB test_rule_files
	"${CMAKE_CURRENT_SOURCE_DIR}/../../../test/rules/*.yaml")

foreach(rule_file_path ${test_rule_files})
	get_filename_component(rule_file ${rule_file_path} NAME)
	add_custom_target(docker-local-rule-${rule_file} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${rule_file})
	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${rule_file}
		COMMAND ${CMAKE_COMMAND} -E copy ${rule_file_path} ${CMAKE_CURRENT_BINARY_DIR}/${rule_file}
		DEPENDS ${rule_file_path})
endforeach()

