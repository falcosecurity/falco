add_subdirectory(k8s_audit)
add_subdirectory(psp)

# Note: list of traces is created at cmake time, not build time
file(GLOB test_trace_files
	"${CMAKE_CURRENT_SOURCE_DIR}/*.scap")

foreach(trace_file_path ${test_trace_files})
	get_filename_component(trace_file ${trace_file_path} NAME)
	add_custom_target(test-trace-${trace_file} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${trace_file})
	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${trace_file}
		COMMAND ${CMAKE_COMMAND} -E copy ${trace_file_path} ${CMAKE_CURRENT_BINARY_DIR}/${trace_file}
		DEPENDS ${trace_file_path})
	list(APPEND BASE_SCAP_TRACE_FILES_TARGETS test-trace-${trace_file})
endforeach()

add_custom_target(trace-files-base-scap ALL)
add_dependencies(trace-files-base-scap ${BASE_SCAP_TRACE_FILES_TARGETS})