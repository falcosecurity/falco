include(copy_files_to_build_dir)

# Note: list of traces is created at cmake time, not build time
file(GLOB test_trace_files
	"${CMAKE_CURRENT_SOURCE_DIR}/../../../test/trace_files/*.scap")

copy_files_to_build_dir("${test_trace_files}" docker-local-traces)
