include(copy_files_to_build_dir)

# Note: list of rules is created at cmake time, not build time
file(GLOB test_rule_files
	"${CMAKE_CURRENT_SOURCE_DIR}/../../../test/rules/*.yaml")

copy_files_to_build_dir("${test_rule_files}" docker-local-rules)
