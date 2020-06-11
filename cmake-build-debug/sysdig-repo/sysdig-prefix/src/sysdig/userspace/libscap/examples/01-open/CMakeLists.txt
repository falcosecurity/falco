include_directories("../../../common")
include_directories("../../")

add_executable(scap-open
	test.c)

target_link_libraries(scap-open
	scap)
