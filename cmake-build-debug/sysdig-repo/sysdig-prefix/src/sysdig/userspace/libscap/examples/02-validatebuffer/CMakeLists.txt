include_directories("../../../common")
include_directories("../..")

add_executable(scap-validatebuffer
	test.c)

target_link_libraries(scap-validatebuffer
	scap)
