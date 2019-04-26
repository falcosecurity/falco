add_subdirectory(traces)
add_subdirectory(rules)

add_custom_target(local-Dockerfile ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile)

add_custom_target(local-docker-entrypoint ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/docker-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/docker-entrypoint.sh)

