include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories("${LUAJIT_INCLUDE}")

include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories("${PROJECT_BINARY_DIR}/userspace/falco")
include_directories("${CURL_INCLUDE_DIR}")
include_directories("${YAMLCPP_INCLUDE_DIR}")
include_directories("${LPEG_SRC}")
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)

add_executable(falco configuration.cpp formats.cpp fields.cpp rules.cpp logger.cpp falco.cpp)

target_link_libraries(falco sinsp)
target_link_libraries(falco
	"${LPEG_SRC}/lpeg.a"
	"${YAMLCPP_LIB}")


set(DIGWATCH_LUA_MAIN "rule_loader.lua")
configure_file(config_digwatch.h.in config_digwatch.h)

install(TARGETS falco DESTINATION bin)
install(FILES lua/compiler.lua
	DESTINATION share/digwatch/lua)
install(FILES lua/rule_loader.lua
	DESTINATION share/digwatch/lua)
install(FILES lua/output.lua
	DESTINATION share/digwatch/lua)
