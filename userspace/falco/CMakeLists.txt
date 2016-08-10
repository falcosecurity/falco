include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp")
include_directories("${LUAJIT_INCLUDE}")

include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp")
include_directories("${PROJECT_SOURCE_DIR}/userspace/engine")
include_directories("${PROJECT_BINARY_DIR}/userspace/falco")
include_directories("${CURL_INCLUDE_DIR}")
include_directories("${YAMLCPP_INCLUDE_DIR}")
include_directories("${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include")

add_executable(falco configuration.cpp formats.cpp logger.cpp falco_outputs.cpp falco.cpp)

target_link_libraries(falco falco_engine sinsp)
target_link_libraries(falco
        "${LIBYAML_LIB}"
	"${YAMLCPP_LIB}")


configure_file(config_falco.h.in config_falco.h)

install(TARGETS falco DESTINATION bin)
install(DIRECTORY lua
	DESTINATION share/falco
	FILES_MATCHING PATTERN *.lua)
