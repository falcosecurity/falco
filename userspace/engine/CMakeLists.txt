include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/engine")
include_directories("${LUAJIT_INCLUDE}")

add_library(falco_engine STATIC rules.cpp falco_common.cpp falco_engine.cpp)

target_include_directories(falco_engine PUBLIC
  "${LUAJIT_INCLUDE}")

target_link_libraries(falco_engine
  "${FALCO_SINSP_LIBRARY}"
  "${LPEG_LIB}"
  "${LYAML_LIB}"
  "${LIBYAML_LIB}")

configure_file(config_falco_engine.h.in config_falco_engine.h)

if(DEFINED FALCO_COMPONENT)
install(DIRECTORY lua
	DESTINATION "${FALCO_SHARE_DIR}"
	COMPONENT "${FALCO_COMPONENT}"
	FILES_MATCHING PATTERN *.lua)
else()
install(DIRECTORY lua
	DESTINATION "${FALCO_SHARE_DIR}"
	FILES_MATCHING PATTERN *.lua)
endif()

add_subdirectory("${PROJECT_SOURCE_DIR}/../falco/rules" "${PROJECT_BINARY_DIR}/rules")
