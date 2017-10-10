configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

file(COPY "${PROJECT_SOURCE_DIR}/scripts/debian/falco"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/debian")

file(COPY "${PROJECT_SOURCE_DIR}/scripts/rpm/falco"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/rpm")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	install(PROGRAMS ${SYSDIG_DIR}/scripts/sysdig-probe-loader
		DESTINATION ${FALCO_BIN_DIR}
		RENAME falco-probe-loader)
endif()
