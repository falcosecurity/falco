configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

file(COPY "${PROJECT_SOURCE_DIR}/scripts/debian/falco"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/debian")

file(COPY "${PROJECT_SOURCE_DIR}/scripts/rpm/falco"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/rpm")

install(PROGRAMS ${SYSDIG_DIR}/scripts/sysdig-probe-loader
	DESTINATION bin
	RENAME falco-probe-loader)
