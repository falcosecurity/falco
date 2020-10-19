if(CPACK_GENERATOR MATCHES "DEB")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/debian/falco.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
endif()

if(CPACK_GENERATOR MATCHES "RPM")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/rpm/falco.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
endif()

if(CPACK_GENERATOR MATCHES "TGZ")
	set(CPACK_SET_DESTDIR "ON")
	set(CPACK_STRIP_FILES "OFF")
endif()
