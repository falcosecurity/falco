#
# Intel tbb
#
if(TARGET tbb)
	message("Already got tbb")
elseif(NOT WIN32)
	option(USE_BUNDLED_TBB "Enable building of the bundled tbb" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_TBB)
		find_path(TBB_INCLUDE_DIR tbb.h PATH_SUFFIXES tbb)
		find_library(TBB_LIB NAMES tbb)
		if(TBB_INCLUDE_DIR AND TBB_LIB)
			message(STATUS "Found tbb: include: ${TBB_INCLUDE_DIR}, lib: ${TBB_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system tbb")
		endif()
	else()
		set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")

		message(STATUS "Using bundled tbb in '${TBB_SRC}'")

		set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
		set(TBB_LIB "${TBB_SRC}/build/lib_release/libtbb.a")
		ExternalProject_Add(tbb
			URL "http://s3.amazonaws.com/download.draios.com/dependencies/tbb-2018_U5.tar.gz"
			URL_MD5 "ff3ae09f8c23892fbc3008c39f78288f"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE} tbb_build_dir=${TBB_SRC}/build tbb_build_prefix=lib extra_inc=big_iron.inc
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${TBB_LIB}
			INSTALL_COMMAND "")
	endif()
endif()
include_directories("${TBB_INCLUDE_DIR}")
