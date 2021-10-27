add_library(test_extract_p1 SHARED test_extract.cpp)
add_library(test_extract_p2 SHARED test_extract.cpp)
add_library(test_source SHARED test_source.cpp)
add_library(test_incompat_api SHARED incompat_api.cpp)

target_include_directories(
	test_extract_p1 PUBLIC "${LIBSCAP_INCLUDE_DIRS}")

target_include_directories(
	test_extract_p2 PUBLIC "${LIBSCAP_INCLUDE_DIRS}")

target_include_directories(
	test_source PUBLIC "${LIBSCAP_INCLUDE_DIRS}")
