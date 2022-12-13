add_subdirectory(trace_files)

if(NOT MUSL_OPTIMIZED_BUILD)
    add_subdirectory(plugins)
    add_subdirectory(confs/plugins)
endif()
