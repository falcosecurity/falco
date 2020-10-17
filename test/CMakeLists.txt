add_subdirectory(trace_files)

add_custom_target(test-trace-files ALL)
add_dependencies(test-trace-files trace-files-base-scap trace-files-psp trace-files-k8s-audit)