# Build a docker container for local development
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(DEV_DOCKER_CXT ${CMAKE_BINARY_DIR}/docker/dev-docker-ctx)

  # This target prepares the `tar.gz` artifact that will be passed to the dockerfile.
  add_custom_target(dev-docker-prepare
    COMMAND mkdir -p ${DEV_DOCKER_CXT}
    COMMAND "${CMAKE_COMMAND}" --build . --target package
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/falco-${FALCO_VERSION}-${FALCO_TARGET_ARCH}.tar.gz ${DEV_DOCKER_CXT}/falco.tar.gz
    DEPENDS falco
  )

  add_custom_target(dev-docker
    COMMAND docker build
      --tag falco-nodriver-dev
      -f ${CMAKE_SOURCE_DIR}/docker/dev/nodriver.Dockerfile
      ${DEV_DOCKER_CXT}
    DEPENDS dev-docker-prepare
  )
endif()
