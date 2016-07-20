if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "/etc")
endif()

if(DEFINED FALCO_COMPONENT)
install(FILES falco_rules.yaml
        COMPONENT "${FALCO_COMPONENT}"
	DESTINATION "${FALCO_ETC_DIR}")
else()
install(FILES falco_rules.yaml
	DESTINATION "${FALCO_ETC_DIR}")
endif()

