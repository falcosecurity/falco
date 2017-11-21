if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "/etc/falco")
endif()

if(NOT DEFINED FALCO_RULES_DEST_FILENAME)
  set(FALCO_RULES_DEST_FILENAME "falco_rules.yaml")
  set(FALCO_LOCAL_RULES_DEST_FILENAME "falco_rules.local.yaml")
  set(FALCO_APP_RULES_DEST_FILENAME "application_rules.yaml")
endif()

if(DEFINED FALCO_COMPONENT)
install(FILES falco_rules.yaml
        COMPONENT "${FALCO_COMPONENT}"
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_RULES_DEST_FILENAME}")

install(FILES falco_rules.local.yaml
        COMPONENT "${FALCO_COMPONENT}"
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}")

# Intentionally *not* installing application_rules.yaml. Not needed
# when falco is embedded in other projects.
else()
install(FILES falco_rules.yaml
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_RULES_DEST_FILENAME}")

install(FILES falco_rules.local.yaml
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}")

install(FILES application_rules.yaml
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_APP_RULES_DEST_FILENAME}")
endif()

