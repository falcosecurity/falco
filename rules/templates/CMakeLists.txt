add_custom_target(k8s_psp_rules_yaml ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/k8s_psp_rules.yaml)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/k8s_psp_rules.yaml
	COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/fill_psp_template.py > ${CMAKE_CURRENT_BINARY_DIR}/k8s_psp_rules.yaml
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fill_psp_template.py
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/k8s_psp_rules.yaml.tmpl
	)
