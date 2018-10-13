#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "/etc/falco")
endif()

if(NOT DEFINED FALCO_RULES_DEST_FILENAME)
  set(FALCO_RULES_DEST_FILENAME "falco_rules.yaml")
  set(FALCO_LOCAL_RULES_DEST_FILENAME "falco_rules.local.yaml")
  set(FALCO_APP_RULES_DEST_FILENAME "application_rules.yaml")
  set(FALCO_K8S_AUDIT_RULES_DEST_FILENAME "k8s_audit_rules.yaml")
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

install(FILES k8s_audit_rules.yaml
	DESTINATION "${FALCO_ETC_DIR}"
	RENAME "${FALCO_K8S_AUDIT_RULES_DEST_FILENAME}")

install(FILES application_rules.yaml
	DESTINATION "/etc/falco/rules.available"
	RENAME "${FALCO_APP_RULES_DEST_FILENAME}")

install(DIRECTORY DESTINATION "/etc/falco/rules.d")
endif()

