#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
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
find_program(PANDOC pandoc)

if (PANDOC)
	add_custom_target(man_sysdig ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man sysdig.md -o ${CMAKE_CURRENT_BINARY_DIR}/sysdig.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sysdig.8
		DESTINATION share/man/man8)

	add_custom_target(man_csysdig ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man csysdig.md -o ${CMAKE_CURRENT_BINARY_DIR}/csysdig.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/csysdig.8
		DESTINATION share/man/man8)
else()
	install(FILES sysdig.8
		DESTINATION share/man/man8)

	install(FILES csysdig.8
		DESTINATION share/man/man8)
endif()
