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
configure_file(debian/postinst.in debian/postinst)
configure_file(debian/prerm.in debian/prerm)

install(FILES completions/bash/sysdig
	DESTINATION "${DIR_ETC}/bash_completion.d")

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/vendor-completions)

install(FILES completions/zsh/_sysdig
	DESTINATION share/zsh/site-functions)

install(PROGRAMS sysdig-probe-loader
	DESTINATION bin)
