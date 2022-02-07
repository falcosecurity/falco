/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "application.h"
#include "app_action.h"

namespace falco {
namespace app {

action::action(application &app)
	: m_app(app)
{
}

action::~action()
{
}

application &action::app()
{
	return m_app;
}

cmdline_options &action::options()
{
	return m_app.options();
}

application::action_state &action::state()
{
	return m_app.state();
}

}; // namespace application
}; // namespace falco
