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

#include "app_actions/create_signal_handlers.h"
#include "app_actions/init_falco_engine.h"
#include "app_actions/init_inspector.h"
#include "app_actions/init_outputs.h"
#include "app_actions/list_plugins.h"
#include "app_actions/list_fields.h"
#include "app_actions/load_config.h"
#include "app_actions/load_plugins.h"
#include "app_actions/load_rules_files.h"
#include "app_actions/print_help.h"
#include "app_actions/print_ignored_events.h"
#include "app_actions/print_support.h"
#include "app_actions/print_version.h"
#include "app_actions/start_grpc_server.h"
#include "app_actions/start_webserver.h"
#include "app_actions/validate_rules_files.h"

#include "app_actions/daemonize.h"
#include "app_actions/open_inspector.h"
#include "app_actions/process_events.h"


