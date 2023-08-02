/*
Copyright (C) 2023 The Falco Authors.
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

#pragma once

#define DEFAULT_ITEMS_QUEUE_CAPAXITY_OUTPUTS 0

enum outputs_recovery_code {
	RECOVERY_DROP_CURRENT = 0,  /* queue_capacity_outputs recovery strategy of continuing on. */
	RECOVERY_EXIT = 1,  /* queue_capacity_outputs recovery strategy of exiting, self OOM kill. */
	RECOVERY_EMPTY = 2,  /* queue_capacity_outputs recovery strategy of emptying queue then continuing. */
};
