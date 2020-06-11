/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#include <string.h>

#include "prefix_search.h"

using namespace std;

path_prefix_search::path_prefix_search()
{
}

path_prefix_search::~path_prefix_search()
{
}

void path_prefix_search::add_search_path(const char *path)
{
	bool dummy = true;
	return path_prefix_map<bool>::add_search_path(path, dummy);
}

void path_prefix_search::add_search_path(const filter_value_t &path)
{
	bool dummy = true;
	return path_prefix_map<bool>::add_search_path(path, dummy);
}

void path_prefix_search::add_search_path(const std::string &str)
{
	bool dummy = true;
	return path_prefix_map<bool>::add_search_path(str, dummy);
}

bool path_prefix_search::match(const char *path)
{
	const bool *val = path_prefix_map<bool>::match(path);
	return (val != NULL);
}

bool path_prefix_search::match(const filter_value_t &path)
{
	const bool *val = path_prefix_map<bool>::match(path);
	return (val != NULL);
}

std::string path_prefix_search::as_string()
{
	return path_prefix_map<bool>::as_string(false);
}

void path_prefix_map_ut::split_path(const filter_value_t &path, filter_components_t &components)
{
	components.clear();

	uint8_t *pos = path.first;

	while (pos < path.first + path.second)
	{
		uint8_t *sep = (uint8_t *) memchr((char *) pos, '/', path.second - (pos - path.first));

		if (sep)
		{
			if (sep-pos > 0)
			{
				components.emplace_back(pos, sep-pos);
			}
			pos = sep + 1;
		}
		else
		{
			components.emplace_back(pos, path.second - (pos - path.first));
			pos = path.first + path.second + 1;
		}
	}
}


