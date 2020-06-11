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

#pragma once

#include <string.h>

#include <string>
#include <sstream>
#include <list>
#include <unordered_map>

#include "filter_value.h"

namespace path_prefix_map_ut
{
	typedef std::list<filter_value_t> filter_components_t;

        // Split path /var/log/messages into a list of components (var, log, messages). Empty components are skipped.
	void split_path(const filter_value_t &path, filter_components_t &components);
};

//
// A data structure that allows testing a path P against a set of
// search paths S. The search succeeds if any of the search paths Si
// is a prefix of the path P.
//
// Here are some examples:
// - search(/var/run/docker, [/var/run, /etc, /lib, /usr/lib])
//         succeeds because /var/run is a prefix of /var/run/docker.
// - search(/boot, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /boot.
// - search(/var/lib/messages, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var/lib/messages.
//         /var is a partial match but not /var/run.
// - search(/var, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var
//         /var is a partial match but the search path is /var/run, not /var.

template<class Value>
class path_prefix_map
{
public:
	path_prefix_map();
	virtual ~path_prefix_map();

	void add_search_path(const char *path, Value &v);
	void add_search_path(const filter_value_t &path, Value &v);

	// With the above methods the pointers in the char */uint8_t *
	// above point to memory not owned by this object. The below
	// method passes a string which is copied into the object,
	// holding its own memory.
	void add_search_path(const std::string &str, Value &v);

	// Similar to add_search_path, but takes a path already split
	// into a list of components. This allows for custom splitting
	// of paths other than on '/' boundaries.
	void add_search_path_components(const path_prefix_map_ut::filter_components_t &components, Value &v);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	Value * match(const char *path);
	Value * match(const filter_value_t &path);

	Value *match_components(const path_prefix_map_ut::filter_components_t &components);

	std::string as_string(bool include_vals);

private:

	std::string as_string(const std::string &prefix, bool include_vals);

	void add_search_path_components(const path_prefix_map_ut::filter_components_t &components, path_prefix_map_ut::filter_components_t::const_iterator comp, Value &v);

	Value *match_components(const path_prefix_map_ut::filter_components_t &components, path_prefix_map_ut::filter_components_t::const_iterator comp);

	// Maps from the path component at the current level to a
	// prefix search for the sub-path below the current level.
	// For example, if the set of search paths is (/var/run, /etc,
	// /lib, /usr, /usr/lib, /var/lib, /var/run), m_dirs contains:
	//   - (var, path_prefix_map(/run)
	//   - (etc, NULL)
	//   - (lib, NULL)
	//   - (usr, NULL)
	//   - (var, path_prefix_map(/lib, /run)
	// Note that because usr is a prefix of /usr/lib, the /usr/lib
	// path is dropped and only /usr is kept.  Also note that
	// terminator paths have a NULL path_prefix_map object.
	std::unordered_map<filter_value_t,
		std::pair<path_prefix_map *, Value *>,
		g_hash_membuf,
		g_equal_to_membuf> m_dirs;

	std::list<std::string> m_strvals;
};

template<class Value>
path_prefix_map<Value>::path_prefix_map()
{
}

template<class Value>
path_prefix_map<Value>::~path_prefix_map()
{
	for (auto &ent : m_dirs)
	{
		delete(ent.second.first);
		delete(ent.second.second);
	}
}

// NOTE: this does not copy, so it is only valid as long as path is valid.
template<class Value>
void path_prefix_map<Value>::add_search_path(const char *path, Value &v)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return add_search_path(mem, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const std::string &str, Value &v)
{
	m_strvals.push_back(str);

	return add_search_path(m_strvals.back().c_str(), v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const filter_value_t &path, Value &v)
{
	path_prefix_map_ut::filter_components_t components;

	path_prefix_map_ut::split_path(path, components);

	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front((uint8_t *) "root", 4);

	return add_search_path_components(components, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path_components(const path_prefix_map_ut::filter_components_t &components, Value &v)
{
	add_search_path_components(components, components.begin(), v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path_components(const path_prefix_map_ut::filter_components_t &components,
							path_prefix_map_ut::filter_components_t::const_iterator comp,
							Value &v)
{
	path_prefix_map *subtree = NULL;
	auto it = m_dirs.find(*comp);
	auto cur = comp;
	comp++;

	if(it == m_dirs.end())
	{
		// This path component doesn't match any existing
		// dirent. We need to add one and its subtree.
		if(comp != components.end())
		{
			subtree = new path_prefix_map();
			subtree->add_search_path_components(components, comp, v);
		}

		// If the path doesn't have anything remaining, we
		// also add the value here.
		m_dirs[*cur] = std::pair<path_prefix_map*,Value *>(subtree, (comp == components.end() ? new Value(v) : NULL));
	}
	else
	{
		// An entry for this dirent already exists. We will
		// either add a new entry to the subtree, do nothing,
		// or get rid of the existing subtree.
		if(comp == components.end())
		{
			// This path is a prefix of the current path and we
			// can drop the existing subtree. For example, we can
			// drop /usr/lib when adding /usr.
			delete(it->second.first);
			delete(it->second.second);
			m_dirs.erase(*cur);
			m_dirs[*cur] = std::pair<path_prefix_map*,Value*>(NULL, new Value(v));
		}
		else if(it->second.first == NULL)
		{
			// The existing path is shorter than the
			// current path, in which case we don't have
			// to do anything. For example, no need to add
			// /usr/lib when /usr exists.
		}
		else
		{
			// We need to add the remainder to the
			// sub-tree's search path.
			it->second.first->add_search_path_components(components, comp, v);
		}
	}
}

// NOTE: this does not copy, so it is only valid as long as path is valid.
template<class Value>
Value *path_prefix_map<Value>::match(const char *path)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return match(mem);
}

template<class Value>
Value *path_prefix_map<Value>::match(const filter_value_t &path)
{
	path_prefix_map_ut::filter_components_t components;

	path_prefix_map_ut::split_path(path, components);

	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front((uint8_t *) "root", 4);

	return match_components(components);
}

template<class Value>
Value *path_prefix_map<Value>::match_components(const path_prefix_map_ut::filter_components_t &components)
{
	return match_components(components, components.begin());
}

template<class Value>
Value *path_prefix_map<Value>::match_components(const path_prefix_map_ut::filter_components_t &components, path_prefix_map_ut::filter_components_t::const_iterator comp)
{
	auto it = m_dirs.find(*comp);
	comp++;

	if(it == m_dirs.end())
	{
		return NULL;
	}
	else
	{
		// If there is nothing left in the match path, the
		// subtree must be null. This ensures that /var
		// matches only /var and not /var/lib
		if(comp == components.end())
		{
			if(it->second.first == NULL)
			{
				return it->second.second;
			}
			else
			{
				return NULL;
			}
		}
		else if(it->second.first == NULL)
		{
			// /foo/bar matched a prefix /foo, so we're
			// done.
			return it->second.second;
		}
		else
		{
			return it->second.first->match_components(components, comp);
		}
	}
}

template<class Value>
std::string path_prefix_map<Value>::as_string(bool include_vals)
{
	return as_string(std::string(""), include_vals);
}

// Unlike all the other methods, this does perform copies.
template<class Value>
std::string path_prefix_map<Value>::as_string(const std::string &prefix, bool include_vals)
{
	std::ostringstream os;

	for (auto &it : m_dirs)
	{
		std::string dirent((const char *) it.first.first, it.first.second);

		os << prefix << dirent << " -> ";
		if (include_vals && it.second.first == NULL)
		{
			os << "v=" << (*it.second.second);
		}

		os << std::endl;

		if(it.second.first)
		{
			std::string indent = prefix;
			indent += "    ";
			os << it.second.first->as_string(indent, include_vals);
		}
	}

	return os.str();
}

class path_prefix_search : public path_prefix_map<bool>
{
public:
	path_prefix_search();
	~path_prefix_search();

	void add_search_path(const char *path);
	void add_search_path(const filter_value_t &path);
	void add_search_path(const std::string &str);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	bool match(const char *path);
	bool match(const filter_value_t &path);

	std::string as_string();
};
