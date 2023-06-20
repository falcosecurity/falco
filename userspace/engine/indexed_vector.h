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

#pragma once

#include <string>
#include <vector>
#include <unordered_map>

/*!
	\brief Simple wrapper of std::vector that allows random access
	through both numeric and string indexes with O(1) complexity
*/
template <typename T>
class indexed_vector
{
public:
	indexed_vector() = default;
	virtual ~indexed_vector() = default;
	indexed_vector(indexed_vector&&) = default;
	indexed_vector& operator = (indexed_vector&&) = default;
	indexed_vector(const indexed_vector&) = default;
	indexed_vector& operator = (const indexed_vector&) = default;

	/*!
		\brief Returns the number of elements
	*/
	virtual inline size_t size() const
	{
		return m_entries.size();
	}

	/*!
		\brief Returns true if the vector is empty
	*/
	virtual inline bool empty() const
	{
		return m_entries.empty();
	}

	/*!
		\brief Removes all the elements
	*/
	virtual inline void clear()
	{
		m_entries.clear();
		m_index.clear();
	}

	/*!
		\brief Inserts a new element in the vector with a given string index
		and returns its numeric index. String indexes are unique in
		the vector. If no element is already present with the given string
		index, then the provided element is added to the vector and its
		numeric index is assigned as the next free slot in the vector.
		Otherwise, the existing element gets overwritten with the contents
		of the provided one and the numeric index of the existing element
		is returned.
		\param entry Element to add in the vector
		\param index String index of the element to be added in the vector
		\return The numeric index assigned to the element
	*/
	virtual inline size_t insert(const T& entry, const std::string& index)
	{
		size_t id;
		auto prev = m_index.find(index);
		if (prev != m_index.end()) {
			id = prev->second;
			m_entries[id] = entry;
			return id;
		}
		id = m_entries.size();
		m_entries.push_back(entry);
		m_index[index] = id;
		return id;
	}

	/*!
		\brief Returns a pointer to the element at the given numeric index,
		or nullptr if no element exists at the given index.
	*/
	virtual inline T* at(size_t id) const
	{
		if (id < m_entries.size())
		{
			return (T* const) &m_entries[id];
		}
		return nullptr;
	}

	/*!
		\brief Returns a pointer to the element at the given string index,
		or nullptr if no element exists at the given index.
	*/
	virtual inline T* at(const std::string& index) const
	{
		auto it = m_index.find(index);
		if (it != m_index.end()) {
			return at(it->second);
		}
		return nullptr;
	}

	virtual inline typename std::vector<T>::iterator begin()
	{
		return m_entries.begin();
	}

	virtual inline typename std::vector<T>::iterator end()
	{
		return m_entries.end();
	}

	virtual inline typename std::vector<T>::const_iterator begin() const 
	{
		return m_entries.begin();
	}

	virtual inline typename std::vector<T>::const_iterator end() const
	{
		return m_entries.end();
	}

private:
	std::vector<T> m_entries;
	std::unordered_map<std::string, size_t> m_index;
};
