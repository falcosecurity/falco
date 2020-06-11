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
#ifdef GATHER_INTERNAL_STATS
#include <map>
#include <memory>
#include <string>

#define INTERNAL_COUNTER(X) internal_metrics::counter *X

namespace internal_metrics {

class metric;
class registry;
class counter;

class SINSP_PUBLIC metric_name
{
public:
	metric_name(std::string name, std::string description)
	{
		m_name = name;
		m_description = description;
	}

	bool operator<(const metric_name& other) const
	{
		return m_name<other.m_name;
	}

	std::string get_name() const
	{
		return m_name;
	}

	std::string get_description() const
	{
		return m_description;
	}

private:
	std::string m_name;
	std::string m_description;
};

class SINSP_PUBLIC processor
{
public:
	virtual void process(counter& metric) {};
};

class SINSP_PUBLIC metric
{
public:
	virtual ~metric() {}
	virtual void process(processor& metric_processor) = 0;
	virtual void clear() = 0;
};

class SINSP_PUBLIC registry
{
public:
	typedef std::map<metric_name,std::shared_ptr<counter>> metric_map_t;
	typedef metric_map_t::iterator metric_map_iterator_t;

	counter& register_counter(const metric_name& name)
	{
		std::shared_ptr<counter> p;
		p = std::make_shared<counter>();
    	m_metrics[name] = p;
		return *p.get();
	}

	metric_map_t& get_metrics()
	{
		return m_metrics;
	}

	void clear_all_metrics();

private:
	//template<typename T, typename... Args> T& create_metric(const metric_name& name, Args... args)
	//{
	//	if (m_metrics.find(name) == std::end(m_metrics))
	//	{
	//		m_metrics[name] = std::make_shared<T>(args...);
	//	}
	//	return dynamic_cast<T&>(*m_metrics[name]);
	//}

	metric_map_t m_metrics;

};


class SINSP_PUBLIC counter : public metric
{
public:
	~counter();
	counter();

	void increment()
	{
		m_value++;
	}

	void decrement()
	{
		m_value--;
	}

	void clear()
	{
		m_value = 0;
	}

	const uint64_t get_value()
	{
		return m_value;
	}

	void process(processor& metric_processor)
	{
		metric_processor.process(*this);
	}

private:

	uint64_t m_value;
};

}
#else
#define INTERNAL_COUNTER(X)
#endif // GATHER_INTERNAL_STATS
