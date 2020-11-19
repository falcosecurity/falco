#pragma once

#include <stdexcept>

#include <stdexcept>
#include <string>

namespace libhawk
{
class hawk_exception : public std::runtime_error
{
public:
	hawk_exception(const std::string& message):
		std::runtime_error(message) {}
};

class hawk_plugin_exception: public hawk_exception
{
public:
	hawk_plugin_exception(const std::string& plugin_name, const std::string& message):
		hawk_exception("plugin: " + plugin_name + ", error: " + message) {}
};
} // namespace libhawk
