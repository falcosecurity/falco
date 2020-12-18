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

class hawk_plugin_exception : public hawk_exception
{
public:
	hawk_plugin_exception(const std::string& plugin_name, const std::string& message):
		hawk_exception("plugin: " + plugin_name + ", error: " + message) {}
};

class hawk_library_exception : public hawk_exception
{
public:
	hawk_library_exception(const std::string& message):
		hawk_exception(message) {}
};

class hawk_library_load_exception : public hawk_library_exception
{
	public:
		hawk_library_load_exception(const std::string&library_name, const std::string&message):
			hawk_library_exception("library loading error, library: " + library_name + " error: " + message) {}
};

class hawk_library_unload_exception : public hawk_library_exception
{
	public:
		hawk_library_unload_exception(const std::string&library_name, const std::string&message):
			hawk_library_exception("library unloading error, library: " + library_name + " error: " + message) {}
};
} // namespace libhawk
