/*
Copyright (C) 2020 The Falco Authors.

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

#include <cxxopts.hpp>

namespace falco
{

class option_requires_specific_argument_exception : public cxxopts::OptionParseException
{
public:
	explicit option_requires_specific_argument_exception(const std::string& option, const std::string& values):
		OptionParseException("Option " + cxxopts::LQUOTE + option + cxxopts::RQUOTE + " requires an argument equal to " + values)
	{
	}
};

class option_cannot_be_specified_exception : public cxxopts::OptionParseException
{
public:
	explicit option_cannot_be_specified_exception(const std::string& option1, const std::string& option2):
		OptionParseException("Options " + cxxopts::LQUOTE + option1 + cxxopts::RQUOTE + " and " + cxxopts::LQUOTE + option2 + cxxopts::RQUOTE + " can not be specified together")
	{
	}
};

class cli
{
public:
	cli(int argc, const char** argv):
		m_argc(argc), m_argv(argv), m_options("falco", "Cloud-Native Runtime Security")
	{
	}
	virtual ~cli()
	{
	}

	void run()
	{
		// These options give some info about Falco (Falco exits).
		m_options.add_options(
			"help",
			{
				{"h,help", "Print help page."},
				{"support", "Print support information (version, rules files, etc.)."},
				{"version", "Print version info."},
			});

		// These are options responsible for listing Falco elements (Falco exits).
		m_options.add_options(
			"list",
			{
				{"L", "Show name and description of all rules."},
				{"l", "Show name and description of a specific rule.", cxxopts::value<std::string>(), "rule name"},
				{"list", "Show all fields.", cxxopts::value<std::string>()->implicit_value("all"), "sycall|k8s_audit"},
				{"N", "Show field names only."},
			});

		// m_options.add_options(
		// 	"output",
		// 	{
		// 		{},
		// 	});

		// m_options.add_options(
		// 	"input",
		// 	{
		// 		{},
		// 	});

		m_options.add_options(
			"filtering",
			{
				{"D", "Disable any rules with names having the given substring. Can be specified multiple times. Can not be specified with -t.", cxxopts::value<std::vector<std::string>>(), "substring"},
				{"T", "Disable any rules with a specific tag. Can be specified several times. Can not be specified with -t.", cxxopts::value<std::vector<std::string>>(), "tag"},
				{"t", "Only run those rules with a specific tag. Can be specified several times. Can not be specified with -T or -D.", cxxopts::value<std::vector<std::string>>(), "tag"},
			});

		m_result = m_options.parse(m_argc, m_argv);

		process();
	}

private:
	void process()
	{
		if(m_result.count("help") && m_result["help"].as<bool>())
		{
			std::cout << m_options.help() << std::endl;
			// todo: print > exit
		}

		if(m_result.count("support") && m_result["support"].as<bool>())
		{
			// todo: argv + config rule filenames > cmdline > print > exit
		}

		if(m_result.count("version") && m_result["version"].as<bool>())
		{
			// todo: print > exit
		}

		if(m_result.count("L") && m_result["L"].as<bool>())
		{
			// todo: engine > print > exit
			// engine->describe_rule(NULL)
		}

		if(m_result.count("l"))
		{
			// todo: engine > print > exit
			// engine->describe_rule(m_result["l"].as<string>());
		}

		if(m_result.count("list"))
		{
			auto source = m_result["list"].as<std::string>();
			// todo: retrieve implicit value
			if(source.empty() || (source != "syscall" && source != "k8s_audit" && source != "all"))
			{
				throw falco::option_requires_specific_argument_exception(
					"list",
					cxxopts::LQUOTE + "syscall" + cxxopts::RQUOTE + " or " + cxxopts::LQUOTE + "k8s_audit" + cxxopts::RQUOTE);
			}

			bool names_only = false;
			if(m_result.count("N"))
			{
				names_only = m_result["N"].as<bool>();
			}

			// todo: engine + names_only + source
			// se valore == syscall ==> + [-V]
		}

		bool count_D = m_result.count("D");
		bool count_t = m_result.count("t");
		bool count_T = m_result.count("T");
		if(count_D > 0)
		{
			if(count_t > 0)
			{
				throw falco::option_cannot_be_specified_exception("D", "t");
			}
			// todo
			// engine > not exit
		}
		if(count_T > 0)
		{
			if(count_t > 0)
			{
				throw falco::option_cannot_be_specified_exception("T", "t");
			}
			// todo
			// engine > not exit
		}
		if(count_t > 0)
		{
			// todo
			// engine > not exit
		}
	}

	int m_argc;
	const char** m_argv;
	cxxopts::Options m_options;
	cxxopts::ParseResult m_result;
};

} // namespace falco

// 3 tipi di azioni
// quelle che una volta date devono farlo uscire e non hanno bisogno di nessuna istanza
// quelle che hanno bisogno di inspector e/o engine e poi falco esce
// quelle che hanno bisogno di inspector e/o engine e poi falco esegue
