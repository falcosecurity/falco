#include <gtest/gtest.h>

#include <falco/falco_outputs.h>

#include <filesystem>
#include <fstream>

TEST(FalcoOutputs, handle_msg_escapes_plain_text_output) {
	const auto output_path =
	        std::filesystem::temp_directory_path() / "falco_outputs_handle_msg_escape.txt";
	std::filesystem::remove(output_path);

	falco::outputs::config output_config;
	output_config.name = "file";
	output_config.options["filename"] = output_path.string();
	output_config.options["keep_alive"] = "false";

	{
		std::vector<falco::outputs::config> outputs = {output_config};
		auto engine = std::make_shared<falco_engine>();
		falco_outputs falco_outputs(engine,
		                            outputs,
		                            false,
		                            true,
		                            true,
		                            true,
		                            true,
		                            1000,
		                            false,
		                            1024,
		                            false,
		                            "host");
		nlohmann::json output_fields = nlohmann::json::object();
		output_fields["detail"] = "value";

		falco_outputs.handle_msg(1000000000,
		                         falco_common::PRIORITY_WARNING,
		                         "line\nnext\tend",
		                         "test rule",
		                         output_fields);
	}

	std::ifstream input(output_path);
	std::string contents((std::istreambuf_iterator<char>(input)),
	                     std::istreambuf_iterator<char>());
	std::filesystem::remove(output_path);

	ASSERT_NE(contents.find(": Warning line\\nnext\\tend ("), std::string::npos);
	ASSERT_EQ(contents.find("line\nnext"), std::string::npos);
}
