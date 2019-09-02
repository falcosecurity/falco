/*
Copyright (C) 2016-2019 The Falco Authors

This file is part of falco.

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

#include <iostream>
#include <memory>
#include <string>
#include <thread>

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "grpc_server.h"
#include "falco_output.grpc.pb.h"
#include "falco_output.pb.h"

bool grpc_server_impl::is_running()
{
	// TODO: this must act as a switch to shut down the server
	return true;
}

class grpc_server : public grpc_server_impl
{
public:
	grpc_server(const char* server_addr, int threadiness):
		server_addr(server_addr),
		threadiness(threadiness)
	{
	}

	virtual ~grpc_server() = default;

	// Run() is blocked. It doesn't return until Stop() is called from another thread.
	void Run();

	void thread_process(int threadIndex)
	{
		// TODO: is this right? That's what we want?
		// Tell pthread to not handle termination signals in the current thread
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGHUP);
		sigaddset(&set, SIGINT);
		pthread_sigmask(SIG_BLOCK, &set, nullptr);

		void* tag = nullptr;
		bool eventReadSuccess = false;
		while(completion_queue->Next(&tag, &eventReadSuccess))
		{
			if(tag == nullptr)
			{
				// TODO: empty tag returned, log, what to do?
				continue;
			}
		}
	}

	// There is no shutdown handling in this code.
	void run()
	{
		grpc::ServerBuilder builder;
		// Listen on the given address without any authentication mechanism.
		builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
		// builder.RegisterService(&falco_output_svc); // TODO: enable this when we do the impl

		completion_queue = builder.AddCompletionQueue();
		server = builder.BuildAndStart();
		std::cout << "Server listening on " << server_addr << std::endl;

		// int context_count = threadiness * 10;

		threads.resize(threadiness);

		int thread_idx = 0;
		for(std::thread& thread : threads)
		{
			thread = std::thread(&grpc_server::thread_process, this, thread_idx++);
		}

		while(is_running())
		{
		}
	}

private:
	// FalcoOutputService::AsyncService falco_output_svc;
	std::unique_ptr<grpc::Server> server;
	std::string server_addr;
	int threadiness = 0;
	std::unique_ptr<grpc::ServerCompletionQueue> completion_queue;
	std::vector<std::thread> threads;
};

bool start_grpc_server(unsigned short port, int threadiness)
{
	// TODO: make bind address configurable
	std::string server_addr = "0.0.0.0:" + std::to_string(port);
	grpc_server srv(server_addr.c_str(), threadiness);
	srv.run();
	return true;
}
