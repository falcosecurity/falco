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

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "grpc_server.h"
#include "grpc_context.h"

bool grpc_server_impl::is_running()
{
	// TODO: this must act as a switch to shut down the server
	return true;
}

void grpc_server::thread_process(int thread_index)
{
	// TODO: is this right? That's what we want?
	// Tell pthread to not handle termination signals in the current thread
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			// TODO: empty tag returned, log, what to do?
			continue;
		}
	}
}

void grpc_server::run()
{
	grpc::ServerBuilder builder;
	// Listen on the given address without any authentication mechanism.
	builder.AddListeningPort(m_server_addr, grpc::InsecureServerCredentials());
	// builder.RegisterService(&falco_output_svc); // TODO: enable this when we do the impl

	m_completion_queue = builder.AddCompletionQueue();
	m_server = builder.BuildAndStart();
	std::cout << "Server listening on " << m_server_addr << std::endl;

	// int context_count = threadiness * 10;

	m_threads.resize(m_threadiness);

	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&grpc_server::thread_process, this, thread_idx++);
	}

	while(is_running())
	{
	}
}

void grpc_server::subscribe_handler(const stream_context& ctx, falco_output_request req, falco_output_response res)
{
}

void start_grpc_server(std::string server_address, int threadiness)
{
	grpc_server srv(server_address, threadiness);
	srv.run();
}
