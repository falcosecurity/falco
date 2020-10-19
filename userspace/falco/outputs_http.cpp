/*
Copyright (C) 2020 The Falco Authors

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

#include "outputs_http.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::outputs::output_http::output(const message *msg)
{
	CURL *curl = NULL;
	CURLcode res = CURLE_FAILED_INIT;
	struct curl_slist *slist1;
	slist1 = NULL;

	curl = curl_easy_init();
	if(curl)
	{
		slist1 = curl_slist_append(slist1, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
		curl_easy_setopt(curl, CURLOPT_URL, m_oc.options["url"].c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg->msg.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK)
		{
			falco_logger::log(LOG_ERR, "libcurl error: " + string(curl_easy_strerror(res)));
		}
		curl_easy_cleanup(curl);
		curl = NULL;
		curl_slist_free_all(slist1);
		slist1 = NULL;
	}
}