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

#include <memory>
#include <mutex>
#include <condition_variable>

namespace falco
{
    /**
     * @brief A simple semaphore implementation. Unfortunately, a standard
     * semaphore is only available since C++20, which currently we don't target.
     */
    class semaphore
    {
    public:
        /**
         * @brief Creates a semaphore with the given initial counter value
         */
        semaphore(int c = 0): count(c) {}
        semaphore(semaphore&&) = default;
        semaphore& operator = (semaphore&&) = default;
        semaphore(const semaphore&) = delete;
        semaphore& operator = (const semaphore&) = delete;
        ~semaphore() = default;

        /**
         * @brief Increments the internal counter and unblocks acquirers
         */
        inline void release()
        {
            std::unique_lock<std::mutex> lock(mtx);
            count++;
            cv.notify_one();
        }

        /**
         * @brief Decrements the internal counter or blocks until it can
         */
        inline void acquire()
        {
            std::unique_lock<std::mutex> lock(mtx);
            while (count == 0)
            {
                cv.wait(lock);
            }
            count--;
        }

    private:
        std::mutex mtx;
        std::condition_variable cv;
        int count;
    };
};
