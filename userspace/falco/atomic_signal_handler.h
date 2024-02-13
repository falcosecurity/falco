// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <mutex>
#include <atomic>
#include <functional>

namespace falco
{
    /**
     * @brief A concurrent object that helps properly handling
     * system signals from multiple threads.
     */
    class atomic_signal_handler
    {
    public:
        /**
         * @brief Returns true if the underlying atomic implementation
         * is lock-free as per C++ standard semantics.
         */
        inline bool is_lock_free() const
        {
            return m_handled.is_lock_free() && m_triggered.is_lock_free();
        }

        /**
         * @brief Resets the handler to its initial state, which is
         * non-triggered and non-handled.
         */
        inline void reset()
        {
            m_handled.store(false, std::memory_order_seq_cst);
            m_triggered.store(false, std::memory_order_seq_cst);
        }

        /**
         * @brief Returns true if the signal has been triggered.
         */
        inline bool triggered() const
        {
            return m_triggered.load(std::memory_order_seq_cst);
        }

        /**
         * @brief Returns true if the signal has been handled.
         */
        inline bool handled() const
        {
            return m_handled.load(std::memory_order_seq_cst);
        }

        /**
         * @brief Triggers the signal. Must generally be invoked from
         * within an actual signal handler (created with the `signal`
         * system call). Can eventually be invoked for "faking"
         * the triggering of a signal programmatically.
         */
        inline void trigger()
        {
            m_triggered.store(true, std::memory_order_seq_cst);
            m_handled.store(false, std::memory_order_seq_cst);
        }

        /**
         * @brief If a signal is triggered, performs an handler action.
         * The action function will be invoked exactly once among all the
         * simultaneous calls. The action will not be performed if the
         * signal is not triggered, or if the triggered has already been
         * handled. When an action is being performed, all the simultaneous
         * callers will wait and be blocked up until its execution is finished.
         * If the handler action throws an exception, it will be considered
         * performed. After the first handler has been performed, every
         * other invocation of handle() will be skipped and return false
         * up until the next invocation of reset().
         *
         * @param f The action to perform.
         * @return true If the action has been performed.
         * @return false If the action has not been performed.
         */
        inline bool handle(std::function<void()> f)
        {
            if (triggered() && !handled())
            {
                std::unique_lock<std::mutex> lock(m_mtx);
                if (!handled())
                {
                    try
                    {
                        f();
                        // note: the action may have forcely reset
                        // the signal handler, so we don't want to create
                        // an inconsistent state
                        if (triggered())
                        {
                            m_handled.store(true, std::memory_order_seq_cst);
                        }
                    }
                    catch (std::exception&)
                    {
                        if (triggered())
                        {
                            m_handled.store(true, std::memory_order_seq_cst);
                        }
                        throw;
                    }
                    return true;
                }
            }
            return false;
        }

    private:
        std::mutex m_mtx;
        std::atomic<bool> m_triggered{false};
        std::atomic<bool> m_handled{false};
    };
};
