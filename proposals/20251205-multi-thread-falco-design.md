# Multi-Threaded Falco High-Level Design (Working draft)

## Summary

This document outlines a high-level design for implementing multi-threading in Falco, an open-source runtime security tool. The goal is to enhance Falco's performance and scalability by leveraging multiple threads for event processing, rule evaluation, and output handling.

## Goals

Address the problems related to single CPU core saturation, leading to dropped events.

## Non-Goals

This document does not cover low-level implementation details that will be addressed in specific design documents for each component.

## High-Level Design

### Current Architecture

![Current Falco Architecture](images/falco-architecture.png)

* The kernel driver (via kmod or eBPF) writes events into per-CPU ring buffers. Each CPU has its own buffer to avoid lock contention. We have a ring buffer per CPU core, and a single userspace.
* Userspace (libscap) performs an `O(n_cpus)` scan on every next() call, it peeks at the head event from each ring buffer, finds the event with the minimum timestamp across all buffers and returns that event to Falco for processing. The consumer position is only advanced after the event has been consumed (on the next call), ensuring the caller can safely read the event data and avoiding to perform copies of the event data.
* Libsinsp processes the events sequentially as they are received from libscap, building a stateful representation of the system and providing the necessary context for rule evaluation.
* Falco evaluates the rules against the processed events and generates alerts based on the defined security policies.

### Proposed Architecture Overview

![Multi-Threaded Falco Architecture](images/falco-multi-thread-architecture.png)

* The kernel driver (modern eBPF probe) writes event into per-TGID ring buffers. Only the modern eBPF probe is supported, as it relies on [BPF_MAP_TYPE_RINGBUF](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/) which does not have a per-CPU design as opposed of the `BPF_MAP_TYPE_PERF_EVENT_ARRAY` used by the legacy eBPF probe.
* Each buffer is associated with an event loop worker thread, that processes events from its assigned ring buffer.
* The `libsinsp` state, e.g. the thread state is maintained in a shared data structure, allowing all workers to access data pushed by other workers. This is crucial for handling events like clone() that rely on data written by other partitions.
This requires designing lightweight synchronization mechanisms to ensure efficient access to shared state without introducing significant contention. A dedicated proposal document will address the design of the shared state and synchronization mechanisms, and data consistency.
* Falco's rule evaluation is performed in parallel by multiple worker threads, each evaluating rules against the events they process.
Current Falco plugins are not supposed to be thread-safe. A dedicated proposal document will address the design of a thread-safe plugin architecture.

### Risks and Mitigations

- **Increased Complexity**: Multi-threading introduces complexity in terms of synchronization and state management. Mitigation: Careful design of shared state and synchronization mechanisms, along with thorough testing.
- **Synchronization Overhead vs Performance Gains**: The overhead of synchronization might negate the performance benefits of multi-threading. Mitigation: Use lightweight synchronization techniques and minimize shared state access.
- **Synchronization Overhead vs Data Consistency**: In order to keep the synchronization overhead low with the shared state, we might need to relax some data consistency guarantees. Mitigation: Analyze the trade-offs and ensure that any relaxed guarantees do not compromise security.
- **Uneven load balancing**: On large systems with a few syscall intensive processes, the load might not be evenly distributed across worker threads. Mitigation: Evaluate different load balancing strategies, such as per-TID. This would increase the contention on the shared state, so a careful analysis of the trade-offs is needed.
