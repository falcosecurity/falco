
# Multi-Threaded Falco High-Level Design (Working draft)

## Summary

This document outlines a high-level design for implementing multi-threading in Falco, an open-source runtime security tool. The goal is to enhance Falco's performance and scalability by leveraging multiple threads for event processing, rule evaluation, and output handling.

## Goals

Address the problems related to single CPU core saturation, leading to dropped events.

## Non-Goals

This document does not cover low-level implementation details that will be addressed in specific design documents for each component.

## High-Level Design

### Architecture Overview

![Multi-Threaded Falco Architecture](images/multi_threaded_falco_architecture.png)
