# gRPC Falco Output

<!-- toc -->

## Summary

We intend to build a gRPC interface to allow users receive and consume the alerts regarding the violated rul.

## Motivation

The most valuable information that Falco can give to its users are the alerts.
An alert is given by Falco each time a rule is matched.
At the current moment, however, Falco can deliver alerts in a very basic way, for example by dumping
them to standard output.

For this reason, many Falco users asked, with issues - eg., [falco#528](https://github.com/falcosecurity/falco/issues/528) - or in the [slack channel]() if we can find a more consumable way to
implement Falco outputs in an extensible way.

The motivation behind this proposal is to design a new output implementation that can meet our user's needs.

### Goals

- To design and implement an additional output containing a gRPC client
- To keep it as simple as possible
- To have a simple contract interface
- To only have the responsibility to route Falco output requests and responses
- To continue supporting the old output formats by implementing their same interface
- To be secure by default
- To be asynchronous and non-blocking


### Non-Goals

- To substitute existing outputs (stdout, syslog, etc.)
- To support connecting to multiple gRPC servers
  - Users can have a single server multiplexing requests to multiple servers
- To support queuing mechanisms for message retransmission
  - Users can have a local gRPC relay server along with Falco that multiplexes connections and handles retires and backoff
- To change the output format
- To make the message context (text, fields, etc.) and format configurable
  - Users can already override rules changing their output messages
- To act as an orchestrator for Falco instances


## Proposal

## Design Details

---
