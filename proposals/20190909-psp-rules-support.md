# Support for K8s Pod Security Policies (PSPs) in Falco

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
  * [Goals](#goals)
  * [Non-Goals](#non-goals)
- [Proposal](#proposal)
  * [Use cases](#use-cases)
  * [Diagrams](#diagrams)
  * [Design Details](#design-details)

<!-- tocstop -->

## Summary

We want to make it easier for K8s Cluster Operators to Author Pod Security Policies by providing a way to read a PSP, convert it to a set of falco rules, and then run falco with those rules.

## Motivation

PSPs provide a rich powerful framework to restrict the behavior of pods and apply consistent security policies across a cluster, but it’s difficult to know the gap between what you want your security policy to be and what your cluster is actually doing. Additionally, since PSPs enforce once applied, they might prevent pods from running, and the process of tuning a PSP live on a cluster can be disruptive and painful.

That's where Falco comes in. We want to make it possible for Falco to perform a “dry run” evaluation of a PSP, translating it to Falco rules that observe the behavior of deployed pods and sending alerts for violations, *without* blocking. This helps accelerate the authoring cycle, providing a complete authoring framework for PSPs without deploying straight to the cluster.

### Goals

Transparently read a candidate PSP into an equivalent set of falco rules that can look for the conditions in the PSP.

### Non-Goals

Falco will not automatically read PSPs from a cluster, will not install PSPs, and will not provide guidance on the parts of your infrastructure that are already covered by PSPs. This feature only helps with the testing part of a candidate PSP. For coming up with an initial PSP, you can use tools like [https://github.com/sysdiglabs/kube-psp-advisor](Kube PSP Advisor).

## Proposal

### Use cases

You'll be able to run falco with a `--psp` argument that provides a single PSP Yaml file. Falco will automatcially convert the PSP into an equivalent set of falco rules, load the rules, and then run with the loaded rules. You can optionally provide a `--psp_save=<path>` command line option to save the converted rules to a file.

### Diagrams

No diagrams yet.

### Design Details

* We'll use [inja](https://github.com/pantor/inja) as the templating engine.

* For the most part, we can rely on the existing framework of rules, filter expressions, and output expressions that already exist in Falco. One significant change will be that filter fields can extract more than one "value" per event, and we'll need to define new operators to perform set comparisions betweeen values in an event and values in the comparison right-hand-side.

* This will rely heavily on existing support for [K8s Audit Events](https://falco.org/docs/event-sources/kubernetes-audit/) in Falco.
