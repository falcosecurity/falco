# Falco rule naming convention

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
  * [Goals](#goals)
  * [Non-Goals](#non-goals)
- [Proposal](#proposal)
  * [Use cases](#use-cases)
  * [Diagrams](#diagrams)
  * [Design Details](#design-details)
    + [Rule](#rule)
    + [Macro](#macro)
    + [List](#list)

<!-- tocstop -->

## Summary

Propose some basic naming conventions when new lists, macros, rules are introduced. 

## Motivation

We want to help people from the community to contribute to falco rules. It will help improving the security content provided by Falco out of the box. Since people have different preference of naming things, it's necessary to set forth some basic naming convention for people to follow when creating new rules, macros and lists.

### Goals

People will have to follow the naming conventions rules when introducing new Falco rules, macros and lists.

### Non-Goals

There will be no intention to cover Falco rule syntax in this proposal.

## Proposal

### Use cases

When new PRs are created in the area of rules, reviewers need to examine whether there are new rules, macros or lists are introduced. If yes, check wether follow the naming convention.

### Diagrams

N/A

### Design Details

#### Rule
- Rule Name: Use phrases with capitalizing every word except preposition (e.g. `Search Private Keys or Passwords`)
- Description: Use sentence always starting with "Detect" and ending with period. (e.g. `Detect grep private keys or passwords activity.`)
- Output: Use sentence. Must at least include output fields (user=%user.name command=%proc.cmdline container_id=%container.id)
- Tags: Use at least one of the following: [network, process, filesystem]. Also encourage to use mitre_* tags if applicable

#### Macro
- Macro Name: Use lowercase_separated_by_underscores (e.g. `parent_java_running_zookeeper`)

#### List
- List Name: Use lowercase_separated_by_underscores (e.g. `protected_shell_spawning_binaries`)
