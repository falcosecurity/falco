# Required engine version scoping for rules

<!-- toc -->

## Summary

We want to be able to scope the `required_engine_version` field also for the specific rule/macro
other than just for the currently rules file.

## Motivation

While the Falco engine and drivers evolve, new fields are added. While new fields are added,
the upstream rules evolve too. This menas that we need a mechanism to be able to tell the users
and the engine at load time "Hey, this rule is compatible". We currently do that at file level
using the `required_engine_version` field.

While this is very handy, this also does not help users to understand what are the rules that require,
let's say engine verison `6` instead of `5`. It's very likely that 99% of a file is compatible with engine `2` while
in reality only one rule is not.

This is particularly useful for rules sharing. Users with different Falco versions can share rules containing this field
and instead of getting `<NA>` they can be informed immediatelly about the incompatibility.

### Goals

- To add a new field `required_engine_version` scoped to the `rule` and `macro` sections.
- The new fields take priority over the file global `required_engine_version` field.

### Non-Goals

- NONE

### Use cases

- Better understanding of what are the specific rules that need a specific engine version
- Helps for when we want to make an API to create/delete/modify rules at runtime. In such a dynamic scenarios it's very useful for users to just know in advance if that rule is compatible
- Makes easier to spot `<NA>` fields happening for `required_engine_version` mismatches  since the incompatibility is immediately reported by the engine.


### Example of rules file

```yaml
- required_engine_version: 2

- list: cat_binaries
  items: [cat]

- list: cat_capable_binaries
  items: [cat_binaries]

- macro: is_cat
  condition: proc.name in (cat_capable_binaries)

- rule: open_from_cat
  required_engine_version: 4
  desc: A process named cat does an open
  condition: evt.type=open and is_cat
  output: "An open was seen (command=%proc.cmdline)"
  priority: WARNING

```

---
