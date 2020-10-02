# Proposal for First Class Structured Exceptions in Falco Rules

## Summary

## Motivation

Almost all Falco Rules have cases where the behavior detected by the
rule should be allowed. For example, The rule Write Below Binary Dir
has exceptions for specific programs that are known to write below
these directories as a part of software installation/management:

```
- rule: Write below binary dir
  desc: an attempt to write to any file below a set of binary directories
  condition: >
    bin_dir and evt.dir = < and open_write
    and not package_mgmt_procs
    and not exe_running_docker_save
    and not python_running_get_pip
    and not python_running_ms_oms
    and not user_known_write_below_binary_dir_activities
...
```
In most cases, these exceptions are expressed as concatenations to the original rule's condition. For example, looking at the macro package_mgmt_procs:

```
- macro: package_mgmt_procs
  condition: proc.name in (package_mgmt_binaries)
```

The result is appending `and not proc.name in (package_mgmt_binaries)` to the condition of the rule.

A more extreme case of this is the write_below_etc macro used by Write below etc rule. It has tens of exceptions:

```
...
    and not sed_temporary_file
    and not exe_running_docker_save
    and not ansible_running_python
    and not python_running_denyhosts
    and not fluentd_writing_conf_files
    and not user_known_write_etc_conditions
    and not run_by_centrify
    and not run_by_adclient
    and not qualys_writing_conf_files
    and not git_writing_nssdb
...
```

The exceptions all generally follow the same structure--naming a program and a directory prefix below /etc where that program is allowed to write files.

### Using Appends/Overwrites to Customize Rules

An important way to customize rules and macros is to use `append: true` to add to them, or `append: false` to define a new rule/macro, overwriting the original rule/macro. Here's an example from Update Package Repository:

```
- list: package_mgmt_binaries
  items: [rpm_binaries, deb_binaries, update-alternat, gem, pip, pip3, sane-utils.post, alternatives, chef-client, apk, snapd]

- macro: package_mgmt_procs
  condition: proc.name in (package_mgmt_binaries)

- macro: user_known_update_package_registry
  condition: (never_true)

- rule: Update Package Repository
  desc: Detect package repositories get updated
  condition: >
    ((open_write and access_repositories) or (modify and modify_repositories))
`    and not package_mgmt_procs
    and not exe_running_docker_save
    and not user_known_update_package_registry
```

If someone wanted to add additional exceptions to this rule, they could add the following to the user_rules file:

```
- list: package_mgmt_binaries
  items: [puppet]
  append: true

- macro: package_mgmt_procs
  condition: and not proc.pname=chef
  append: true

- macro: user_known_update_package_registry
  condition: (proc.name in (npm))
  append: false
```

This adds an 3 different exceptions:
* an additional binary to package_mgmt_binaries (because append is true),
* adds to package_mgmt_procs, adding an exception for programs spawned by chef (because append is true)
* overrides the macro user_known_update_package_registry to add an exception for npm (because append is false).

### Problems with Appends/Overrides to Define Exceptions

Although the concepts of macros and lists in condition fields, combined with appending to lists/conditions in macros/rules, is very general purpose, it can be unwieldy:

* Appending to conditions can result in incorrect behavior, unless the original condition has its logical operators set up properly with parentheses. For example:

```
rule: my_rule
condition: (evt.type=open and (fd.name=/tmp/foo or fd.name=/tmp/bar))

rule: my_rule
condition: or fd.name=/tmp/baz
append: true
```

Results in unintended behavior. It will match any fd related event where the name is /tmp/baz, when the intent was probably to add /tmp/baz as an additional opened file.

* A good convention many rules use is to have a clause "and not user_known_xxxx" built into the condition field. However, it's not in all rules and its use is a bit haphazard.

* Appends and overrides can get confusing if you try to apply them multiple times. For example:

```
macro: allowed_files
condition: fd.name=/tmp/foo

...

macro: allowed_files
condition: and fd.name=/tmp/bar
append: true
```

If someone wanted to override the original behavior of allowed_files, they would have to use `append: false` in a third definition of allowed_files, but this would result in losing the append: true override.

## Solution: Exceptions as first class objects

To address some of these problems, we will add the notion of Exceptions as top level objects alongside Rules, Macros, and Lists. A rule that supports exceptions must define a new key `exceptions` in the rule. The exceptions key is a list of identifier plus list of tuples of filtercheck fields. Here's an example:

```
- rule: Write below binary dir
  desc: an attempt to write to any file below a set of binary directories
  condition: >
    bin_dir and evt.dir = < and open_write
    and not package_mgmt_procs
    and not exe_running_docker_save
    and not python_running_get_pip
    and not python_running_ms_oms
    and not user_known_write_below_binary_dir_activities
  exceptions:
   - name: proc_writer
     fields: [proc.name, fd.directory]
   - name: container_writer
     fields: [container.image.repository, fd.directory]
     comps: [=, startswith]
```

This rule defines two kinds of exceptions: one called proc_writer with a combination of proc.name and fd.directory, and a second called container_writer with a combination of container.image.repository and fd.directory. The specific strings "proc_writer" and "container_writer" are arbitrary strings and don't have a special meaning to the rules file parser. They're only used to link together the list of field names with the list of field values that exist in the exception object.

proc_writer does not have any comps property, so the fields are directly compared to values using the = operator. container_writer does have a comps property, so each field will be compared to the corresponding exception items using the corresponding comparison operator.

Notice that exceptions are defined as a part of the rule. This is important because the author of the rule defines what construes a valid exception to the rule. In this case, an exception can consist of a process and file directory (actor and target), but not a process name only (too broad).

We'll add a new object exception that defines exceptions to a rule:

```
- exception: Write below binary dir
  items:
  - name: proc_writer
    values:
    - [apk, /usr/lib/alpine]
    - [npm, /usr/node/bin]
  - name: container_writer
    values:
    - [docker.io/alpine, /usr/libexec/alpine]
```

The name of the exception links it to the rule.

A rule exception applies if for a given event, the fields in a rule.exception match all of the values in some exception.item. For example, if a program `apk` writes to a file below `/usr/lib/alpine`, the rule will not trigger, even if the condition is met.

Append will be supported for exception objects. If append: is true, the items in the second definition will be added to the items in the earlier definition. For example, adding:

```
- exception: Write below binary dir
  items:
  - container_writer:
    - [docker.io/golang-alpine, /usr/libexec/go]
  append: true
```

Would add a second container_writer exception.

### Implementation

Each exception can be thought of as an implicit "and not (field1 cmp1 val1 and field2 cmp2 val2 and...)" appended to the rule's condition. In practice, that's how exceptions will be implemented.

When a rule is parsed, the original condition will be wrapped in an extra layer of parentheses and all exception values will be appended to the condition. For example, using the example above, the resulting condition will be:

```
(<Write below binary dir condition>) and not ((proc.name = apk and fd.directory = /usr/lib/alpine) or (proc.name = npm and fd.directory = /usr/node/bin) or (container.image.repository = docker.io/alpine and fd.directory startswith /usr/libexec/alpine))
```

The exceptions are effectively syntatic sugar that allows expressing sets of exceptions in a concise way.

### Advantages

Adding Exception objects as described here has several advantages:

* All rules will implicitly support exceptions. A rule writer doesn't need to define a user_known_xxx macro and add it to the condition.
* The rule writer has some controls on what defines a valid exception. The rule author knows best what is a good exception, and can define the fields that make up the exception.
* With this approach, it's much easier to add and manage multiple sets of exceptions from multiple sources. You're just combining lists of tuples of filtercheck field values.

## Backwards compatibility

To take advantage of these new features, users will need to upgrade Falco to a version that supports exception objects and exception keys in rules. For the most part, however, the rules file structure is unchanged.

This approach does not remove the ability to append to exceptions nor the existing use of user_xxx macros to define exceptions to rules. It only provides an additional way to express exceptions. Hopefully, we can migrate existing exceptions to use this approach, but there isn't any plan to make wholesale rules changes as a part of this.

This approach is for the most part backwards compatible with older Falco releases. To implement exceptions, we'll add a preprocessing element to rule parsing. The main Falco engine is unchanged.

However, there are a few changes we'll have to make to Falco rules file parsing:

* Currently, Falco will reject files containing anything other than rule/macro/list top-level objects. As a result, `exception` objects would be rejected. We'll probably want to make a one-time change to Falco to allow arbitrary top level objects.
* Similarly, Falco will reject rule objects with exception keys. We'll also probably want to change Falco to allow unknown keys inside rule/macro/list/exception objects.




