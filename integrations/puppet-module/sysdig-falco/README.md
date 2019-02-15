# Falco

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with Falco](#setup)
    * [What Falco affects](#what-falco-affects)
    * [Beginning with Falco](#beginning-with-falco)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Overview

Sysdig Falco is a behavioral activity monitor designed to detect anomalous activity in your applications. Powered by sysdig’s system call capture infrastructure, Falco lets you continuously monitor and detect container, application, host, and network activity... all in one place, from one source of data, with one set of rules.

#### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls. Thanks to Sysdig's core decoding and state tracking functionality, Falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. For example, you can easily detect things like:

- A shell is run inside a container
- A container is running in privileged mode, or is mounting a sensitive path like `/proc` from the host.
- A server process spawns a child process of an unexpected type
- Unexpected read of a sensitive file (like `/etc/shadow`)
- A non-device file is written to `/dev`
- A standard system binary (like `ls`) makes an outbound network connection

## Module Description

This module configures Falco as a systemd service. You configure Falco
to send its notifications to one or more output channels (syslog,
files, programs).

## Setup

### What Falco affects

This module affects the following:

* The main Falco configuration file `/etc/falco/falco.yaml`, including
** Output format (JSON vs plain text)
** Log level
** Rule priority level to run
** Output buffering
** Output throttling
** Output channels (syslog, file, program)

### Beginning with Falco

To have Puppet install Falco with the default parameters, declare the Falco class:

``` puppet
class { 'falco': }
```

When you declare this class with the default options, the module:

* Installs the appropriate Falco software package and installs the falco-probe kernel module for your operating system.
* Creates the required configuration file `/etc/falco/falco.yaml`. By default only syslog output is enabled.
* Starts the Falco service.

## Usage

### Enabling file output

To enable file output, set the `file_output` hash, as follows:

``` puppet
class { 'falco':
  file_output => {
    'enabled' => 'true',
    'keep_alive' => 'false',
	'filename' => '/tmp/falco-events.txt'
  },
}
```

### Enabling program output

To enable program output, set the `program_output` hash and optionally the `json_output` parameters, as follows:

``` puppet
class { 'falco':
  json_output => 'true',
  program_output => {
    'enabled' => 'true',
    'keep_alive' => 'false',
	'program' => 'curl http://some-webhook.com'
  },
}
```

## Reference

* [**Public classes**](#public-classes)
    * [Class: falco](#class-falco)

### Public Classes

#### Class: `falco`

Guides the basic setup and installation of Falco on your system.

When this class is declared with the default options, Puppet:

* Installs the appropriate Falco software package and installs the falco-probe kernel module for your operating system.
* Creates the required configuration file `/etc/Falco/falco.yaml`. By default only syslog output is enabled.
* Starts the falco service.

You can simply declare the default `falco` class:

``` puppet
class { 'falco': }
```

###### `rules_file`

An array of files for Falco to load. Order matters--the first file listed will be loaded first.

Default: `['/etc/falco/falco_rules.yaml', '/etc/falco/falco_rules.local.yaml']`

##### `json_output`

Whether to output events in json or text.

Default: `false`

##### `log_stderr`

Send Falco's logs to stderr. Note: this is not notifications, this is
logs from the Falco daemon itself.

Default: `false`

##### `log_syslog`

Send Falco's logs to syslog. Note: this is not notifications, this is
logs from the Falco daemon itself.

Default: `true`

##### `log_level`

Minimum log level to include in logs. Note: these levels are
separate from the priority field of rules. This refers only to the
log level of Falco's internal logging. Can be one of "emergency",
"alert", "critical", "error", "warning", "notice", "info", "debug".

Default: `info`

##### `priority`

Minimum rule priority level to load and run. All rules having a
priority more severe than this level will be loaded/run.  Can be one
of "emergency", "alert", "critical", "error", "warning", "notice",
"info", "debug".

Default: `debug`

##### `buffered_outputs`

Whether or not output to any of the output channels below is
buffered.

Default: `true`

##### `outputs_rate`/`outputs_max_burst`

A throttling mechanism implemented as a token bucket limits the
rate of Falco notifications. This throttling is controlled by the following configuration
options:

* `outputs_rate`: the number of tokens (i.e. right to send a notification)
   gained per second. Defaults to 1.
* `outputs_max_burst`: the maximum number of tokens outstanding. Defaults to 1000.

##### `syslog_output

Controls syslog output for notifications. Value: a hash, containing the following:

* `enabled`: `true` or `false`. Default: `true`.

Example:

``` puppet
class { 'falco':
  syslog_output => {
    'enabled' => 'true',
  },
}
```

##### `file_output`

Controls file output for notifications. Value: a hash, containing the following:

* `enabled`: `true` or `false`. Default: `false`.
* `keep_alive`: If keep_alive is set to true, the file will be opened once and continuously written to, with each output message on its own line. If keep_alive is set to false, the file will be re-opened for each output message. Default: `false`.
* `filename`: Notifications will be written to this file.

Example:

``` puppet
class { 'falco':
  file_output => {
    'enabled' => 'true',
    'keep_alive' => 'false',
	'filename' => '/tmp/falco-events.txt'
  },
}
```

##### `program_output

Controls program output for notifications. Value: a hash, containing the following:

* `enabled`: `true` or `false`. Default: `false`.
* `keep_alive`: If keep_alive is set to true, the file will be opened once and continuously written to, with each output message on its own line. If keep_alive is set to false, the file will be re-opened for each output message. Default: `false`.
* `program`: Notifications will be written to this program.

Example:

``` puppet
class { 'falco':
  program_output => {
    'enabled' => 'true',
    'keep_alive' => 'false',
	'program' => 'curl http://some-webhook.com'
  },
}
```

## Limitations

The module works where Falco works as a daemonized service (generally, Linux only).

## Development

For more information on Sysdig Falco, visit our [github](https://github.com/falcosecurity/falco) or [web site](https://sysdig.com/opensource/falco/).
