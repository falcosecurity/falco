# Change Log

This file documents all notable changes to Falco. The release numbering uses [semantic versioning](http://semver.org).

## v0.5.0

Released 2016-12-22

Starting with this release, we're adding a new section "Rule Changes" devoted to changes to the default ruleset `falco_rules.yaml`.

### Major Changes

* Cache event formatting objects so they are not re-created for every falco notification. This can result in significant speedups when the ruleset results in lots of notifications. [[#158](https://github.com/draios/falco/pull/158)]
* Falco notifications are now throttled by a token bucket, preventing a flood of notifications when many events match a rule. Controlled by the `outputs, rate` and `outputs, max_burst` options. [[#161](https://github.com/draios/falco/pull/161)]

### Minor Changes

* When run from a container, you can provide the environment variable `SYSDIG_SKIP_LOAD` to skip the process of building/loading the kernel module. Thanks @carlsverre for the fix. [[#145](https://github.com/draios/falco/pull/145)]
* Fully implement `USE_BUNDLED_DEPS` within CMakeFiles so you can build with external third-party libraries. [[#147](https://github.com/draios/falco/pull/147)]
* Improve error messages that result when trying to load a rule with a malformed `output:` attribute [[#150](https://github.com/draios/falco/pull/150)] [[#151](https://github.com/draios/falco/pull/151)]
* Add the ability to write event capture statistics to a file via the `-s <statsfile>` option. [[#155](https://github.com/draios/falco/pull/155)]
* New configuration option `log_level` controls the verbosity of falco's logging. [[#160](https://github.com/draios/falco/pull/160)]


### Bug Fixes

* Improve compatibility with Sysdig Cloud Agent build [[#148](https://github.com/draios/falco/pull/148)]

### Rule Changes

* Add DNF as non-alerting for RPM and package management. Thanks @djcross for the fix. [[#153](https://github.com/draios/falco/pull/153)]
* Make `google_containers/kube-proxy` a trusted image, affecting the File Open by Privileged Container/Sensitive Mount by Container rules. [[#159](https://github.com/draios/falco/pull/159)]
* Add fail2ban-server as a program that can spawn shells. Thanks @jcoetzee for the fix. [[#168](https://github.com/draios/falco/pull/168)]
* Add systemd as a program that can access sensitive files. Thanks @jcoetzee for the fix. [[#169](https://github.com/draios/falco/pull/169)]
* Add apt/apt-get as programs that can spawn shells. Thanks @jcoetzee for the fix. [[#170](https://github.com/draios/falco/pull/170)]

## v0.4.0

Released 2016-10-25

As falco depends heavily on sysdig, many changes here were actually made to sysdig and pulled in as a part of the build process. Issues/PRs starting with `sysdig/#XXX` are sysdig changes.

### Major Changes

* Improved visibility into containers:
** New filter `container.privileged` to match containers running in privileged mode [[sysdig/#655](https://github.com/draios/sysdig/pull/655)] [[sysdig/#658](https://github.com/draios/sysdig/pull/658)]
** New rules utilizing privileged state [[#121](https://github.com/draios/falco/pull/121)]
** New filters `container.mount*` to match container mount points [[sysdig/#655](https://github.com/draios/sysdig/pull/655)]
** New rules utilizing container mount points [[#120](https://github.com/draios/falco/pull/120)]
** New filter `container.image.id` to match container image id [[sysdig/#661](https://github.com/draios/sysdig/pull/661)]

* Improved visibility into orchestration environments:
** New k8s.deployment.* and k8s.rs.* filters to support latest kubernetes features [[sysdg/#dbf9b5c](https://github.com/draios/sysdig/commit/dbf9b5c893d49f945c59684b4effe5700d730973)]
** Rule changes to avoid FPs when monitoring k8s environments [[#138](https://github.com/draios/falco/pull/138)]
** Add new options `-pc`/`-pk`/`-pm`/`-k`/`-m` analogous to sysdig command line options. These options pull metadata information from k8s/mesos servers and adjust default falco notification outputs to contain container/orchestration information when applicable. [[#131](https://github.com/draios/falco/pull/131)] [[#134](https://github.com/draios/falco/pull/134)]

* Improved ability to work with file pathnames:
** Added `glob` operator for strings, works as classic shell glob path matcher [[sysdig/#653](https://github.com/draios/sysdig/pull/653)]
** Added `pmatch` operator to efficiently test a subject pathname against a set of target pathnames, to see if the subject is a prefix of any target [[sysdig/#660](https://github.com/draios/sysdig/pull/660)] [[#125](https://github.com/draios/falco/pull/125)]

### Minor Changes

* Add an event generator program that simulates suspicious activity that can be detected by falco. This is also available as a docker image [[sysdig/falco-event-generator](https://hub.docker.com/r/sysdig/falco-event-generator/)]. [[#113](https://github.com/draios/falco/pull/113)] [[#132](https://github.com/draios/falco/pull/132)]
* Changed rule names to be human readable [[#116](https://github.com/draios/falco/pull/116)]
* Add Copyright notice to all source files [[#126](https://github.com/draios/falco/pull/126)]
* Changes to docker images to make it easier to massage JSON output for webhooks [[#133](https://github.com/draios/falco/pull/133)]
* When run with `-v`, print statistics on the number of events processed and dropped [[#139](https://github.com/draios/falco/pull/139)]
* Add ability to write trace files with `-w`. This can be useful to write a trace file in parallel with live event monitoring so you can reproduce it later. [[#140](https://github.com/draios/falco/pull/140)]
* All rules can now take an optional `enabled` flag. With `enabled: false`, a rule will not be loaded or run against events. By default all rules are enabled [[#119](https://github.com/draios/falco/pull/119)]

### Bug Fixes

* Fixed rule FPs related to docker's `docker`/`dockerd` split in 1.12 [[#112](https://github.com/draios/falco/pull/112)]
* Fixed rule FPs related to sysdigcloud agent software [[#141](https://github.com/draios/falco/pull/141)]
* Minor changes to node.js example to avoid falco false positives [[#111](https://github.com/draios/falco/pull/111/)]
* Fixed regression that broke configurable outputs [[#117](https://github.com/draios/falco/pull/117)]. This was not broken in 0.3.0, just between 0.3.0 and 0.4.0.
* Fixed a lua stack leak that could cause problems when matching millions of events against a large set of rules [[#123](https://github.com/draios/falco/pull/123)]
* Update docker files to reflect changes to `debian:unstable` docker image [[#124](https://github.com/draios/falco/pull/124)]
* Fixed logic for detecting config files to ensure config files in `/etc/falco.yaml` are properly detected  [[#135](https://github.com/draios/falco/pull/135)] [[#136](https://github.com/draios/falco/pull/136)]
* Don't alert on falco spawning a shell for program output notifications [[#137](https://github.com/draios/falco/pull/137)]

## v0.3.0

Released 2016-08-05

### Major Changes

Significantly improved performance, involving changes in the falco and sysdig repositories:

* Reordering a rule condition's operators to put likely-to-fail operators at the beginning and expensive operators at the end. [[#95](https://github.com/draios/falco/pull/95/)] [[#104](https://github.com/draios/falco/pull/104/)]
* Adding the ability to perform x in (a, b, c, ...) as a single set membership test instead of individual comparisons between x=a, x=b, etc. [[#624](https://github.com/draios/sysdig/pull/624)] [[#98](https://github.com/draios/falco/pull/98/)]
* Avoid unnecessary string manipulations. [[#625](https://github.com/draios/sysdig/pull/625)]
* Using `startswith` as a string comparison operator when possible. [[#623](https://github.com/draios/sysdig/pull/623)]
* Use `is_open_read`/`is_open_write` when possible instead of searching through open flags. [[#610](https://github.com/draios/sysdig/pull/610)]
* Group rules by event type, which allows for an initial filter using event type before going through each rule's condition. [[#627](https://github.com/draios/sysdig/pull/627)] [[#101](https://github.com/draios/falco/pull/101/)]

All of these changes result in dramatically reduced CPU usage. Here are some comparisons between 0.2.0 and 0.3.0 for the following workloads:

* [Phoronix](http://www.phoronix-test-suite.com/)'s `pts/apache` and `pts/dbench` tests.
* Sysdig Cloud Kubernetes Demo: Starts a kubernetes environment using docker with apache and wordpress instances + synthetic workloads.
* [Juttle-engine examples](https://github.com/juttle/juttle-engine/blob/master/examples/README.md) : Several elasticsearch, node.js, logstash, mysql, postgres, influxdb instances run under docker-compose.

| Workload | 0.2.0 CPU Usage | 0.3.0 CPU Usage |
|----------| --------------- | ----------------|
| pts/apache | 24% | 7% |
| pts/dbench | 70% | 5% |
| Kubernetes-Demo (Running) | 6% | 2% |
| Kubernetes-Demo (During Teardown) | 15% | 3% |
| Juttle-examples | 3% | 1% |

As a part of these changes, falco now prefers rule conditions that have at least one `evt.type=` operator, at the beginning of the condition, before any negative operators (i.e. `not` or `!=`). If a condition does not have any `evt.type=` operator, falco will log a warning like:

```
Rule no_evttype: warning (no-evttype):
proc.name=foo
     did not contain any evt.type restriction, meaning it will run for all event types.
     This has a significant performance penalty. Consider adding an evt.type restriction if possible.
```

If a rule has a `evt.type` operator in the later portion of the condition, falco will log a warning like:

```
Rule evttype_not_equals: warning (trailing-evttype):
evt.type!=execve
     does not have all evt.type restrictions at the beginning of the condition,
     or uses a negative match (i.e. "not"/"!=") for some evt.type restriction.
     This has a performance penalty, as the rule can not be limited to specific event types.
     Consider moving all evt.type restrictions to the beginning of the rule and/or
     replacing negative matches with positive matches if possible.
```


### Minor Changes

* Several sets of rule cleanups to reduce false positives. [[#95](https://github.com/draios/falco/pull/95/)]
* Add example of how falco can detect abuse of a badly designed REST API. [[#97](https://github.com/draios/falco/pull/97/)]
* Add a new output type "program" that writes a formatted event to a configurable program. Each notification results in one invocation of the program. A common use of this output type would be to send an email for every falco notification. [[#105](https://github.com/draios/falco/pull/105/)] [[#99](https://github.com/draios/falco/issues/99)]
* Add the ability to run falco on all events, including events that are flagged with `EF_DROP_FALCO`. (These events are high-volume, low-value events that are ignored by default to improve performance). [[#107](https://github.com/draios/falco/pull/107/)] [[#102](https://github.com/draios/falco/issues/102)]

### Bug Fixes

* Add third-party jq library now that sysdig requires it. [[#96](https://github.com/draios/falco/pull/96/)]

## v0.2.0

Released 2016-06-09

For full handling of setsid system calls and session id tracking using `proc.sname`, falco requires a sysdig version >= 0.10.0.

### Major Changes

- Add TravisCI regression tests. Testing involves a variety of positive, negative, and informational trace files with both plain and json output. [[#76](https://github.com/draios/falco/pull/76)] [[#83](https://github.com/draios/falco/pull/83)]
- Fairly big rework of ruleset to improve coverage, reduce false positives, and handle installation environments effectively [[#83](https://github.com/draios/falco/pull/83)] [[#87](https://github.com/draios/falco/pull/87)]
- Not directly a code change, but mentioning it here--the Wiki has now been populated with an initial set of articles, migrating content from the README and adding detail when necessary. [[#90](https://github.com/draios/falco/pull/90)]

### Minor Changes

- Improve JSON output to include the rule name, full output string, time, and severity [[#89](https://github.com/draios/falco/pull/89)]

### Bug Fixes

- Improve CMake quote handling [[#84](https://github.com/draios/falco/pull/84)]
- Remove unnecessary NULL check of a delete [[#85](https://github.com/draios/falco/pull/85)]

## v0.1.0

Released 2016-05-17

### Major Changes

- Initial release. Subsequent releases will have "Major Changes", "Minor Changes", and "Bug Fixes" sections, with links to github issues/pull requests as appropriate.
