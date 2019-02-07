# Change Log

This file documents all notable changes to Falco. The release numbering uses [semantic versioning](http://semver.org).

## v0.14.0

Released 2019-02-06

## Major Changes

* Rules versioning support: The falco engine and executable now have an *engine version* that represents the fields they support. Similarly, rules files have an optional *required_engine_version: NNN* object that names the minimum engine version required to read that rules file. Any time the engine adds new fields, event sources, etc, the engine version will be incremented, and any time a rules file starts using new fields, event sources, etc, the required engine version will be incremented. [[#492](https://github.com/falcosecurity/falco/pull/492)]

* Allow SSL for K8s audit endpoint/embedded webserver [[#471](https://github.com/falcosecurity/falco/pull/471)]

* Add stale issues bot that automatically flags old github issues as stale after 60 days of inactivity and closes issues after 67 days of inactivity. [[#500](https://github.com/falcosecurity/falco/pull/500)]

* Support bundle: When run with `--support`, falco will print a json object containing necessary information like falco version, command line, operating system information, and falco rules files contents. This could be useful when reporting issues. [[#517](https://github.com/falcosecurity/falco/pull/517)]

## Minor Changes

* Support new third-party library dependencies from open source sysdig. [[#498](https://github.com/falcosecurity/falco/pull/498)]

* Add CII best practices badge. [[#499](https://github.com/falcosecurity/falco/pull/499)]

* Fix kernel module builds when running on centos as a container by installing gcc 5 by hand instead of directly from debian/unstable. [[#501](https://github.com/falcosecurity/falco/pull/501)]

* Mount `/etc` when running as a container, which allows container to build kernel module/ebpf program on COS/Minikube. [[#475](https://github.com/falcosecurity/falco/pull/475)]

* Improved way to specify the source of generic event objects [[#480](https://github.com/falcosecurity/falco/pull/480)]

* Readability/clarity improvements to K8s Audit/K8s Daemonset READMEs. [[#503](https://github.com/falcosecurity/falco/pull/503)]

* Add additional RBAC permissions to track deployments/daemonsets/replicasets. [[#514](https://github.com/falcosecurity/falco/pull/514)]

## Bug Fixes

* Fix formatting of nodejs examples README [[#502](https://github.com/falcosecurity/falco/pull/502)]

## Rule Changes

* Remove FPs for `Launch Sensitive Mount Container` rule [[#509](https://github.com/falcosecurity/falco/pull/509/files)]

* Update Container rules/macros to use the more reliable `container.image.{repository,tag}` that always return the repository/tag of an image instead of `container.image`, which may not for some docker daemon versions. [[#513](https://github.com/falcosecurity/falco/pull/513)]

## v0.13.1

Released 2019-01-16

## Major Changes


## Minor Changes

* Unbuffer outputs by default. This helps make output readable when used in environments like K8s. [[#494](https://github.com/falcosecurity/falco/pull/494)]

* Improved documentation for running Falco within K8s and getting K8s Audit Logging to work with Minikube and Falco as a Daemonset within K8s. [[#496](https://github.com/falcosecurity/falco/pull/496)]

* Fix AWS Permissions for Kubernetes Response Engine [[#465](https://github.com/falcosecurity/falco/pull/465)]

* Tighten compilation flags to include `-Wextra` and `-Werror` [[#479](https://github.com/falcosecurity/falco/pull/479)]

* Add `k8s.ns.name` to outputs when `-pk` argument is used [[#472](https://github.com/falcosecurity/falco/pull/472)]

* Remove kubernetes-response-engine from system:masters [[#488](https://github.com/falcosecurity/falco/pull/488)]

## Bug Fixes

* Ensure `-pc`/`-pk` only apply to syscall rules and not k8s_audit rules [[#495](https://github.com/falcosecurity/falco/pull/495)]

* Fix a potential crash that could occur when using the falco engine and rulesets [[#468](https://github.com/falcosecurity/falco/pull/468)]

* Fix a regression where format output options were mistakenly removed [[#485](https://github.com/falcosecurity/falco/pull/485)]

## Rule Changes

* Fix FPs related to calico and writing files below etc [[#481](https://github.com/falcosecurity/falco/pull/481)]

* Fix FPs related to `apt-config`/`apt-cache`, `apk` [[#490](https://github.com/falcosecurity/falco/pull/490)]

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, `Lauch Suspicious Network Tool in Container` look for host-level network tools like `netcat`, package management tools like `apt-get`, or network tool binaries being run in a container. [[#490](https://github.com/falcosecurity/falco/pull/490)]

* Fix the `inbound` and `outbound` macros so they work with sendto/recvfrom/sendmsg/recvmsg. [[#470](https://github.com/falcosecurity/falco/pull/470)]

* Fix FPs related to prometheus/openshift writing config below /etc. [[#470](https://github.com/falcosecurity/falco/pull/470)]


## v0.13.0

Released 2018-11-09

## Major Changes

* **Support for K8s Audit Events** : Falco now supports [K8s Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) as a second stream of events in addition to syscalls. For full details on the feature, see the [wiki](https://github.com/falcosecurity/falco/wiki/K8s-Audit-Event-Support).

* Transparent Config/Rule Reloading: On SIGHUP, Falco will now reload all config files/rules files and start processing new events. Allows rules changes without having to restart falco [[#457](https://github.com/falcosecurity/falco/pull/457)] [[#432](https://github.com/falcosecurity/falco/issues/432)]

## Minor Changes

* The reference integration of falco into a action engine now supports aws actions like lambda, etc. [[#460](https://github.com/falcosecurity/falco/pull/460)]

* Add netcat to falco docker images, which allows easier integration of program outputs to external servers [[#456](https://github.com/falcosecurity/falco/pull/456)] [[#433](https://github.com/falcosecurity/falco/issues/433)]

## Bug Fixes

* Links cleanup related to the draios/falco -> falcosecurity/falco move [[#447](https://github.com/falcosecurity/falco/pull/447)]

* Properly load/unload kernel module when the falco service is started/stopped [[#459](https://github.com/falcosecurity/falco/pull/459)] [[#418](https://github.com/falcosecurity/falco/issues/418)]

## Rule Changes

* Better coverage (e.g. reduced FPs) for critical stack, hids systems, ufw, cloud-init, etc. [[#445](https://github.com/falcosecurity/falco/pull/445)]

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, and `Lauch Suspicious Network Tool in Container` look for running various suspicious programs in a container. [[#461](https://github.com/falcosecurity/falco/pull/461)]

* Misc changes to address false positives in GKE, Istio, etc. [[#455](https://github.com/falcosecurity/falco/pull/455)] [[#439](https://github.com/falcosecurity/falco/issues/439)]

## v0.12.1

Released 2018-09-11

## Bug Fixes

* Fig regression in libcurl configure script [[#416](https://github.com/draios/falco/pull/416)]

## v0.12.0

Released 2018-09-11

## Major Changes

* Improved IPv6 Support to fully support use of IPv6 addresses in events, connections and filters [[#sysdig/1204](https://github.com/draios/sysdig/pull/1204)]

* Ability to associate connections with dns names: new filterchecks `fd.*ip.name` allow looking up the DNS name for a connection's IP address. This can be used to identify or restrict connections by dns names e.g. `evt.type=connect and fd.sip.name=github.com`. [[#412](https://github.com/draios/falco/pull/412)] [[#sysdig/1213](https://github.com/draios/sysdig/pull/1213)]

* New filterchecks `user.loginuid` and `user.loginname` can be used to match the login uid, which stays consistent across sudo/su. This can be used to find the actual user running a given process [[#sysdig/1189](https://github.com/draios/sysdig/pull/1189)]

## Minor Changes

* Upgrade zlib to 1.2.11, openssl to 1.0.2n, and libcurl to 7.60.0 to address software vulnerabilities [[#402](https://github.com/draios/falco/pull/402)]
* New `endswith` operator can be used for suffix matching on strings [[#sysdig/1209](https://github.com/draios/sysdig/pull/1209)]

## Bug Fixes

* Better control of specifying location of lua source code [[#406](https://github.com/draios/falco/pull/406)]

## Rule Changes

* None for this release.

## v0.11.1

Released 2018-07-31

## Bug Fixes

* Fix a problem that caused the kernel module to not load on certain kernel versions [[#397](https://github.com/draios/falco/pull/397)] [[#394](https://github.com/draios/falco/issues/394)]

## v0.11.0

Released 2018-07-24

## Major Changes

* **EBPF Support** (Beta): Falco can now read events via an ebpf program loaded into the kernel instead of the `falco-probe` kernel module. Full docs [here](https://github.com/draios/sysdig/wiki/eBPF-(beta)). [[#365](https://github.com/draios/falco/pull/365)]

## Minor Changes

* Rules may now have an `skip-if-unknown-filter` property. If set to true, a rule will be skipped if its condition/output property refers to a filtercheck (e.g. `fd.some-new-attibute`) that is not present in the current falco version. [[#364](https://github.com/draios/falco/pull/364)] [[#345](https://github.com/draios/falco/issues/345)]
* Small changes to Falco `COPYING` file so github automatically recognizes license [[#380](https://github.com/draios/falco/pull/380)]
* New example integration showing how to connect Falco with Anchore to dynamically create falco rules based on negative scan results [[#390](https://github.com/draios/falco/pull/390)]
* New example integration showing how to connect Falco, [nats](https://nats.io/), and K8s to run flexible "playbooks" based on Falco events [[#389](https://github.com/draios/falco/pull/389)]

## Bug Fixes

* Ensure all rules are enabled by default [[#379](https://github.com/draios/falco/pull/379)]
* Fix libcurl compilation problems [[#374](https://github.com/draios/falco/pull/374)]
* Add gcc-6 to docker container, which improves compatibility when building kernel module [[#382](https://github.com/draios/falco/pull/382)] [[#371](https://github.com/draios/falco/issues/371)]
* Ensure the /lib/modules symlink to /host/lib/modules is set correctly [[#392](https://github.com/draios/falco/issues/392)]

## Rule Changes

* Add additional binary writing programs [[#366](https://github.com/draios/falco/pull/366)]
* Add additional package management programs [[#388](https://github.com/draios/falco/pull/388)] [[#366](https://github.com/draios/falco/pull/366)]
* Expand write_below_etc handling for additional programs [[#388](https://github.com/draios/falco/pull/388)] [[#366](https://github.com/draios/falco/pull/366)]
* Expand set of programs allowed to write to `/etc/pki` [[#388](https://github.com/draios/falco/pull/388)]
* Expand set of root written directories/files [[#388](https://github.com/draios/falco/pull/388)] [[#366](https://github.com/draios/falco/pull/366)]
* Let pam-config read sensitive files [[#388](https://github.com/draios/falco/pull/388)]
* Add additional trusted containers: openshift, datadog, docker ucp agent, gliderlabs logspout [[#388](https://github.com/draios/falco/pull/388)]
* Let coreos update-ssh-keys write to /home/core/.ssh [[#388](https://github.com/draios/falco/pull/388)]
* Expand coverage for MS OMS [[#388](https://github.com/draios/falco/issues/388)] [[#387](https://github.com/draios/falco/issues/387)]
* Expand the set of shell spawning programs [[#366](https://github.com/draios/falco/pull/366)]
* Add additional mysql programs/directories [[#366](https://github.com/draios/falco/pull/366)]
* Let program `id` open network connections [[#366](https://github.com/draios/falco/pull/366)]
* Opt-in rule for protecting tomcat shell spawns [[#366](https://github.com/draios/falco/pull/366)]
* New rule `Write below monitored directory` [[#366](https://github.com/draios/falco/pull/366)]

## v0.10.0

Released 2018-04-24

## Major Changes

* **Rules Directory Support**: Falco will read rules files from `/etc/falco/rules.d` in addition to `/etc/falco/falco_rules.yaml` and `/etc/falco/falco_rules.local.yaml`. Also, when the argument to `-r`/falco.yaml `rules_file` is a directory, falco will read rules files from that directory. [[#348](https://github.com/draios/falco/pull/348)] [[#187](https://github.com/draios/falco/issues/187)]
* Properly support all syscalls (e.g. those without parameter extraction by the kernel module) in falco conditions, so they can be included in `evt.type=<name>` conditions. [[#352](https://github.com/draios/falco/pull/352)]
* When packaged as a container, start building kernel module with gcc 5.0 instead of gcc 4.9. [[#331](https://github.com/draios/falco/pull/331)]
* New example puppet module for falco. [[#341](https://github.com/draios/falco/pull/341)] [[#115](https://github.com/draios/falco/issues/115)]
* When signaled with `USR1`, falco will close/reopen log files. Include a [logrotate](https://github.com/logrotate/logrotate) example that shows how to use this feature for log rotation. [[#347](https://github.com/draios/falco/pull/347)] [[#266](https://github.com/draios/falco/issues/266)]
* To improve resource usage, further restrict the set of system calls available to falco [[#351](https://github.com/draios/falco/pull/351)] [[draios/sysdig#1105](https://github.com/draios/sysdig/pull/1105)]

## Minor Changes

* Add gdb to the development Docker image (sysdig/falco:dev) to aid in debugging. [[#323](https://github.com/draios/falco/pull/323)]
* You can now specify -V multiple times on the command line to validate multiple rules files at once. [[#329](https://github.com/draios/falco/pull/329)]
* When run with `-v`, falco will print *dangling* macros/lists that are not used by any rules. [[#329](https://github.com/draios/falco/pull/329)]
* Add an example demonstrating cryptomining attack that exploits an open docker daemon using host mounts. [[#336](https://github.com/draios/falco/pull/336)]
* New falco.yaml option `json_include_output_property` controls whether the formatted string "output" is included in the json object when json output is enabled. [[#342](https://github.com/draios/falco/pull/342)]
* Centralize testing event types for consideration by falco into a single function [[draios/sysdig#1105](https://github.com/draios/sysdig/pull/1105)) [[#356](https://github.com/draios/falco/pull/356)]
* If a rule has an attribute `warn_evttypes`, falco will not complain about `evt.type` restrictions on that rule [[#355](https://github.com/draios/falco/pull/355)]
* When run with `-i`, print all ignored events/syscalls and exit. [[#359](https://github.com/draios/falco/pull/359)]

## Bug Fixes

* Minor bug fixes to k8s daemonset configuration. [[#325](https://github.com/draios/falco/pull/325)] [[#296](https://github.com/draios/falco/pull/296)] [[#295](https://github.com/draios/falco/pull/295)]
* Ensure `--validate` can be used interchangeably with `-V`. [[#334](https://github.com/draios/falco/pull/334)] [[#322](https://github.com/draios/falco/issues/322)]
* Rule conditions like `fd.net` can now be used with the `in` operator e.g. `evt.type=connect and fd.net in ("127.0.0.1/24")`. [[draios/sysdig#1091](https://github.com/draios/sysdig/pull/1091)] [[#343](https://github.com/draios/falco/pull/343)]
* Ensure that `keep_alive` can be used both with file and program output at the same time. [[#335](https://github.com/draios/falco/pull/335)]
* Make it possible to append to a skipped macro/rule without falco complaining [[#346](https://github.com/draios/falco/pull/346)] [[#305](https://github.com/draios/falco/issues/305)]
* Ensure rule order is preserved even when rules do not contain any `evt.type` restriction. [[#354](https://github.com/draios/falco/issues/354)] [[#355](https://github.com/draios/falco/pull/355)]

## Rule Changes

* Make it easier to extend the `Change thread namespace` rule via a `user_known_change_thread_namespace_binaries` list. [[#324](https://github.com/draios/falco/pull/324)]
* Various FP fixes from users. [[#321](https://github.com/draios/falco/pull/321)] [[#326](https://github.com/draios/falco/pull/326)] [[#344](https://github.com/draios/falco/pull/344)] [[#350](https://github.com/draios/falco/pull/350)]
* New rule `Disallowed SSH Connection` detects attempts ssh connection attempts to hosts outside of an expected set. In order to be effective, you need to override the macro `allowed_ssh_hosts` in a user rules file. [[#321](https://github.com/draios/falco/pull/321)]
* New rule `Unexpected K8s NodePort Connection` detects attempts to contact the K8s NodePort range from a program running inside a container. In order to be effective, you need to override the macro `nodeport_containers` in a user rules file. [[#321](https://github.com/draios/falco/pull/321)]
* Improve `Modify binary dirs` rule to work with new syscalls [[#353](https://github.com/draios/falco/pull/353)]
* New rule `Unexpected UDP Traffic` checks for udp traffic not on a list of expected ports. Somewhat FP-prone, so it must be explicitly enabled by overriding the macro `do_unexpected_udp_check` in a user rules file. [[#320](https://github.com/draios/falco/pull/320)] [[#357](https://github.com/draios/falco/pull/357)]

## v0.9.0

Released 2018-01-18

### Bug Fixes

* Fix driver incompatibility problems with some linux kernel versions that can disable pagefault tracepoints [[#sysdig/1034](https://github.com/draios/sysdig/pull/1034)]
* Fix OSX Build incompatibility with latest version of libcurl [[#291](https://github.com/draios/falco/pull/291)]

### Minor Changes

* Updated the Kubernetes example to provide an additional example: Daemon Set using RBAC and a ConfigMap for configuration. Also expanded the documentation for both the RBAC and non-RBAC examples. [[#309](https://github.com/draios/falco/pull/309)]

### Rule Changes

* Refactor the shell-related rules to reduce false positives. These changes significantly decrease the scope of the rules so they trigger only for shells spawned below specific processes instead of anywhere. [[#301](https://github.com/draios/falco/pull/301)] [[#304](https://github.com/draios/falco/pull/304)]
* Lots of rule changes based on feedback from Sysdig Secure community [[#293](https://github.com/draios/falco/pull/293)] [[#298](https://github.com/draios/falco/pull/298)] [[#300](https://github.com/draios/falco/pull/300)] [[#307](https://github.com/draios/falco/pull/307)] [[#315](https://github.com/draios/falco/pull/315)]

## v0.8.1

Released 2017-10-10

### Bug Fixes

* Fix packaging to specify correct built-in config file [[#288](https://github.com/draios/falco/pull/288)]

## v0.8.0

Released 2017-10-10

**Important**: the location for falco's configuration file has moved from `/etc/falco.yaml` to `/etc/falco/falco.yaml`. The default rules file has moved from `/etc/falco_rules.yaml` to `/etc/falco/falco_rules.yaml`. In addition, 0.8.0 has added a _local_ ruls file to `/etc/falco/falco_rules.local.yaml`. See [the documentation](https://github.com/draios/falco/wiki/Falco-Default-and-Local-Rules-Files) for more details.

### Major Changes

* Add the ability to append one list to another list by setting an `append: true` attribute. [[#264](https://github.com/draios/falco/pull/264)]
* Add the ability to append one macro/rule to another list by setting an `append: true` attribute. [[#277](https://github.com/draios/falco/pull/277)]
* Ensure that falco rules/config files are preserved across package upgrades/removes if modified. [[#278](https://github.com/draios/falco/pull/278)]
* Add the notion of a "local" rules file that should contain modifications to the default falco rules file. [[#278](https://github.com/draios/falco/pull/278)]
* When using json output, separately include the individual templated fields in the json object. [[#282](https://github.com/draios/falco/pull/282)]
* Add the ability to keep a file/program pipe handle open across rule notifications. [[#283](https://github.com/draios/falco/pull/283)]
* New argument `-V` validates rules file and immediately exits. [[#286](https://github.com/draios/falco/pull/286)]

### Minor Changes

* Minor updates to falco example programs [[#248](https://github.com/draios/falco/pull/248)] [[#275](https://github.com/draios/falco/pull/275)]
* Also validate macros at rule parse time. [[#257](https://github.com/draios/falco/pull/257)]
* Minor README typo fixes [[#276](https://github.com/draios/falco/pull/276)]
* Add a government CLA (contributor license agreement). [[#263](https://github.com/draios/falco/pull/263)]
* Add ability to only run rules with a priority >= some threshold [[#281](https://github.com/draios/falco/pull/281)]
* Add ability to make output channels unbuffered [[#285](https://github.com/draios/falco/pull/285)]

### Bug Fixes

* Fix installation of falco on OSX [[#252](https://github.com/draios/falco/pull/252)]
* Fix a bug that caused the trailing whitespace of a quoted string to be accidentally removed [[#254](https://github.com/draios/falco/pull/254)]
* When multiple sets of kernel headers are installed, find the one for the running kernel [[#260](https://github.com/draios/falco/pull/260)]
* Allow pathnames in rule/macro conditions to contain '.' characters [[#262](https://github.com/draios/falco/pull/262)]
* Fix a bug where a list named "foo" would be substituted even if it were a substring of a longer word like "my_foo" [[#258](https://github.com/draios/falco/pull/258)]
* Remove extra trailing newlines from rule output strings [[#265](https://github.com/draios/falco/pull/265)]
* Improve build pathnames to avoid relative paths when possible [[#284](https://github.com/draios/falco/pull/284)]

### Rule Changes

* Significant changes to default ruleset to address FPs. These changes resulted from hundreds of hours of use in actual customer environments. [[#247](https://github.com/draios/falco/pull/247)] [[#259](https://github.com/draios/falco/pull/259)]
* Add official gitlab EE docker image to list of known shell spawning images. Thanks @dkerwin! [[#270](https://github.com/draios/falco/pull/270)]
* Add keepalived to list of shell spawning binaries. Thanks @dkerwin! [[#269](https://github.com/draios/falco/pull/269)]

## v0.7.0

Released 2017-05-30

### Major Changes

* Update the priorities of falco rules to use a wider range of priorities rather than just ERROR/WARNING. More info on the use of priorities in the ruleset can be found [here](https://github.com/draios/falco/wiki/Falco-Rules#rule-priorities). [[#244](https://github.com/draios/falco/pull/244)]

### Minor Changes

None.

### Bug Fixes

* Fix typos in various markdown files. Thanks @sublimino! [[#241](https://github.com/draios/falco/pull/241)]

### Rule Changes

* Add gitlab-mon as a gitlab binary, which allows it to run shells, etc. Thanks @dkerwin! [[#237](https://github.com/draios/falco/pull/237)]
* A new rule Terminal shell in container" that looks for shells spawned in a container with an attached terminal. [[#242](https://github.com/draios/falco/pull/242)]
* Fix some FPs related to the sysdig monitor agent. [[#243](https://github.com/draios/falco/pull/243)]
* Fix some FPs related to stating containers combined with missed events [[#243](https://github.com/draios/falco/pull/243)]

## v0.6.1

Released 2017-05-15

### Major Changes

None

### Minor Changes

* Small changes to token bucket used to throttle falco events [[#234](https://github.com/draios/falco/pull/234)] [[#235](https://github.com/draios/falco/pull/235)] [[#236](https://github.com/draios/falco/pull/236)] [[#238](https://github.com/draios/falco/pull/238)]

### Bug Fixes

* Update the falco driver to work with kernel 4.11 [[#829](https://github.com/draios/sysdig/pull/829)]

### Rule Changes

* Don't allow apache2 to spawn shells in containers [[#231](https://github.com/draios/falco/issues/231)] [[#232](https://github.com/draios/falco/pull/232)]

## v0.6.0

Released 2017-03-29

### Major Changes

* Add the notion of tagged falco rules. Full documentation for this feature is available on the [wiki](https://github.com/draios/falco/wiki/Falco-Rules#rule-tags). [[#58](https://github.com/draios/falco/issues/58)] [[#59](https://github.com/draios/falco/issues/59)] [[#60](https://github.com/draios/falco/issues/60)] [[#206](https://github.com/draios/falco/pull/206)]
* Falco now has its own dedicated kernel module. Previously, it would depend on sysdig being installed and would use sysdig's `sysdig-probe` kernel module. This ensures you can upgrade sysdig and falco without kernel driver compatibility problems. More details on the kernel module and its installation are on the [wiki](https://github.com/draios/falco/wiki/Falco-Kernel-Module). [[#215](https://github.com/draios/falco/issues/215)] [[#223](https://github.com/draios/falco/issues/223)] [[#224](https://github.com/draios/falco/pull/224)]
* When providing multiple rules files by specifying `-r' multiple times, make sure that you can override rules/lists/macros. Previously, a list/macro/rule specified in an earlier file could not be overridden in a later file. [[#176](https://github.com/draios/falco/issues/176)] [[#177](https://github.com/draios/falco/pull/177)]
* Add example k8s yaml files that show how to run falco as a k8s DaemonSet, and how to run falco-event-generator as a deployment running on one node. [[#222](https://github.com/draios/falco/pull/222)] [[#225](https://github.com/draios/falco/issues/225)] [[#226](https://github.com/draios/falco/pull/226)]
* Update third party libraries to address security vulnerabilities. [[#182](https://github.com/draios/falco/pull/182)]
* Falco can now be built on OSX. Like sysdig, on OSX it is limited to reading existing trace files. [[#210](https://github.com/draios/falco/pull/210)]

### Minor Changes
* Several changes to [falco-event-generator](https://github.com/draios/falco/wiki/Generating-Sample-Events) to improve usability. [[#205](https://github.com/draios/falco/pull/205)]
* Switch to a formatter cache provided by sysdig code instead of using our own. [[#212](https://github.com/draios/falco/pull/212)]
* Add automated tests that use locally-built docker images. [[#188](https://github.com/draios/falco/issues/188)]

### Bug Fixes

* Make sure output strings are not truncated when a given %field expression has a NULL value. [[#180](https://github.com/draios/falco/issues/180)] [[#181](https://github.com/draios/falco/pull/181)]
* Allow ASSERTs when running travisci tests. [[#199](https://github.com/draios/falco/pull/199)]
* Fix make dependencies for lyaml. [[#204](https://github.com/draios/falco/pull/204)] [[#130](https://github.com/draios/falco/issues/130)]
* (This was a change in sysdig, but affected falco). Prevent hangs when traversing malformed parent thread state. [[#208](https://github.com/draios/falco/issues/208)]

### Rule Changes

* Add confd as a program that can write files below /etc and fleetctl as a program that can spawn shells. [[#175](https://github.com/draios/falco/pull/175)]
* Add [exechealthz](https://github.com/kubernetes/contrib/tree/master/exec-healthz), a k8s liveness checking utility, to the list of shell spawners. [[#190](https://github.com/draios/falco/pull/190)]
* Eliminate FPs related to weekly ubuntu cron jobs. [[#192](https://github.com/draios/falco/pull/192)]
* Allow shells spawned by ansible, and eliminate FPs when managing machines via ansible. [[#193](https://github.com/draios/falco/pull/193)] [[#196](https://github.com/draios/falco/pull/196)] [[#202](https://github.com/draios/falco/pull/202)]
* Eliminate FPs related to use of other security products. Thanks to @juju4 for the useful rule updates. [[#200](https://github.com/draios/falco/pull/200)]
* Add additional possible locations for denyhosts, add [PM2](http://pm2.keymetrics.io/) as a shell spawner. [[#202](https://github.com/draios/falco/pull/202)]
* Add flanneld as a privileged container, improve grouping for the "x running y" macros, allow denyhosts to spawn shells. [[#207](https://github.com/draios/falco/pull/207)]
* Handle systemd changing its name to "(systemd)", add sv (part of [runit](http://smarden.org/runit/)) as a program that can write below /etc, allow writing to all `/dev/tty*` files. [[#209](https://github.com/draios/falco/pull/209)]
* Add erl_child_setup as a shell spawner. Thanks to @dkerwin for the useful rule updates. [[#218](https://github.com/draios/falco/pull/218)]  [[#221](https://github.com/draios/falco/pull/221)]
* Add support for gitlab omnibus containers/pods. Thanks to @dkerwin for the useful rule updates. [[#220](https://github.com/draios/falco/pull/220)]

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
