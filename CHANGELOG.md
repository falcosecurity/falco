# Change Log

This file documents all notable changes to Falco. The release numbering uses [semantic versioning](http://semver.org).

## v0.23.0

Released on 2020-18-05

### Major Changes

* BREAKING CHANGE: the falco-driver-loader script now references `falco-probe.o` and `falco-probe.ko` as `falco.o` and `falco.ko` [[#1158](https://github.com/falcosecurity/falco/pull/1158)]
* BREAKING CHANGE: the `falco-driver-loader` script environment variable to use a custom repository to download drivers now uses the `DRIVERS_REPO` environment variable instead of `DRIVER_LOOKUP_URL`. This variable must contain the parent URI containing the following directory structure `/$driver_version$/falco_$target$_$kernelrelease$_$kernelversion$.[ko|o]`. e.g: [[#1160](https://github.com/falcosecurity/falco/pull/1160)]
* new(scripts): options and command-line usage for `falco-driver-loader` [[#1200](https://github.com/falcosecurity/falco/pull/1200)]
* new: ability to specify exact matches when adding rules to Falco engine (only API) [[#1185](https://github.com/falcosecurity/falco/pull/1185)]
* new(docker): add an image that wraps the `falco-driver-loader` with the toolchain [[#1192](https://github.com/falcosecurity/falco/pull/1192)]
* new(docker): add `falcosecurity/falco-no-driver` image [[#1205](https://github.com/falcosecurity/falco/pull/1205)]


### Minor Changes

* update(scripts): improve `falco-driver-loader` output messages [[#1200](https://github.com/falcosecurity/falco/pull/1200)]
* update: containers look for prebuilt drivers on the Drivers Build Grid [[#1158](https://github.com/falcosecurity/falco/pull/1158)]
* update: driver version bump to 96bd9bc560f67742738eb7255aeb4d03046b8045 [[#1190](https://github.com/falcosecurity/falco/pull/1190)]
* update(docker): now `falcosecurity/falco:slim-*` alias to `falcosecurity/falco-no-driver:*` [[#1205](https://github.com/falcosecurity/falco/pull/1205)]
* docs: instructions to run unit tests [[#1199](https://github.com/falcosecurity/falco/pull/1199)]
* docs(examples): move `/examples` to `contrib` repo [[#1191](https://github.com/falcosecurity/falco/pull/1191)]
* update(docker): remove `minimal` image [[#1196](https://github.com/falcosecurity/falco/pull/1196)]
* update(integration): move `/integrations` to `contrib` repo [[#1157](https://github.com/falcosecurity/falco/pull/1157)]
* https://dl.bintray.com/driver/$driver_version$/falco_$target$_$kernelrelease$_$kernelversion$.[ko|o]` [[#1160](https://github.com/falcosecurity/falco/pull/1160)]
* update(docker/event-generator): remove the event-generator from Falco repository [[#1156](https://github.com/falcosecurity/falco/pull/1156)]
* docs(examples): set audit level to metadata for object secrets [[#1153](https://github.com/falcosecurity/falco/pull/1153)]


### Bug Fixes

* fix(scripts): upstream files (prebuilt drivers) for the generic Ubuntu kernel contains "ubuntu-generic" [[#1212](https://github.com/falcosecurity/falco/pull/1212)]
* fix: support Falco driver on Linux kernels 5.6.y [[#1174](https://github.com/falcosecurity/falco/pull/1174)]


### Rule Changes

* rule(Redirect STDOUT/STDIN to Network Connection in Container): correct rule name as per rules naming convention [[#1164](https://github.com/falcosecurity/falco/pull/1164)]
* rule(Redirect STDOUT/STDIN to Network Connection in Container): new rule to detect Redirect stdout/stdin to network connection in container [[#1152](https://github.com/falcosecurity/falco/pull/1152)]
* rule(K8s Secret Created): new rule to track the creation of Kubernetes secrets (excluding kube-system and service account secrets) [[#1151](https://github.com/falcosecurity/falco/pull/1151)]
* rule(K8s Secret Deleted): new rule to track the deletion of Kubernetes secrets (excluding kube-system and service account secrets) [[#1151](https://github.com/falcosecurity/falco/pull/1151)]

## v0.22.1

Released on 2020-17-04

### Major Changes

* Same as v0.22.0

### Minor Changes

* Same as v0.22.0

### Bug Fixes

* fix: correct driver path (/usr/src/falco-%driver_version%) for RPM package [[#1148](https://github.com/falcosecurity/falco/pull/1148)]

### Rule Changes

* Same as v0.22.0

## v0.22.0

Released on 2020-16-04

### Major Changes

* new: falco version and driver version are distinct and not coupled anymore [[#1111](https://github.com/falcosecurity/falco/pull/1111)]
* new: flag to disable asynchronous container metadata (CRI) fetch `--disable-cri-async` [[#1099](https://github.com/falcosecurity/falco/pull/1099)]


### Minor Changes

* docs(integrations): update API resource versions to Kubernetes 1.16 [[#1044](https://github.com/falcosecurity/falco/pull/1044)]
* docs: add new release archive to the `README.md` [[#1098](https://github.com/falcosecurity/falco/pull/1098)]
* update: driver version a259b4bf49c3 [[#1138](https://github.com/falcosecurity/falco/pull/1138)]
* docs(integrations/k8s-using-daemonset): --cri flag correct socket path [[#1140](https://github.com/falcosecurity/falco/pull/1140)]
* update: bump driver version to cd3d10123e [[#1131](https://github.com/falcosecurity/falco/pull/1131)]
* update(docker): remove RHEL, kernel/linuxkit, and kernel/probeloader images [[#1124](https://github.com/falcosecurity/falco/pull/1124)]
* update: falco-probe-loader script is falco-driver-loader now [[#1111](https://github.com/falcosecurity/falco/pull/1111)]
* update: using only sha256 hashes when pulling build dependencies [[#1118](https://github.com/falcosecurity/falco/pull/1118)]


### Bug Fixes

* fix(integrations/k8s-using-daemonset): added missing privileges for the apps Kubernetes API group in the falco-cluster-role when using RBAC [[#1136](https://github.com/falcosecurity/falco/pull/1136)]
* fix: connect to docker works also with libcurl >= 7.69.0 [[#1138](https://github.com/falcosecurity/falco/pull/1138)]
* fix: HOST_ROOT environment variable detection [[#1133](https://github.com/falcosecurity/falco/pull/1133)]
* fix(driver/bpf): stricter conditionals while dealing with strings [[#1131](https://github.com/falcosecurity/falco/pull/1131)]
* fix: `/usr/bin/falco-${DRIVER_VERSION}` driver directory [[#1111](https://github.com/falcosecurity/falco/pull/1111)]
* fix: FALCO_VERSION env variable inside Falco containers contains the Falco version now (not the docker image tag) [[#1111](https://github.com/falcosecurity/falco/pull/1111)]


### Rule Changes

* rule(macro user_expected_system_procs_network_activity_conditions): allow whitelisting system binaries using the network under specific conditions [[#1070](https://github.com/falcosecurity/falco/pull/1070)]
* rule(Full K8s Administrative Access): detect any k8s operation by an administrator with full access [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Ingress Object without TLS Certificate Created): detect any attempt to create an ingress without TLS certification (rule enabled by default) [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Untrusted Node Successfully Joined the Cluster): detect a node successfully joined the cluster outside of the list of allowed nodes [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Untrusted Node Unsuccessfully Tried to Join the Cluster): detect an unsuccessful attempt to join the cluster for a node not in the list of allowed nodes [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Network Connection outside Local Subnet): detect traffic to image outside local subnet [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Outbound or Inbound Traffic not to Authorized Server Process and Port): detect traffic that is not to authorized server process and port [[#1122](https://github.com/falcosecurity/falco/pull/1122)]
* rule(Delete or rename shell history): "mitre_defense_evation" tag corrected to "mitre_defense_evasion" [[#1143](https://github.com/falcosecurity/falco/pull/1143)]
* rule(Delete Bash History): "mitre_defense_evation" tag corrected to "mitre_defense_evasion" [[#1143](https://github.com/falcosecurity/falco/pull/1143)]
* rule(Write below root): use pmatch to check against known root directories [[#1137](https://github.com/falcosecurity/falco/pull/1137)]
* rule(Detect outbound connections to common miner pool ports): whitelist sysdig/agent and falcosecurity/falco for query miner domain dns [[#1115](https://github.com/falcosecurity/falco/pull/1115)]
* rule(Service Account Created in Kube Namespace): only detect sa created in kube namespace with success [[#1117](https://github.com/falcosecurity/falco/pull/1117)]

## v0.21.0

Released on 2020-03-17

### Major Changes

* BREAKING CHANGE: the SYSDIG_BPF_PROBE environment variable is now just FALCO_BPF_PROBE (please update your systemd scripts or kubernetes deployments. [[#1050](https://github.com/falcosecurity/falco/pull/1050)]
* new: automatically publish deb packages (from git master branch) to public dev repository [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: automatically publish rpm packages (from git master branch) to public dev repository [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: automatically release deb packages (from git tags) to public repository [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: automatically release rpm packages (from git tags) to public repository [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: automatically publish docker images from master (master, master-slim, master-minimal) [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: automatically publish docker images from git tag (tag, tag-slim, tag-master, latest, latest-slim, latest-minimal) [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* new: sign packages with falcosecurity gpg key [[#1059](https://github.com/falcosecurity/falco/pull/1059)]

### Minor Changes

* new: falco_version_prerelease contains the number of commits since last tag on the master [[#1086](https://github.com/falcosecurity/falco/pull/1086)]
* docs: update branding [[#1074](https://github.com/falcosecurity/falco/pull/1074)]
* new(docker/event-generator): add example k8s resource files that allow running the event generator in a k8s cluster. [[#1088](https://github.com/falcosecurity/falco/pull/1088)]
* update: creating *-dev docker images using build arguments at build time [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* update: docker images use packages from the new repositories [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* update: docker image downloads old deb dependencies (gcc-6, gcc-5, binutils-2.30) from a new open repository [[#1059](https://github.com/falcosecurity/falco/pull/1059)]

### Bug Fixes

* fix(docker): updating `stable` and `local` images to run from `debian:stable` [[#1018](https://github.com/falcosecurity/falco/pull/1018)]
* fix(event-generator): the image used by the event generator deployment to `latest`. [[#1091](https://github.com/falcosecurity/falco/pull/1091)]
* fix: -t (to disable rules by certain tag) or -t (to only run rules with a certain tag) work now [[#1081](https://github.com/falcosecurity/falco/pull/1081)]
* fix: the falco driver now compiles on >= 5.4 kernels [[#1080](https://github.com/falcosecurity/falco/pull/1080)]
* fix: download falco packages which url contains character to encode - eg, `+` [[#1059](https://github.com/falcosecurity/falco/pull/1059)]
* fix(docker): use base name in docker-entrypoint.sh [[#981](https://github.com/falcosecurity/falco/pull/981)]

### Rule Changes

* rule(detect outbound connections to common miner pool ports): disabled by default [[#1061](https://github.com/falcosecurity/falco/pull/1061)]
* rule(macro net_miner_pool): add localhost and rfc1918 addresses as exception in the rule. [[#1061](https://github.com/falcosecurity/falco/pull/1061)]
* rule(change thread namespace): modify condition to detect suspicious container activity [[#974](https://github.com/falcosecurity/falco/pull/974)]

## v0.20.0

Released on 2020-02-24

### Major Changes

* fix: memory leak introduced in 0.18.0 happening while using json events and the kubernetes audit endpoint [[#1041](https://github.com/falcosecurity/falco/pull/1041)]
* new: grpc version api [[#872](https://github.com/falcosecurity/falco/pull/872)]


### Bug Fixes

* fix: the base64 output format (-b) now works with both json and normal output. [[#1033](https://github.com/falcosecurity/falco/pull/1033)]
* fix: version follows semver 2 bnf [[#872](https://github.com/falcosecurity/falco/pull/872)]

### Rule Changes

* rule(write below etc): add "dsc_host" as a ms oms program [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(write below etc): let mcafee write to /etc/cma.d  [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(write below etc): let avinetworks supervisor write some ssh cfg [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(write below etc): alow writes to /etc/pki from openshift secrets dir [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(write below root): let runc write to /exec.fifo [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(change thread namespace): let cilium-cni change namespaces [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
* rule(run shell untrusted): let puma reactor spawn shells [[#1028](https://github.com/falcosecurity/falco/pull/1028)]


## v0.19.0

Released on 2020-01-23

### Major Changes

* new: security audit [[#977](https://github.com/falcosecurity/falco/pull/977)]
* instead of crashing, now falco will report the error when an internal error occurs while handling an event to be inspected. the log line will be of type error and will contain the string `error handling inspector event` [[#746](https://github.com/falcosecurity/falco/pull/746)]
* build: bump grpc to 1.25.0 [[#939](https://github.com/falcosecurity/falco/pull/939)]
* build: (most of) dependencies are bundled dynamically (by default) [[#968](https://github.com/falcosecurity/falco/pull/968)]
* test: integration tests now can run on different distributions via docker containers, for now CentOS 7 and Ubuntu 18.04 with respective rpm and deb packages [[#1012](https://github.com/falcosecurity/falco/pull/1012)]

### Minor Changes

* proposal: rules naming convention [[#980](https://github.com/falcosecurity/falco/pull/980)]
* update: also allow posting json arrays containing k8s audit events to the k8s_audit endpoint. [[#967](https://github.com/falcosecurity/falco/pull/967)]
* update: add support for k8s audit events to the falco-event-generator container. [[#997](https://github.com/falcosecurity/falco/pull/997)]
* update: falco-tester base image is fedora:31 now [[#968](https://github.com/falcosecurity/falco/pull/968)]
* build: switch to circleci [[#968](https://github.com/falcosecurity/falco/pull/968)]
* build: bundle openssl into falco-builder docker image [[#1004](https://github.com/falcosecurity/falco/pull/1004)]
* build: falco-builder docker image revamp (centos:7 base image) [[#1004](https://github.com/falcosecurity/falco/pull/1004)]
* update: puppet module had been renamed from "sysdig-falco" to "falco" [[#922](https://github.com/falcosecurity/falco/pull/922)]
* update: adds a hostname field to grpc output [[#927](https://github.com/falcosecurity/falco/pull/927)]
* build: download grpc from their github repo [[#933](https://github.com/falcosecurity/falco/pull/933)]
* update: ef_drop_falco is now ef_drop_simple_cons [[#922](https://github.com/falcosecurity/falco/pull/922)]
* update(docker): use host_root environment variable rather than sysdig_host_root [[#922](https://github.com/falcosecurity/falco/pull/922)]
* update: ef_drop_falco is now ef_drop_simple_cons [[#922](https://github.com/falcosecurity/falco/pull/922)]

### Bug Fixes

* fix: providing clang into docker-builder [[#972](https://github.com/falcosecurity/falco/pull/972)]
* fix: prevent throwing json type error c++ exceptions outside of the falco engine when procesing k8s audit events. [[#928](https://github.com/falcosecurity/falco/pull/928)]
* fix(docker/kernel/linuxkit): correct from for falco minimal image [[#913](https://github.com/falcosecurity/falco/pull/913)]

### Rule Changes

* rules(list network_tool_binaries): add some network tools to detect suspicious network activity. [[#973](https://github.com/falcosecurity/falco/pull/973)]
* rules(write below etc): allow automount to write to /etc/mtab [[#957](https://github.com/falcosecurity/falco/pull/957)]
* rules(macro user_known_k8s_client_container): when executing the docker client, exclude fluentd-gcp-scaler container running in the `kube-system` namespace to avoid false positives [[#962](https://github.com/falcosecurity/falco/pull/962)]
* rules(the docker client is executed in a container): detect the execution of the docker client in a container and logs it with warning priority.  [[#915](https://github.com/falcosecurity/falco/pull/915)]
* rules(list k8s_client_binaries): create and add docker, kubectl, crictl [[#915](https://github.com/falcosecurity/falco/pull/915)]
* rules(macro container_entrypoint): add docker-runc-cur  [[#914](https://github.com/falcosecurity/falco/pull/914)]
* rules(list user_known_chmod_applications): add hyperkube [[#914](https://github.com/falcosecurity/falco/pull/914)]
* rules(list network_tool_binaries): add some network tools to detect suspicious network activity. [[#975](https://github.com/falcosecurity/falco/pull/975)]
* rules(macro user_known_k8s_client_container): macro to match kube-system namespace [[#955](https://github.com/falcosecurity/falco/pull/955)]
* rules(contact k8s api server from container): now it can automatically resolve the cluster ip address  [[#952](https://github.com/falcosecurity/falco/pull/952)]
* rules(macro k8s_api_server): new macro to match the default k8s api server [[#952](https://github.com/falcosecurity/falco/pull/952)]
* rules(macro sensitive_vol_mount): add more sensitive host paths [[#929](https://github.com/falcosecurity/falco/pull/929)]
* rules(macro sensitive_mount): add more sensitive paths [[#929](https://github.com/falcosecurity/falco/pull/929)]
* rules(macro consider_metadata_access): macro to decide whether to consider metadata or not (off by default) [[#943](https://github.com/falcosecurity/falco/pull/943)]
* rules(contact cloud metadata service from container): add rules to detect access to gce instance metadata [[#943](https://github.com/falcosecurity/falco/pull/943)]
* rules(macro sensitive_vol_mount): align sensitive mounts macro between k8s audit rules and syscall rules [[#950](https://github.com/falcosecurity/falco/pull/950)]
* rules(macro consider_packet_socket_communication): macro to consider or not packet socket communication (off by default) [[#945](https://github.com/falcosecurity/falco/pull/945)]
* rules(packet socket created in container): rule to detect raw packets creation [[#945](https://github.com/falcosecurity/falco/pull/945)]
* rules(macro exe_running_docker_save): fixed false positives in multiple rules that were caused by the use of docker in docker [[#951](https://github.com/falcosecurity/falco/pull/951)]
* rules(modify shell configuration file): fixed a false positive by excluding "exe_running_docker_save" [[#949](https://github.com/falcosecurity/falco/pull/949)]
* rules(update package repository): fixed a false positive by excluding "exe_running_docker_save". [[#948](https://github.com/falcosecurity/falco/pull/948)]
* rules(the docker client is executed in a container): when executing the docker client, exclude containers running in the `kube-system` namespace to avoid false positives [[#955](https://github.com/falcosecurity/falco/pull/955)]
* rules(list user_known_chmod_applications): add kubelet [[#944](https://github.com/falcosecurity/falco/pull/944)]
* rules(set setuid or setgid bit): fixed a false positive by excluding "exe_running_docker_save" [[#946](https://github.com/falcosecurity/falco/pull/946)]
* rules(macro user_known_package_manager_in_container): allow users to specify conditions that match a legitimate use case for using a package management process in a container. [[#941](https://github.com/falcosecurity/falco/pull/941)]

## v0.18.0

Released 2019-10-28

### Major Changes

* falco grpc api server implementation, contains a subscribe method to subscribe to outputs from any grpc capable language [[#822](https://github.com/falcosecurity/falco/pull/822)]
* add support for converting k8s pod security policies (psps) into set of falco rules that can be used to evaluate the conditions specified in the psp. [[#826](https://github.com/falcosecurity/falco/pull/826)]
* initial redesign container images to remove build tools and leverage init containers for kernel module delivery. [[#776](https://github.com/falcosecurity/falco/pull/776)]
* add flags to disable `syscall` event source or `k8s_audit` event source [[#779](https://github.com/falcosecurity/falco/pull/779)]

### Minor Changes

* allow for unique names for psp converted rules/macros/lists/rule names as generated by falcoctl 0.0.3 [[#895](https://github.com/falcosecurity/falco/pull/895)]
* make it easier to run regression tests without necessarily using the falco-tester docker image. [[#808](https://github.com/falcosecurity/falco/pull/808)]
* fix falco engine compatibility with older k8s audit rules files. [[#893](https://github.com/falcosecurity/falco/pull/893)]
* add tests for psp conversions with names containing spaces/dashes. [[#899](https://github.com/falcosecurity/falco/pull/899)]

### Bug Fixes

* handle multi-document yaml files when reading rules files. [[#760](https://github.com/falcosecurity/falco/pull/760)]
* improvements to how the webserver handles incoming invalid inputs [[#759](https://github.com/falcosecurity/falco/pull/759)]
* fix: make lua state access thread-safe [[#867](https://github.com/falcosecurity/falco/pull/867)]
* fix compilation on gcc 5.4 by working around gcc bug https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480 [[#873](https://github.com/falcosecurity/falco/pull/873)]
* add explicit dependency between tests and catch2 header file. [[#879](https://github.com/falcosecurity/falco/pull/879)]
* fix: stable dockerfile libgcc-6-dev dependencies [[#830](https://github.com/falcosecurity/falco/pull/830)]
* fix: build dependencies for the local dockerfile [[#782](https://github.com/falcosecurity/falco/pull/782)]
* fix: a crash bug that could result from reading more than ~6 rules files [[#906](https://github.com/falcosecurity/falco/issues/906)] [[#907](https://github.com/falcosecurity/falco/pull/907)]

### Rule Changes

* rules: add calico/node to trusted privileged container list [[#902](https://github.com/falcosecurity/falco/pull/902)]
* rules: add macro `calico_node_write_envvars` to exception list of write below etc [[#902](https://github.com/falcosecurity/falco/pull/902)]
* rules: add exception for rule write below rpm, this is a fp caused by amazon linux 2 yum. [[#755](https://github.com/falcosecurity/falco/pull/755)]
* rules: ignore sensitive mounts from the ecs-agent [[#881](https://github.com/falcosecurity/falco/pull/881)]
* rules: add rules to detect crypto mining activities [[#763](https://github.com/falcosecurity/falco/pull/763)]
* rules: add back rule delete bash history for backport compatibility [[#864](https://github.com/falcosecurity/falco/pull/864)]
* rule: syscalls are used to detect suid and sgid [[#765](https://github.com/falcosecurity/falco/pull/765)]
* rules: delete bash history is renamed to delete or rename shell history [[#762](https://github.com/falcosecurity/falco/pull/762)]
* rules: add image fluent/fluentd-kubernetes-daemonset to clear log trusted images [[#852](https://github.com/falcosecurity/falco/pull/852)]
* rules: include default users created by `kops`. [[#898](https://github.com/falcosecurity/falco/pull/898)]
* rules: delete or rename shell history: when deleting a shell history file now the syscalls are taken into account rather than just the commands deleting the files [[#762](https://github.com/falcosecurity/falco/pull/762)]
* rules: delete or rename shell history: history deletion now supports fish and zsh in addition to bash [[#762](https://github.com/falcosecurity/falco/pull/762)]
* rules: "create hidden files or directories" and "update package repository" now trigger also if the files are moved and not just if modified or created. [[#766](https://github.com/falcosecurity/falco/pull/766)]

## v0.17.1

Released 2019-09-26

### Major Changes

* Same as v0.17.0

### Minor Changes

* Same as v0.17.0

### Bug Fixes

* All in v0.17.0
* Fix a build problem for pre-built kernel probes. [[draios/sysdig#1471](https://github.com/draios/sysdig/pull/1471)]

### Rule Changes

* Same as v0.17.0

## v0.17.0

Released 2019-07-31

### Major Changes

* **The set of supported platforms has changed**. Switch to a reorganized builder image that uses Centos 7 as a base. As a result, falco is no longer supported on Centos 6. The other supported platforms should remain the same [[#719](https://github.com/falcosecurity/falco/pull/719)]

### Minor Changes

* When enabling rules within the falco engine, use rule substrings instead of regexes. [[#743](https://github.com/falcosecurity/falco/pull/743)]

* Additional improvements to the handling and display of rules validation errors [[#744](https://github.com/falcosecurity/falco/pull/744)] [[#747](https://github.com/falcosecurity/falco/pull/747)]

### Bug Fixes

* Fix a problem that would cause prevent container metadata lookups when falco was daemonized [[#731](https://github.com/falcosecurity/falco/pull/731)]

* Allow rule priorites to be expressed as lowercase and a mix of lower/uppercase [[#737](https://github.com/falcosecurity/falco/pull/737)]

### Rule Changes

* Fix a parentheses bug with the `shell_procs` macro [[#728](https://github.com/falcosecurity/falco/pull/728)]

* Allow additional containers to mount sensitive host paths [[#733](https://github.com/falcosecurity/falco/pull/733)] [[#736](https://github.com/falcosecurity/falco/pull/736)]

* Allow additional containers to truncate log files [[#733](https://github.com/falcosecurity/falco/pull/733)]

* Fix false positives with the `Write below root` rule on GKE [[#739](https://github.com/falcosecurity/falco/pull/739)]

## v0.16.0

Released 2019-07-12

### Major Changes

* Clean up error reporting to provide more meaningful error messages along with context when loading rules files. When run with -V, the results of the validation ("OK" or error message) are sent to standard output. [[#708](https://github.com/falcosecurity/falco/pull/708)]

* Improve rule loading performance by optimizing lua parsing paths to avoid expensive pattern matches. [[#694](https://github.com/falcosecurity/falco/pull/694)]

* Bump falco engine version to 4 to reflect new fields `ka.useragent`, others. [[#710](https://github.com/falcosecurity/falco/pull/710)] [[#681](https://github.com/falcosecurity/falco/pull/681)]

* Add Catch2 as a unit testing framework. This will add additional coverage on top of the regression tests using Avocado. [[#687](https://github.com/falcosecurity/falco/pull/687)]

### Minor Changes

* Add SYSDIG_DIR Cmake option to specify location for sysdig source code when building falco. [[#677](https://github.com/falcosecurity/falco/pull/677)] [[#679](https://github.com/falcosecurity/falco/pull/679)] [[#702](https://github.com/falcosecurity/falco/pull/702)]

* New field `ka.useragent` reports the useragent from k8s audit events. [[#709](https://github.com/falcosecurity/falco/pull/709)]

* Add clang formatter for C++ syntax formatting. [[#701](https://github.com/falcosecurity/falco/pull/701)] [[#689](https://github.com/falcosecurity/falco/pull/689)]

* Partial changes towards lua syntax formatting. No particular formatting enforced yet, though. [[#718](https://github.com/falcosecurity/falco/pull/718)]

* Partial changes towards yaml syntax formatting. No particular formatting enforced yet, though. [[#714](https://github.com/falcosecurity/falco/pull/714)]

* Add cmake syntax formatting. [[#703](https://github.com/falcosecurity/falco/pull/703)]

* Token bucket unit tests and redesign. [[#692](https://github.com/falcosecurity/falco/pull/692)]

* Update github PR template. [[#699](https://github.com/falcosecurity/falco/pull/699)]

* Fix PR template for kind/rule-*. [[#697](https://github.com/falcosecurity/falco/pull/697)]

### Bug Fixes

* Remove an unused cmake file. [[#700](https://github.com/falcosecurity/falco/pull/700)]

* Misc Cmake cleanups. [[#673](https://github.com/falcosecurity/falco/pull/673)]

* Misc k8s install docs improvements. [[#671](https://github.com/falcosecurity/falco/pull/671)]

### Rule Changes

* Allow k8s.gcr.io/kube-proxy image to run privileged. [[#717](https://github.com/falcosecurity/falco/pull/717)]

* Add runc to the list of possible container entrypoint parents. [[#712](https://github.com/falcosecurity/falco/pull/712)]

* Skip Source RFC 1918 addresses when considering outbound connections. [[#685](https://github.com/falcosecurity/falco/pull/685)]

* Add additional `user_XXX` placeholder macros to allow for easy customization of rule exceptions. [[#685](https://github.com/falcosecurity/falco/pull/685)]

* Let weaveworks programs change namespaces. [[#685](https://github.com/falcosecurity/falco/pull/685)]

* Add additional openshift images. [[#685](https://github.com/falcosecurity/falco/pull/685)]

* Add openshift as a k8s binary. [[#678](https://github.com/falcosecurity/falco/pull/678)]

* Add dzdo as a binary that can change users. [[#678](https://github.com/falcosecurity/falco/pull/678)]

* Allow azure/calico binaries to change namespaces. [[#678](https://github.com/falcosecurity/falco/pull/678)]

* Add back trusted_containers list for backport compatibility [[#675](https://github.com/falcosecurity/falco/pull/675)]

* Add mkdirat as a syscall for mkdir operations. [[#667](https://github.com/falcosecurity/falco/pull/667)]

* Add container id/repository to rules that can work with containers. [[#667](https://github.com/falcosecurity/falco/pull/667)]

## v0.15.3

Released 2019-06-12

### Major Changes

* None.

### Minor Changes

* None.

### Bug Fixes

* Fix kernel module compilation for kernels < 3.11 [[#sysdig/1436](https://github.com/draios/sysdig/pull/1436)]

### Rule Changes

* None.

## v0.15.2

Released 2019-06-12

### Major Changes

* New documentation and process handling around issues and pull requests. [[#644](https://github.com/falcosecurity/falco/pull/644)] [[#659](https://github.com/falcosecurity/falco/pull/659)] [[#664](https://github.com/falcosecurity/falco/pull/664)] [[#665](https://github.com/falcosecurity/falco/pull/665)]

### Minor Changes

* None.

### Bug Fixes

* Fix compilation of eBPF programs on COS (used by GKE) [[#sysdig/1431](https://github.com/draios/sysdig/pull/1431)]

### Rule Changes

* Rework exceptions lists for `Create Privileged Pod`, `Create Sensitive Mount Pod`, `Launch Sensitive Mount Container`, `Launch Privileged Container` rules to use separate specific lists rather than a single "Trusted Containers" list. [[#651](https://github.com/falcosecurity/falco/pull/651)]

## v0.15.1

Released 2019-06-07

### Major Changes

* Drop unnecessary events at the kernel level instead of userspace, which should improve performance [[#635](https://github.com/falcosecurity/falco/pull/635)]

### Minor Changes

* Add instructions for k8s audit support in >= 1.13 [[#608](https://github.com/falcosecurity/falco/pull/608)]

* Fix security issues reported by GitHub on Anchore integration [[#592](https://github.com/falcosecurity/falco/pull/592)]

* Several docs/readme improvements [[#620](https://github.com/falcosecurity/falco/pull/620)] [[#616](https://github.com/falcosecurity/falco/pull/616)] [[#631](https://github.com/falcosecurity/falco/pull/631)] [[#639](https://github.com/falcosecurity/falco/pull/639)] [[#642](https://github.com/falcosecurity/falco/pull/642)]

* Better tracking of rule counts per ruleset [[#645](https://github.com/falcosecurity/falco/pull/645)]

### Bug Fixes

* Handle rule patterns that are invalid regexes [[#636](https://github.com/falcosecurity/falco/pull/636)]

* Fix kernel module builds on newer kernels [[#646](https://github.com/falcosecurity/falco/pull/646)] [[#sysdig/1413](https://github.com/draios/sysdig/pull/1413)]

### Rule Changes

* New rule `Launch Remote File Copy Tools in Container` could be used to identify exfiltration attacks [[#600](https://github.com/falcosecurity/falco/pull/600)]

* New rule `Create Symlink Over Sensitive Files` can help detect attacks like [[CVE-2018-15664](https://nvd.nist.gov/vuln/detail/CVE-2018-15664)] [[#613](https://github.com/falcosecurity/falco/pull/613)] [[#637](https://github.com/falcosecurity/falco/pull/637)]

* Let etcd-manager write to /etc/hosts. [[#613](https://github.com/falcosecurity/falco/pull/613)]

* Let additional processes spawned by google-accounts-daemon access sensitive files [[#593](https://github.com/falcosecurity/falco/pull/593)]

* Add Sematext Monitoring & Logging agents to trusted k8s containers [[#594](https://github.com/falcosecurity/falco/pull/594/)]

* Add additional coverage for `Netcat Remote Code Execution in Container` rule. [[#617](https://github.com/falcosecurity/falco/pull/617/)]

* Fix `egrep` typo. [[#617](https://github.com/falcosecurity/falco/pull/617/)]

* Allow Ansible to run using Python 3 [[#625](https://github.com/falcosecurity/falco/pull/625/)]

* Additional `Write below etc` exceptions for nginx, rancher [[#637](https://github.com/falcosecurity/falco/pull/637)] [[#648](https://github.com/falcosecurity/falco/pull/648)] [[#652](https://github.com/falcosecurity/falco/pull/652)]

* Add rules for running with IBM Cloud Kubernetes Service [[#634](https://github.com/falcosecurity/falco/pull/634)]

## v0.15.0

Released 2019-05-13

### Major Changes

* **Actions and alerts for dropped events**: Falco can now take actions, including sending alerts/logging messages, and/or even exiting Falco, when it detects dropped system call events. Fixes CVE 2019-8339. [[#561](https://github.com/falcosecurity/falco/pull/561)] [[#571](https://github.com/falcosecurity/falco/pull/571)]

* **Support for Containerd/CRI-O**: Falco now supports containerd/cri-o containers. [[#585](https://github.com/falcosecurity/falco/pull/585)] [[#591](https://github.com/falcosecurity/falco/pull/591)] [[#599](https://github.com/falcosecurity/falco/pull/599)] [[#sysdig/1376](https://github.com/draios/sysdig/pull/1376)] [[#sysdig/1310](https://github.com/draios/sysdig/pull/1310)] [[#sysdig/1399](https://github.com/draios/sysdig/pull/1399)]

* **Perform docker metadata fetches asynchronously**: When new containers are discovered, fetch metadata about the container asynchronously, which should significantly reduce the likelihood of dropped system call events. [[#sysdig/1326](https://github.com/draios/sysdig/pull/1326)] [[#550](https://github.com/falcosecurity/falco/pull/550)] [[#570](https://github.com/falcosecurity/falco/pull/570)]

* Better syscall event performance: improve algorithm for reading system call events from kernel module to handle busy event streams [[#sysdig/1372](https://github.com/draios/sysdig/pull/1372)]

* HTTP Output: Falco can now send alerts to http endpoints directly without having to use curl. [[#523](https://github.com/falcosecurity/falco/pull/523)]

* Move Kubernetes Response Engine to own repo: The Kubernetes Response Engine is now in its [own github repository](https://github.com/falcosecurity/kubernetes-response-engine). [[#539](https://github.com/falcosecurity/falco/pull/539)]

* Updated Puppet Module: An all-new puppet module compatible with puppet 4 with a smoother installation process and updated package links. [[#537](https://github.com/falcosecurity/falco/pull/537)] [[#543](https://github.com/falcosecurity/falco/pull/543)] [[#546](https://github.com/falcosecurity/falco/pull/546)]

* RHEL-based falco image: Provide dockerfiles that use RHEL 7 as the base image instead of debian:unstable. [[#544](https://github.com/falcosecurity/falco/pull/544)]


### Minor Changes

* ISO-8601 Timestamps: Add the ability to write timestamps in ISO-8601 w/ UTC, and use this format by default when running falco in a container [[#518](https://github.com/falcosecurity/falco/pull/518)]

* Docker-based builder/tester: You can now build Falco using the [falco-builder](https://falco.org/docs/source/#build-using-falco-builder-container) docker image, and run regression tests using the [falco-tester](https://falco.org/docs/source/#test-using-falco-tester-container) docker image. [[#522](https://github.com/falcosecurity/falco/pull/522)] [[#584](https://github.com/falcosecurity/falco/pull/584)]

* Several small docs changes to improve clarity and readibility [[#524](https://github.com/falcosecurity/falco/pull/524)] [[#540](https://github.com/falcosecurity/falco/pull/540)] [[#541](https://github.com/falcosecurity/falco/pull/541)] [[#542](https://github.com/falcosecurity/falco/pull/542)]

* Add instructions on how to enable K8s Audit Logging for kops [[#535](https://github.com/falcosecurity/falco/pull/535)]

* Add a "stale issue" bot that marks and eventually closes old issues with no activity [[#548](https://github.com/falcosecurity/falco/pull/548)]

* Improvements to sample K8s daemonset/service/etc files [[#562](https://github.com/falcosecurity/falco/pull/562)]

### Bug Fixes

* Fix regression that broke json output [[#581](https://github.com/falcosecurity/falco/pull/581)]

* Fix errors when building via docker from MacOS [[#582](https://github.com/falcosecurity/falco/pull/582)]

### Rule Changes

* **Tag rules using Mitre Attack Framework**: Add tags for all relevant rules linking them to the [MITRE Attack Framework](https://attack.mitre.org). We have an associated [blog post](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/). [[#575](https://github.com/falcosecurity/falco/pull/575)] [[#578](https://github.com/falcosecurity/falco/pull/578)]

* New rules for additional use cases: New rules `Schedule Cron Jobs`, `Update Package Repository`, `Remove Bulk Data from Disk`, `Set Setuid or Setgid bit`, `Detect bash history deletion`, `Create Hidden Files or Directories` look for additional common follow-on activity you might see from an attacker. [[#578](https://github.com/falcosecurity/falco/pull/578)] [[#580](https://github.com/falcosecurity/falco/pull/580)]

* Allow docker's "exe" (usually part of docker save/load) to write to many filesystem locations [[#552](https://github.com/falcosecurity/falco/pull/552)]

* Let puppet write below /etc [[#563](https://github.com/falcosecurity/falco/pull/563)

* Add new `user_known_write_root_conditions`, `user_known_non_sudo_setuid_conditions`, and `user_known_write_monitored_dir_conditions` macros to allow those rules to be easily customized in user rules files [[#563](https://github.com/falcosecurity/falco/pull/563)] [[#566](https://github.com/falcosecurity/falco/pull/566)]

* Better coverage and exceptions for rancher [[#559](https://github.com/falcosecurity/falco/pull/559)]

* Allow prometheus to write to its conf directory under etc [[#564](https://github.com/falcosecurity/falco/pull/564)]

* Better coverage and exceptions for openshift/related tools [[#567](https://github.com/falcosecurity/falco/pull/567)] [[#573](https://github.com/falcosecurity/falco/pull/573)]

* Better coverage for cassandra/kubelet/kops to reduce FPs [[#551](https://github.com/falcosecurity/falco/pull/551)]

* Better coverage for docker, openscap to reduce FPs [[#573](https://github.com/falcosecurity/falco/pull/573)]

* Better coverage for fluentd/jboss to reduce FPs [[#590](https://github.com/falcosecurity/falco/pull/590)]

* Add `ash` (Alpine Linux-related shell) as a shell binary [[#597](https://github.com/falcosecurity/falco/pull/597)]

## v0.14.0

Released 2019-02-06

### Major Changes

* Rules versioning support: The falco engine and executable now have an *engine version* that represents the fields they support. Similarly, rules files have an optional *required_engine_version: NNN* object that names the minimum engine version required to read that rules file. Any time the engine adds new fields, event sources, etc, the engine version will be incremented, and any time a rules file starts using new fields, event sources, etc, the required engine version will be incremented. [[#492](https://github.com/falcosecurity/falco/pull/492)]

* Allow SSL for K8s audit endpoint/embedded webserver [[#471](https://github.com/falcosecurity/falco/pull/471)]

* Add stale issues bot that automatically flags old github issues as stale after 60 days of inactivity and closes issues after 67 days of inactivity. [[#500](https://github.com/falcosecurity/falco/pull/500)]

* Support bundle: When run with `--support`, falco will print a json object containing necessary information like falco version, command line, operating system information, and falco rules files contents. This could be useful when reporting issues. [[#517](https://github.com/falcosecurity/falco/pull/517)]

### Minor Changes

* Support new third-party library dependencies from open source sysdig. [[#498](https://github.com/falcosecurity/falco/pull/498)]

* Add CII best practices badge. [[#499](https://github.com/falcosecurity/falco/pull/499)]

* Fix kernel module builds when running on centos as a container by installing gcc 5 by hand instead of directly from debian/unstable. [[#501](https://github.com/falcosecurity/falco/pull/501)]

* Mount `/etc` when running as a container, which allows container to build kernel module/ebpf program on COS/Minikube. [[#475](https://github.com/falcosecurity/falco/pull/475)]

* Improved way to specify the source of generic event objects [[#480](https://github.com/falcosecurity/falco/pull/480)]

* Readability/clarity improvements to K8s Audit/K8s Daemonset READMEs. [[#503](https://github.com/falcosecurity/falco/pull/503)]

* Add additional RBAC permissions to track deployments/daemonsets/replicasets. [[#514](https://github.com/falcosecurity/falco/pull/514)]

### Bug Fixes

* Fix formatting of nodejs examples README [[#502](https://github.com/falcosecurity/falco/pull/502)]

### Rule Changes

* Remove FPs for `Launch Sensitive Mount Container` rule [[#509](https://github.com/falcosecurity/falco/pull/509/files)]

* Update Container rules/macros to use the more reliable `container.image.{repository,tag}` that always return the repository/tag of an image instead of `container.image`, which may not for some docker daemon versions. [[#513](https://github.com/falcosecurity/falco/pull/513)]

## v0.13.1

Released 2019-01-16

### Major Changes


### Minor Changes

* Unbuffer outputs by default. This helps make output readable when used in environments like K8s. [[#494](https://github.com/falcosecurity/falco/pull/494)]

* Improved documentation for running Falco within K8s and getting K8s Audit Logging to work with Minikube and Falco as a Daemonset within K8s. [[#496](https://github.com/falcosecurity/falco/pull/496)]

* Fix AWS Permissions for Kubernetes Response Engine [[#465](https://github.com/falcosecurity/falco/pull/465)]

* Tighten compilation flags to include `-Wextra` and `-Werror` [[#479](https://github.com/falcosecurity/falco/pull/479)]

* Add `k8s.ns.name` to outputs when `-pk` argument is used [[#472](https://github.com/falcosecurity/falco/pull/472)]

* Remove kubernetes-response-engine from system:masters [[#488](https://github.com/falcosecurity/falco/pull/488)]

### Bug Fixes

* Ensure `-pc`/`-pk` only apply to syscall rules and not k8s_audit rules [[#495](https://github.com/falcosecurity/falco/pull/495)]

* Fix a potential crash that could occur when using the falco engine and rulesets [[#468](https://github.com/falcosecurity/falco/pull/468)]

* Fix a regression where format output options were mistakenly removed [[#485](https://github.com/falcosecurity/falco/pull/485)]

### Rule Changes

* Fix FPs related to calico and writing files below etc [[#481](https://github.com/falcosecurity/falco/pull/481)]

* Fix FPs related to `apt-config`/`apt-cache`, `apk` [[#490](https://github.com/falcosecurity/falco/pull/490)]

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, `Lauch Suspicious Network Tool in Container` look for host-level network tools like `netcat`, package management tools like `apt-get`, or network tool binaries being run in a container. [[#490](https://github.com/falcosecurity/falco/pull/490)]

* Fix the `inbound` and `outbound` macros so they work with sendto/recvfrom/sendmsg/recvmsg. [[#470](https://github.com/falcosecurity/falco/pull/470)]

* Fix FPs related to prometheus/openshift writing config below /etc. [[#470](https://github.com/falcosecurity/falco/pull/470)]


## v0.13.0

Released 2018-11-09

### Major Changes

* **Support for K8s Audit Events** : Falco now supports [K8s Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) as a second stream of events in addition to syscalls. For full details on the feature, see the [wiki](https://github.com/falcosecurity/falco/wiki/K8s-Audit-Event-Support).

* Transparent Config/Rule Reloading: On SIGHUP, Falco will now reload all config files/rules files and start processing new events. Allows rules changes without having to restart falco [[#457](https://github.com/falcosecurity/falco/pull/457)] [[#432](https://github.com/falcosecurity/falco/issues/432)]

### Minor Changes

* The reference integration of falco into a action engine now supports aws actions like lambda, etc. [[#460](https://github.com/falcosecurity/falco/pull/460)]

* Add netcat to falco docker images, which allows easier integration of program outputs to external servers [[#456](https://github.com/falcosecurity/falco/pull/456)] [[#433](https://github.com/falcosecurity/falco/issues/433)]

### Bug Fixes

* Links cleanup related to the draios/falco -> falcosecurity/falco move [[#447](https://github.com/falcosecurity/falco/pull/447)]

* Properly load/unload kernel module when the falco service is started/stopped [[#459](https://github.com/falcosecurity/falco/pull/459)] [[#418](https://github.com/falcosecurity/falco/issues/418)]

### Rule Changes

* Better coverage (e.g. reduced FPs) for critical stack, hids systems, ufw, cloud-init, etc. [[#445](https://github.com/falcosecurity/falco/pull/445)]

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, and `Lauch Suspicious Network Tool in Container` look for running various suspicious programs in a container. [[#461](https://github.com/falcosecurity/falco/pull/461)]

* Misc changes to address false positives in GKE, Istio, etc. [[#455](https://github.com/falcosecurity/falco/pull/455)] [[#439](https://github.com/falcosecurity/falco/issues/439)]

## v0.12.1

Released 2018-09-11

### Bug Fixes

* Fig regression in libcurl configure script [[#416](https://github.com/draios/falco/pull/416)]

## v0.12.0

Released 2018-09-11

### Major Changes

* Improved IPv6 Support to fully support use of IPv6 addresses in events, connections and filters [[#sysdig/1204](https://github.com/draios/sysdig/pull/1204)]

* Ability to associate connections with dns names: new filterchecks `fd.*ip.name` allow looking up the DNS name for a connection's IP address. This can be used to identify or restrict connections by dns names e.g. `evt.type=connect and fd.sip.name=github.com`. [[#412](https://github.com/draios/falco/pull/412)] [[#sysdig/1213](https://github.com/draios/sysdig/pull/1213)]

* New filterchecks `user.loginuid` and `user.loginname` can be used to match the login uid, which stays consistent across sudo/su. This can be used to find the actual user running a given process [[#sysdig/1189](https://github.com/draios/sysdig/pull/1189)]

### Minor Changes

* Upgrade zlib to 1.2.11, openssl to 1.0.2n, and libcurl to 7.60.0 to address software vulnerabilities [[#402](https://github.com/draios/falco/pull/402)]
* New `endswith` operator can be used for suffix matching on strings [[#sysdig/1209](https://github.com/draios/sysdig/pull/1209)]

### Bug Fixes

* Better control of specifying location of lua source code [[#406](https://github.com/draios/falco/pull/406)]

### Rule Changes

* None for this release.

## v0.11.1

Released 2018-07-31

### Bug Fixes

* Fix a problem that caused the kernel module to not load on certain kernel versions [[#397](https://github.com/draios/falco/pull/397)] [[#394](https://github.com/draios/falco/issues/394)]

## v0.11.0

Released 2018-07-24

### Major Changes

* **EBPF Support** (Beta): Falco can now read events via an ebpf program loaded into the kernel instead of the `falco-probe` kernel module. Full docs [here](https://github.com/draios/sysdig/wiki/eBPF-(beta)). [[#365](https://github.com/draios/falco/pull/365)]

### Minor Changes

* Rules may now have an `skip-if-unknown-filter` property. If set to true, a rule will be skipped if its condition/output property refers to a filtercheck (e.g. `fd.some-new-attibute`) that is not present in the current falco version. [[#364](https://github.com/draios/falco/pull/364)] [[#345](https://github.com/draios/falco/issues/345)]
* Small changes to Falco `COPYING` file so github automatically recognizes license [[#380](https://github.com/draios/falco/pull/380)]
* New example integration showing how to connect Falco with Anchore to dynamically create falco rules based on negative scan results [[#390](https://github.com/draios/falco/pull/390)]
* New example integration showing how to connect Falco, [nats](https://nats.io/), and K8s to run flexible "playbooks" based on Falco events [[#389](https://github.com/draios/falco/pull/389)]

### Bug Fixes

* Ensure all rules are enabled by default [[#379](https://github.com/draios/falco/pull/379)]
* Fix libcurl compilation problems [[#374](https://github.com/draios/falco/pull/374)]
* Add gcc-6 to docker container, which improves compatibility when building kernel module [[#382](https://github.com/draios/falco/pull/382)] [[#371](https://github.com/draios/falco/issues/371)]
* Ensure the /lib/modules symlink to /host/lib/modules is set correctly [[#392](https://github.com/draios/falco/issues/392)]

### Rule Changes

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

### Major Changes

* **Rules Directory Support**: Falco will read rules files from `/etc/falco/rules.d` in addition to `/etc/falco/falco_rules.yaml` and `/etc/falco/falco_rules.local.yaml`. Also, when the argument to `-r`/falco.yaml `rules_file` is a directory, falco will read rules files from that directory. [[#348](https://github.com/draios/falco/pull/348)] [[#187](https://github.com/draios/falco/issues/187)]
* Properly support all syscalls (e.g. those without parameter extraction by the kernel module) in falco conditions, so they can be included in `evt.type=<name>` conditions. [[#352](https://github.com/draios/falco/pull/352)]
* When packaged as a container, start building kernel module with gcc 5.0 instead of gcc 4.9. [[#331](https://github.com/draios/falco/pull/331)]
* New example puppet module for falco. [[#341](https://github.com/draios/falco/pull/341)] [[#115](https://github.com/draios/falco/issues/115)]
* When signaled with `USR1`, falco will close/reopen log files. Include a [logrotate](https://github.com/logrotate/logrotate) example that shows how to use this feature for log rotation. [[#347](https://github.com/draios/falco/pull/347)] [[#266](https://github.com/draios/falco/issues/266)]
* To improve resource usage, further restrict the set of system calls available to falco [[#351](https://github.com/draios/falco/pull/351)] [[draios/sysdig#1105](https://github.com/draios/sysdig/pull/1105)]

### Minor Changes

* Add gdb to the development Docker image (sysdig/falco:dev) to aid in debugging. [[#323](https://github.com/draios/falco/pull/323)]
* You can now specify -V multiple times on the command line to validate multiple rules files at once. [[#329](https://github.com/draios/falco/pull/329)]
* When run with `-v`, falco will print *dangling* macros/lists that are not used by any rules. [[#329](https://github.com/draios/falco/pull/329)]
* Add an example demonstrating cryptomining attack that exploits an open docker daemon using host mounts. [[#336](https://github.com/draios/falco/pull/336)]
* New falco.yaml option `json_include_output_property` controls whether the formatted string "output" is included in the json object when json output is enabled. [[#342](https://github.com/draios/falco/pull/342)]
* Centralize testing event types for consideration by falco into a single function [[draios/sysdig#1105](https://github.com/draios/sysdig/pull/1105)) [[#356](https://github.com/draios/falco/pull/356)]
* If a rule has an attribute `warn_evttypes`, falco will not complain about `evt.type` restrictions on that rule [[#355](https://github.com/draios/falco/pull/355)]
* When run with `-i`, print all ignored events/syscalls and exit. [[#359](https://github.com/draios/falco/pull/359)]

### Bug Fixes

* Minor bug fixes to k8s daemonset configuration. [[#325](https://github.com/draios/falco/pull/325)] [[#296](https://github.com/draios/falco/pull/296)] [[#295](https://github.com/draios/falco/pull/295)]
* Ensure `--validate` can be used interchangeably with `-V`. [[#334](https://github.com/draios/falco/pull/334)] [[#322](https://github.com/draios/falco/issues/322)]
* Rule conditions like `fd.net` can now be used with the `in` operator e.g. `evt.type=connect and fd.net in ("127.0.0.1/24")`. [[draios/sysdig#1091](https://github.com/draios/sysdig/pull/1091)] [[#343](https://github.com/draios/falco/pull/343)]
* Ensure that `keep_alive` can be used both with file and program output at the same time. [[#335](https://github.com/draios/falco/pull/335)]
* Make it possible to append to a skipped macro/rule without falco complaining [[#346](https://github.com/draios/falco/pull/346)] [[#305](https://github.com/draios/falco/issues/305)]
* Ensure rule order is preserved even when rules do not contain any `evt.type` restriction. [[#354](https://github.com/draios/falco/issues/354)] [[#355](https://github.com/draios/falco/pull/355)]

### Rule Changes

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

| Workload                          | 0.2.0 CPU Usage | 0.3.0 CPU Usage |
| --------------------------------- | --------------- | --------------- |
| pts/apache                        | 24%             | 7%              |
| pts/dbench                        | 70%             | 5%              |
| Kubernetes-Demo (Running)         | 6%              | 2%              |
| Kubernetes-Demo (During Teardown) | 15%             | 3%              |
| Juttle-examples                   | 3%              | 1%              |

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
