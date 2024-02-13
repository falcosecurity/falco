# Change Log

## v0.37.1

Released on 2024-02-13

### Major Changes

* new(docker): added option for insecure http driver download to falco and driver-loader images [[#3058](https://github.com/falcosecurity/falco/pull/3058)] - [@toamto94](https://github.com/toamto94)

### Minor Changes

* update(cmake): bumped falcoctl to v0.7.2 [[#3076](https://github.com/falcosecurity/falco/pull/3076)] - [@FedeDP](https://github.com/FedeDP)
* update(build): link libelf dynamically [[#3048](https://github.com/falcosecurity/falco/pull/3048)] - [@LucaGuerra](https://github.com/LucaGuerra)

### Bug Fixes

* fix(userspace/engine): always consider all rules (even the ones below min_prio) in m_rule_stats_manager [[#3060](https://github.com/falcosecurity/falco/pull/3060)] - [@FedeDP](https://github.com/FedeDP)

### Non user-facing changes

* Added http headers option for driver download in docker images [[#3075](https://github.com/falcosecurity/falco/pull/3075)] - [@toamto94](https://github.com/toamto94)
* fix(build): install libstdc++ in the Wolfi image [[#3053](https://github.com/falcosecurity/falco/pull/3053)] - [@LucaGuerra](https://github.com/LucaGuerra)

## v0.37.0

Released on 2024-01-30

### Breaking Changes

- The deprecated `rate-limiter` mechanism is removed as it is no longer used.
  - the deprecated `outputs.rate` Falco config is removed.
  - the deprecated `outputs.max_burst` Falco config is removed.
- The deprecated `--userspace` CLI option is removed as it is no longer used.
- The `falco-driver-loader` script will be removed and embedded into falcoctl. The new falcoctl driven implementation will drop:
  - `--source-only` CLI option.
  - `BPF_USE_LOCAL_KERNEL_SOURCES` environment variable.
  - `DRIVER_CURL_OPTIONS` environment variable.
  - `FALCO_BPF_PROBE` environment variable is not used by the new falcoctl driver loader, since it is already deprecated and will be removed in the next major version.
  
  Some env vars were renamed:
  - `DRIVERS_REPO` env variable has been replaced by `FALCOCTL_DRIVER_NAME`  or `--name` command line argument for `falcoctl driver` command
  - `DRIVERS_NAME` env variable has been replaced by `FALCOCTL_DRIVER_REPOS`, or `--repo` command line argument for `falcoctl driver` command
  - `DRIVER_KERNEL_RELEASE` env variable has been replaced by `--kernelrelease` command line argument for `falcoctl driver install` command
  - `DRIVER_KERNEL_VERSION` env variable has been replaced by `--kernelversion` command line argument for `falcoctl driver install` command
  - `DRIVER_INSECURE_DOWNLOAD` env variable has been replaced by `--http-insecure` command line argument for `falcoctl driver install` command
- Remove `-K/-k` options from Falco in favor of the new `k8smeta` plugin.
- Drop plugins shipped with Falco since plugins are now be managed by falcoctl.
- Falco 0.37.0 allows environment variables to be expanded even if they are part of a string. This introduces small breaking changes:
  - Previously, environment variables used in YAML that were empty or defined as `“”` would be expanded to the default value. This was not consistent with the way YAML was handled in other cases, where we only returned the default values if the node was not defined. Now expanded env vars retain the same behavior of all other variables.
  - Falco 0.37.0 will return default value for nodes that cannot be parsed to chosen type.
  - `program_output` command will be env-expanded at init time, instead of letting `popen` and thus the `sh` shell expand it. This is technically a breaking change even if no behavioral change is expected. Also, you can avoid env var expansion by using `${{FOO}}` instead of `${FOO}`. It will resolve to `${FOO}` and won't be resolved to the env var value.

### Major Changes

* new!: dropped falco-driver-loader script in favor of new falcoctl driver command [[#2905](https://github.com/falcosecurity/falco/pull/2905)] - [@FedeDP](https://github.com/FedeDP)
* update!: bump libs to latest and deprecation of k8s metadata options and configs [[#2914](https://github.com/falcosecurity/falco/pull/2914)] - [@jasondellaluce](https://github.com/jasondellaluce)
* cleanup(falco)!: remove `outputs.rate` and `outputs.max_burst` from Falco config [[#2841](https://github.com/falcosecurity/falco/pull/2841)] - [@Andreagit97](https://github.com/Andreagit97)
* cleanup(falco)!: remove `--userspace` support [[#2839](https://github.com/falcosecurity/falco/pull/2839)] - [@Andreagit97](https://github.com/Andreagit97)
* new(engine): add selective overrides for Falco rules [[#2981](https://github.com/falcosecurity/falco/pull/2981)] - [@LucaGuerra](https://github.com/LucaGuerra)
* feat(userspace/falco): falco administrators can now configure the http output to compress the data sent as well as enable keep alive for the connection. Two new fields (compress_uploads and keep_alive) in the http_output block of the `falco.yaml` file can be used for that purpose. Both are disabled by default. [[#2974](https://github.com/falcosecurity/falco/pull/2974)] - [@sgaist](https://github.com/sgaist)
* new(userspace): support env variable expansion in all yaml, even inside strings. [[#2918](https://github.com/falcosecurity/falco/pull/2918)] - [@FedeDP](https://github.com/FedeDP)
* new(scripts): add a way to enforce driver kind and falcoctl enablement when installing Falco from packages and dialog is not present. [[#2773](https://github.com/falcosecurity/falco/pull/2773)] - [@vjjmiras](https://github.com/vjjmiras)
* new(falco): print system info when Falco starts [[#2927](https://github.com/falcosecurity/falco/pull/2927)] - [@Andreagit97](https://github.com/Andreagit97)
* new: driver selection in falco.yaml [[#2413](https://github.com/falcosecurity/falco/pull/2413)] - [@therealbobo](https://github.com/therealbobo)
* new(build): enable compilation on win32 and macOS. [[#2889](https://github.com/falcosecurity/falco/pull/2889)] - [@therealbobo](https://github.com/therealbobo)
* feat(userspace/falco): falco administrators can now configure the address on which the webserver listen using the new listen_address field in the webserver block of the `falco.yaml` file. [[#2890](https://github.com/falcosecurity/falco/pull/2890)] - [@sgaist](https://github.com/sgaist)

### Minor Changes

* update(userspace/falco): add `engine_version_semver` key in `/versions` endpoint [[#2899](https://github.com/falcosecurity/falco/pull/2899)] - [@loresuso](https://github.com/loresuso)
* update: default ruleset upgrade to version 3.0 [[#3034](https://github.com/falcosecurity/falco/pull/3034)] - [@leogr](https://github.com/leogr)
* update!(config): soft deprecation of drop stats counters in `syscall_event_drops` [[#3015](https://github.com/falcosecurity/falco/pull/3015)] - [@incertum](https://github.com/incertum)
* update(cmake): bumped falcoctl tool to v0.7.1. [[#3030](https://github.com/falcosecurity/falco/pull/3030)] - [@FedeDP](https://github.com/FedeDP)
* update(rule_loader): deprecate the `append` flag in Falco rules [[#2992](https://github.com/falcosecurity/falco/pull/2992)] - [@Andreagit97](https://github.com/Andreagit97)
* cleanup!(cmake): drop bundled plugins in Falco [[#2997](https://github.com/falcosecurity/falco/pull/2997)] - [@FedeDP](https://github.com/FedeDP)
* update(config): clarify deprecation notices + list all env vars [[#2988](https://github.com/falcosecurity/falco/pull/2988)] - [@incertum](https://github.com/incertum)
* update: now the `watch_config_files` config option monitors file/directory moving and deletion, too [[#2965](https://github.com/falcosecurity/falco/pull/2965)] - [@NitroCao](https://github.com/NitroCao)
* update(userspace): enhancements in rule description feature [[#2934](https://github.com/falcosecurity/falco/pull/2934)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace/falco): add libsinsp state metrics option [[#2883](https://github.com/falcosecurity/falco/pull/2883)] - [@incertum](https://github.com/incertum)
* update(doc): Add Thought Machine as adopters [[#2919](https://github.com/falcosecurity/falco/pull/2919)] - [@RichardoC](https://github.com/RichardoC)
* update(docs): add Wireshark/Logray as adopter [[#2867](https://github.com/falcosecurity/falco/pull/2867)] - [@geraldcombs](https://github.com/geraldcombs)
* update: engine_version in semver representation [[#2838](https://github.com/falcosecurity/falco/pull/2838)] - [@loresuso](https://github.com/loresuso)
* update(userspace/engine): modularize rule compiler, fix and enrich rule descriptions [[#2817](https://github.com/falcosecurity/falco/pull/2817)] - [@jasondellaluce](https://github.com/jasondellaluce)

### Bug Fixes

* fix(userspace/metric): minor fixes in new libsinsp state metrics handling [[#3033](https://github.com/falcosecurity/falco/pull/3033)] - [@incertum](https://github.com/incertum)
* fix(userspace/engine): avoid storing escaped strings in engine defs [[#3028](https://github.com/falcosecurity/falco/pull/3028)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/engine): cache latest rules compilation output [[#2900](https://github.com/falcosecurity/falco/pull/2900)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/engine): solve description of macro-only rules [[#2898](https://github.com/falcosecurity/falco/pull/2898)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/engine): fix memory leak [[#2877](https://github.com/falcosecurity/falco/pull/2877)] - [@therealbobo](https://github.com/therealbobo)

### Non user-facing changes

* fix: nlohmann_json lib include path [[#3032](https://github.com/falcosecurity/falco/pull/3032)] - [@federico-sysdig](https://github.com/federico-sysdig)
* chore: bump falco rules [[#3021](https://github.com/falcosecurity/falco/pull/3021)] - [@Andreagit97](https://github.com/Andreagit97)
* chore: bump Falco to libs 0.14.1 [[#3020](https://github.com/falcosecurity/falco/pull/3020)] - [@Andreagit97](https://github.com/Andreagit97)
* chore(build): remove outdated development libs [[#2946](https://github.com/falcosecurity/falco/pull/2946)] - [@federico-sysdig](https://github.com/federico-sysdig)
* chore(falco): bump Falco to `000d576` libs commit [[#2944](https://github.com/falcosecurity/falco/pull/2944)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(gha): update rpmsign [[#2856](https://github.com/falcosecurity/falco/pull/2856)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `424b258` to `1221b9e` [[#3000](https://github.com/falcosecurity/falco/pull/3000)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `2ac430b` to `c39d31a` [[#3019](https://github.com/falcosecurity/falco/pull/3019)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(falco.yaml): rename `none` in `nodriver` [[#3012](https://github.com/falcosecurity/falco/pull/3012)] - [@Andreagit97](https://github.com/Andreagit97)
* update(config): graduate outputs_queue to stable [[#3016](https://github.com/falcosecurity/falco/pull/3016)] - [@incertum](https://github.com/incertum)
* update(cmake): bump falcoctl to v0.7.0. [[#3009](https://github.com/falcosecurity/falco/pull/3009)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-rules from `1221b9e` to `2ac430b` [[#3007](https://github.com/falcosecurity/falco/pull/3007)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* chore(ci): bumped rn2md to latest master. [[#3006](https://github.com/falcosecurity/falco/pull/3006)] - [@FedeDP](https://github.com/FedeDP)
* chore: bump Falco to latest libs [[#3002](https://github.com/falcosecurity/falco/pull/3002)] - [@Andreagit97](https://github.com/Andreagit97)
* chore: bump driver version [[#2998](https://github.com/falcosecurity/falco/pull/2998)] - [@Andreagit97](https://github.com/Andreagit97)
* Add addl source related methods [[#2939](https://github.com/falcosecurity/falco/pull/2939)] - [@mstemm](https://github.com/mstemm)
* build(deps): Bump submodules/falcosecurity-rules from `cd33bc3` to `424b258` [[#2993](https://github.com/falcosecurity/falco/pull/2993)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(engine): clarify deprecation notice for engines [[#2987](https://github.com/falcosecurity/falco/pull/2987)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(cmake): bumped falcoctl to v0.7.0-rc1. [[#2983](https://github.com/falcosecurity/falco/pull/2983)] - [@FedeDP](https://github.com/FedeDP)
* chore(ci): revert #2961. [[#2984](https://github.com/falcosecurity/falco/pull/2984)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-testing from `930170b` to `9b9630e` [[#2980](https://github.com/falcosecurity/falco/pull/2980)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* chore: bump Falco to latest libs [[#2977](https://github.com/falcosecurity/falco/pull/2977)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `262f569` to `cd33bc3` [[#2976](https://github.com/falcosecurity/falco/pull/2976)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* Allow enabling rules by ruleset id in addition to name [[#2920](https://github.com/falcosecurity/falco/pull/2920)] - [@mstemm](https://github.com/mstemm)
* chore(ci): enable aarch64 falco driver loader tests. [[#2961](https://github.com/falcosecurity/falco/pull/2961)] - [@FedeDP](https://github.com/FedeDP)
* chore(unit_tests): added more tests for yaml env vars expansion. [[#2972](https://github.com/falcosecurity/falco/pull/2972)] - [@FedeDP](https://github.com/FedeDP)
* chore(falco.yaml): use HOME env var for ebpf probe path. [[#2971](https://github.com/falcosecurity/falco/pull/2971)] - [@FedeDP](https://github.com/FedeDP)
* chore: bump falco to latest libs [[#2970](https://github.com/falcosecurity/falco/pull/2970)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `dd38952` to `262f569` [[#2969](https://github.com/falcosecurity/falco/pull/2969)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* update(readme): add actuated.dev badge [[#2967](https://github.com/falcosecurity/falco/pull/2967)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(cmake,docker): bumped falcoctl to v0.7.0-beta5. [[#2968](https://github.com/falcosecurity/falco/pull/2968)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-rules from `64e2adb` to `dd38952` [[#2959](https://github.com/falcosecurity/falco/pull/2959)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(docker): small fixes in docker entrypoints for new driver loader. [[#2966](https://github.com/falcosecurity/falco/pull/2966)] - [@FedeDP](https://github.com/FedeDP)
* chore(build): allow usage of non-bundled nlohmann-json [[#2947](https://github.com/falcosecurity/falco/pull/2947)] - [@federico-sysdig](https://github.com/federico-sysdig)
* update(ci): enable actuated.dev [[#2945](https://github.com/falcosecurity/falco/pull/2945)] - [@LucaGuerra](https://github.com/LucaGuerra)
* cleanup: fix several warnings from a Clang build [[#2948](https://github.com/falcosecurity/falco/pull/2948)] - [@federico-sysdig](https://github.com/federico-sysdig)
* chore(docker/falco): add back some deps to falco docker image. [[#2932](https://github.com/falcosecurity/falco/pull/2932)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-testing from `92c313f` to `5248e6d` [[#2937](https://github.com/falcosecurity/falco/pull/2937)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `e206c1a` to `8f0520f` [[#2904](https://github.com/falcosecurity/falco/pull/2904)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(falco): remove decode_uri as it is no longer used [[#2933](https://github.com/falcosecurity/falco/pull/2933)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(engine): port decode_uri in falco engine [[#2912](https://github.com/falcosecurity/falco/pull/2912)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(falco): update to libs on nov 28th [[#2929](https://github.com/falcosecurity/falco/pull/2929)] - [@LucaGuerra](https://github.com/LucaGuerra)
* cleanup(falco): remove `init` in the configuration constructor [[#2917](https://github.com/falcosecurity/falco/pull/2917)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `8f0520f` to `64e2adb` [[#2908](https://github.com/falcosecurity/falco/pull/2908)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(userspace/engine): remove legacy k8saudit implementation [[#2913](https://github.com/falcosecurity/falco/pull/2913)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(gha): disable branch protection rule trigger for scorecard [[#2911](https://github.com/falcosecurity/falco/pull/2911)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(gha): set cosign-installer to v3.1.2 [[#2901](https://github.com/falcosecurity/falco/pull/2901)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(docs): sync changelog for 0.36.2. [[#2894](https://github.com/falcosecurity/falco/pull/2894)] - [@FedeDP](https://github.com/FedeDP)
* Run OpenSSF Scorecard in pipeline [[#2888](https://github.com/falcosecurity/falco/pull/2888)] - [@maxgio92](https://github.com/maxgio92)
* cleanup: replace banned.h with semgrep [[#2881](https://github.com/falcosecurity/falco/pull/2881)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(gha): upgrade GitHub actions [[#2876](https://github.com/falcosecurity/falco/pull/2876)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `a22d0d7` to `e206c1a` [[#2865](https://github.com/falcosecurity/falco/pull/2865)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `d119706` to `a22d0d7` [[#2860](https://github.com/falcosecurity/falco/pull/2860)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(gha): use fedora instead of centos 7 for package publishing [[#2854](https://github.com/falcosecurity/falco/pull/2854)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(gha): pin versions to hashes [[#2849](https://github.com/falcosecurity/falco/pull/2849)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `c366d5b` to `d119706` [[#2847](https://github.com/falcosecurity/falco/pull/2847)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* new(ci): properly link libs and driver releases linked to a Falco release [[#2846](https://github.com/falcosecurity/falco/pull/2846)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-rules from `7a7cf24` to `c366d5b` [[#2842](https://github.com/falcosecurity/falco/pull/2842)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `77ba57a` to `7a7cf24` [[#2836](https://github.com/falcosecurity/falco/pull/2836)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* chore(ci): bumped rn2md to latest master. [[#2844](https://github.com/falcosecurity/falco/pull/2844)] - [@FedeDP](https://github.com/FedeDP)

## v0.36.2

Released on 2023-10-27

NO CHANGES IN FALCO, ALL CHANGES IN LIBS.


## v0.36.1

Released on 2023-10-16

### Major Changes

### Minor Changes

* feat(userspace): remove experimental outputs queue recovery strategies [[#2863](https://github.com/falcosecurity/falco/pull/2863)] - [@incertum](https://github.com/incertum)

### Bug Fixes

* fix(userspace/falco): timer_delete() workaround due to bug in older GLIBC [[#2851](https://github.com/falcosecurity/falco/pull/2851)] - [@incertum](https://github.com/incertum)


## v0.36.0

Released on 2023-09-26

### Breaking Changes

- The default rules file that is shipped in the Falco image and/or can be downloaded via falcoctl as `falco-rules` is now a _stable_ rule file. This file **contains a much smaller number of rules** that are less noisy and have been vetted by the community. This serves as a much requested "starter" Falco rule set that covers many common use case. The rest of that file has been expanded and split into `falco-incubating-rules` and `falco-sandbox-rules`. For more information, see the [rules repository](https://github.com/falcosecurity/rules)
- The main `falcosecurity/falco` container image and its `falco-driver-loader` counterpart have been upgraded. Now they are able to compile the kernel module or classic eBPF probe for relatively newer version of the kernel (5.x and above) while we no longer ship toolchains to compile the kernel module for older versions in the default images. Downloading of prebuilt drivers and the modern eBPF will work exactly like before. The older image, meant for compatibility with older kernels (4.x and below), is currently retained as `falcosecurity/falco-driver-loader-legacy`.
- The Falco HTTP output no longer logs to stdout by default for performance reasons. You can set stdout logging preferences and restore the previous behavior with the configuration option `http_output.echo` in `falco.yaml`.
- The `--list-syscall-events` command line option has been replaced by `--list-events` which prints all supported system events (syscall, tracepoints, metaevents, internal plugin events) in addition to extra information about flags.
- The semantics of `proc.exepath` have changed. Now that field contains the executable path on disk even if the binary was launched from a symbolic link.
- The `-d` daemonize option has been removed.
- The `-p` option is now changed:
    - when only `-pc` is set Falco will print `container_id=%container.id container_image=%container.image.repository container_image_tag=%container.image.tag container_name=%container.name`
    - when `-pk` is set it will print as above, but with `k8s_ns=%k8s.ns.name k8s_pod_name=%k8s.pod.name` appended


### Major Changes


* new(falco-driver-loader): --source-only now prints the values as env vars [[#2353](https://github.com/falcosecurity/falco/pull/2353)] - [@steakunderscore](https://github.com/steakunderscore)
* new(docker): allow passing options to falco-driver-loader from the driver loader container [[#2781](https://github.com/falcosecurity/falco/pull/2781)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(docker): add experimental falco-distroless image based on Wolfi [[#2768](https://github.com/falcosecurity/falco/pull/2768)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new: the legacy falco image is available as driver-loader-legacy [[#2718](https://github.com/falcosecurity/falco/pull/2718)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new: added option to enable/disable echoing of server answer to stdout (disabled by default) when using HTTP output [[#2602](https://github.com/falcosecurity/falco/pull/2602)] - [@FedeDP](https://github.com/FedeDP)
* new: support systemctl reload for Falco services [[#2588](https://github.com/falcosecurity/falco/pull/2588)] - [@jabdr](https://github.com/jabdr)
* new(falco/config): add new configurations for http_output that allow mTLS [[#2633](https://github.com/falcosecurity/falco/pull/2633)] - [@annadorottya](https://github.com/annadorottya)
* new: allow falco to match multiple rules on same event [[#2705](https://github.com/falcosecurity/falco/pull/2705)] - [@loresuso](https://github.com/loresuso)


### Minor Changes

* update(cmake): bumped bundled falcoctl to 0.6.2 [[#2829](https://github.com/falcosecurity/falco/pull/2829)] - [@FedeDP](https://github.com/FedeDP)
* update(rules)!: major rule update to version 2.0.0 [[#2823](https://github.com/falcosecurity/falco/pull/2823)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(cmake): bumped plugins to latest stable versions [[#2820](https://github.com/falcosecurity/falco/pull/2820)] - [@FedeDP](https://github.com/FedeDP)
* update(cmake): bumped libs to 0.13.0-rc2 and driver to 6.0.1+driver [[#2806](https://github.com/falcosecurity/falco/pull/2806)] - [@FedeDP](https://github.com/FedeDP)
* update!: default substitution for `%container.info` is now equal `container_id=%container.id container_name=%container.name` [[#2793](https://github.com/falcosecurity/falco/pull/2793)] - [@leogr](https://github.com/leogr)
* update!: the --list-syscall-events flag is now called --list-events and lists all events [[#2771](https://github.com/falcosecurity/falco/pull/2771)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update!: the Falco base image is now based on Debian 12 with gcc 11-12 [[#2718](https://github.com/falcosecurity/falco/pull/2718)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(docker): the Falco no-driver image is now based on Debian 12 [[#2782](https://github.com/falcosecurity/falco/pull/2782)] - [@LucaGuerra](https://github.com/LucaGuerra)
* feat(userspace)!: remove `-d` daemonize option [[#2677](https://github.com/falcosecurity/falco/pull/2677)] - [@incertum](https://github.com/incertum)
* build(deps): Bump submodules/falcosecurity-rules from 3f52480 to 0d0e333 [[#2693](https://github.com/falcosecurity/falco/pull/2693)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from 3f52480 to b42893a [[#2756](https://github.com/falcosecurity/falco/pull/2756)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from b42893a to 6ed73fe [[#2780](https://github.com/falcosecurity/falco/pull/2780)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* update(cmake): bumped libs to 0.13.0-rc1 and driver to 6.0.0+driver. [[#2783](https://github.com/falcosecurity/falco/pull/2783)] - [@FedeDP](https://github.com/FedeDP)
* feat: support parsing of system environment variables in yaml [[#2562](https://github.com/falcosecurity/falco/pull/2562)] - [@therealdwright](https://github.com/therealdwright)
* feat(userspace)!: deprecate stats command args option in favor of metrics configs in falco.yaml [[#2739](https://github.com/falcosecurity/falco/pull/2739)] - [@incertum](https://github.com/incertum)
* update: upgrade `falcoctl` to version 0.6.0 [[#2764](https://github.com/falcosecurity/falco/pull/2764)] - [@leogr](https://github.com/leogr)
* cleanup: deprecate rate limiter mechanism [[#2762](https://github.com/falcosecurity/falco/pull/2762)] - [@Andreagit97](https://github.com/Andreagit97)
* cleanup(config): add more info [[#2758](https://github.com/falcosecurity/falco/pull/2758)] - [@incertum](https://github.com/incertum)
* update(userspace/engine): improve skip-if-unknown-filter YAML field [[#2749](https://github.com/falcosecurity/falco/pull/2749)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore: improved HTTP output performance [[#2602](https://github.com/falcosecurity/falco/pull/2602)] - [@FedeDP](https://github.com/FedeDP)
* update!: HTTP output will no more echo to stdout by default [[#2602](https://github.com/falcosecurity/falco/pull/2602)] - [@FedeDP](https://github.com/FedeDP)
* chore: remove b64 from falco dependencies [[#2746](https://github.com/falcosecurity/falco/pull/2746)] - [@Andreagit97](https://github.com/Andreagit97)
* update(cmake): support building libs and driver from forks [[#2747](https://github.com/falcosecurity/falco/pull/2747)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: `-p` presets have been updated to reflect the new rules style guide [[#2737](https://github.com/falcosecurity/falco/pull/2737)] - [@leogr](https://github.com/leogr)
* feat: Allow specifying explicit kernel release and version for falco-driver-loader [[#2728](https://github.com/falcosecurity/falco/pull/2728)] - [@johananl](https://github.com/johananl)
* cleanup(config): assign Stable to `base_syscalls` config [[#2740](https://github.com/falcosecurity/falco/pull/2740)] - [@incertum](https://github.com/incertum)
* update : support build for wasm [[#2663](https://github.com/falcosecurity/falco/pull/2663)] - [@Rohith-Raju](https://github.com/Rohith-Raju)
* docs(config.yaml): fix wrong severity levels for sinsp logger [[#2736](https://github.com/falcosecurity/falco/pull/2736)] - [@Andreagit97](https://github.com/Andreagit97)
* update(cmake): bump libs and driver to 0.12.0 [[#2721](https://github.com/falcosecurity/falco/pull/2721)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(docker): remove experimental image based on RedHat UBI [[#2720](https://github.com/falcosecurity/falco/pull/2720)] - [@leogr](https://github.com/leogr)


### Bug Fixes

* fix(outputs): expose queue_capacity_outputs config for memory control [[#2711](https://github.com/falcosecurity/falco/pull/2711)] - [@incertum](https://github.com/incertum)
* fix(userspace/falco): cleanup metrics timer upon leaving. [[#2759](https://github.com/falcosecurity/falco/pull/2759)] - [@FedeDP](https://github.com/FedeDP)
* fix: restore Falco MINIMAL_BUILD and deprecate `userspace` option [[#2761](https://github.com/falcosecurity/falco/pull/2761)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/engine): support appending to unknown sources [[#2753](https://github.com/falcosecurity/falco/pull/2753)] - [@jasondellaluce](https://github.com/jasondellaluce)



### Non user-facing changes

* build(deps): Bump submodules/falcosecurity-rules from `69c9be8` to `77ba57a` [[#2833](https://github.com/falcosecurity/falco/pull/2833)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* chore: bump submodule testing to 62edc65 [[#2831](https://github.com/falcosecurity/falco/pull/2831)] - [@Andreagit97](https://github.com/Andreagit97)
* update(gha): add version for rn2md [[#2830](https://github.com/falcosecurity/falco/pull/2830)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore: automatically attach release author to release body. [[#2828](https://github.com/falcosecurity/falco/pull/2828)] - [@FedeDP](https://github.com/FedeDP)
* new(ci): autogenerate release body. [[#2812](https://github.com/falcosecurity/falco/pull/2812)] - [@FedeDP](https://github.com/FedeDP)
* fix(dockerfile): remove useless CMD [[#2824](https://github.com/falcosecurity/falco/pull/2824)] - [@Andreagit97](https://github.com/Andreagit97)
* chore: bump to the latest libs [[#2822](https://github.com/falcosecurity/falco/pull/2822)] - [@Andreagit97](https://github.com/Andreagit97)
* update: add SPDX license identifier [[#2809](https://github.com/falcosecurity/falco/pull/2809)] - [@leogr](https://github.com/leogr)
* chore: bump to latest libs [[#2815](https://github.com/falcosecurity/falco/pull/2815)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `ee5fb38` to `bea364e` [[#2814](https://github.com/falcosecurity/falco/pull/2814)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(build): set the right bucket and version for driver legacy [[#2800](https://github.com/falcosecurity/falco/pull/2800)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `43580b4` to `ee5fb38` [[#2810](https://github.com/falcosecurity/falco/pull/2810)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(userspace): thrown exceptions and avoid multiple logs [[#2803](https://github.com/falcosecurity/falco/pull/2803)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `c6e01fa` to `43580b4` [[#2801](https://github.com/falcosecurity/falco/pull/2801)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-testing from `76d1743` to `30c3643` [[#2802](https://github.com/falcosecurity/falco/pull/2802)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(userspace/falco): clearing full output queue [[#2798](https://github.com/falcosecurity/falco/pull/2798)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(docs): add driver-loader-legacy to readme and fix bad c&p [[#2799](https://github.com/falcosecurity/falco/pull/2799)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `d31dbc2` to `c6e01fa` [[#2797](https://github.com/falcosecurity/falco/pull/2797)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* docs: add LICENSE file [[#2796](https://github.com/falcosecurity/falco/pull/2796)] - [@leogr](https://github.com/leogr)
* build(deps): Bump submodules/falcosecurity-rules from `b6372d2` to `d31dbc2` [[#2794](https://github.com/falcosecurity/falco/pull/2794)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(stats): always initialize m_output field [[#2789](https://github.com/falcosecurity/falco/pull/2789)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `6ed73fe` to `b6372d2` [[#2786](https://github.com/falcosecurity/falco/pull/2786)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* update(cmake/modules): bump rules to falco-rules-2.0.0-rc1 [[#2775](https://github.com/falcosecurity/falco/pull/2775)] - [@leogr](https://github.com/leogr)
* update(OWNERS): add LucaGuerra to owners [[#2650](https://github.com/falcosecurity/falco/pull/2650)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `9126bef` to `0328c59` [[#2709](https://github.com/falcosecurity/falco/pull/2709)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `0d0e333` to `64ce419` [[#2731](https://github.com/falcosecurity/falco/pull/2731)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `3ceea88` to `40a9817` [[#2745](https://github.com/falcosecurity/falco/pull/2745)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* docs(README.md): correct URL [[#2772](https://github.com/falcosecurity/falco/pull/2772)] - [@vjjmiras](https://github.com/vjjmiras)
* #2393 Document why Falco is written in C++ rather than anything else [[#2410](https://github.com/falcosecurity/falco/pull/2410)] - [@RichardoC](https://github.com/RichardoC)
* chore: bump Falco to latest libs [[#2769](https://github.com/falcosecurity/falco/pull/2769)] - [@Andreagit97](https://github.com/Andreagit97)
* ci: disable falco-driver-loader tests on ARM64 [[#2770](https://github.com/falcosecurity/falco/pull/2770)] - [@Andreagit97](https://github.com/Andreagit97)
* update(userspace/falco): revised CLI help messages [[#2755](https://github.com/falcosecurity/falco/pull/2755)] - [@leogr](https://github.com/leogr)
* fix(engine): fix reorder warning for m_watch_config_files / m_rule_matching [[#2767](https://github.com/falcosecurity/falco/pull/2767)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update: introduce new stats updated to the latest libs version [[#2766](https://github.com/falcosecurity/falco/pull/2766)] - [@Andreagit97](https://github.com/Andreagit97)
* ci: support tests on amazon-linux [[#2765](https://github.com/falcosecurity/falco/pull/2765)] - [@Andreagit97](https://github.com/Andreagit97)
* chore: bump Falco to latest libs master [[#2754](https://github.com/falcosecurity/falco/pull/2754)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-testing from `b39c807` to `9110022` [[#2760](https://github.com/falcosecurity/falco/pull/2760)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix: fix "ebpf_enabled" output stat [[#2751](https://github.com/falcosecurity/falco/pull/2751)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/engine): support both old and new gcc + std::move [[#2748](https://github.com/falcosecurity/falco/pull/2748)] - [@jasondellaluce](https://github.com/jasondellaluce)
* cleanup: turn some warnings into errors [[#2744](https://github.com/falcosecurity/falco/pull/2744)] - [@Andreagit97](https://github.com/Andreagit97)
* update(ci): minimize retention days for build-only CI artifacts [[#2743](https://github.com/falcosecurity/falco/pull/2743)] - [@jasondellaluce](https://github.com/jasondellaluce)
* cleanup: remove unused `--pidfile` option from systemd units [[#2742](https://github.com/falcosecurity/falco/pull/2742)] - [@Andreagit97](https://github.com/Andreagit97)
* build(deps): Bump submodules/falcosecurity-rules from `bf1639a` to `3ceea88` [[#2741](https://github.com/falcosecurity/falco/pull/2741)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `64ce419` to `bf1639a` [[#2738](https://github.com/falcosecurity/falco/pull/2738)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* Relocate tools on Flatcar in BPF mode [[#2729](https://github.com/falcosecurity/falco/pull/2729)] - [@johananl](https://github.com/johananl)
* build: update versioning with cmake [[#2727](https://github.com/falcosecurity/falco/pull/2727)] - [@leogr](https://github.com/leogr)
* update(userspace/engine): make rule_matching strategy stateless  [[#2726](https://github.com/falcosecurity/falco/pull/2726)] - [@loresuso](https://github.com/loresuso)
* chore: bump Falco to latest libs version [[#2722](https://github.com/falcosecurity/falco/pull/2722)] - [@Andreagit97](https://github.com/Andreagit97)
* update: enforce bumping engine version whenever appropriate [[#2719](https://github.com/falcosecurity/falco/pull/2719)] - [@jasondellaluce](https://github.com/jasondellaluce)


## v0.35.1

Released on 2023-06-29

### Major Changes


### Minor Changes

* update(userspace): change description of snaplen option stating only performance implications [[#2634](https://github.com/falcosecurity/falco/pull/2634)] - [@loresuso](https://github.com/loresuso)
* update(cmake): bump libs to 0.11.3 [[#2662](https://github.com/falcosecurity/falco/pull/2662)] - [@jasondellaluce](https://github.com/jasondellaluce)
* cleanup(config): minor config clarifications [[#2651](https://github.com/falcosecurity/falco/pull/2651)] - [@incertum](https://github.com/incertum)
* update(cmake): bump falco rules to v1.0.1 [[#2648](https://github.com/falcosecurity/falco/pull/2648)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore(userspace/falco): make source matching error more expressive [[#2623](https://github.com/falcosecurity/falco/pull/2623)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(.github): integrate Go regression tests [[#2437](https://github.com/falcosecurity/falco/pull/2437)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Bug Fixes

* fix(scripts): fixed falco-driver-loader to manage debian kernel rt and cloud flavors. [[#2627](https://github.com/falcosecurity/falco/pull/2627)] - [@FedeDP](https://github.com/FedeDP)
* fix(userspace/falco): solve live multi-source issues when loading more than two sources [[#2653](https://github.com/falcosecurity/falco/pull/2653)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(driver-loader): fix ubuntu kernel version parsing [[#2635](https://github.com/falcosecurity/falco/pull/2635)] - [@therealbobo](https://github.com/therealbobo)
* fix(userspace): switch to timer_settime API for stats writer. [[#2646](https://github.com/falcosecurity/falco/pull/2646)] - [@FedeDP](https://github.com/FedeDP)



### Non user-facing changes

* CI: bump ubuntu version for tests-driver-loader-integration job [[#2661](https://github.com/falcosecurity/falco/pull/2661)] - [@Andreagit97](https://github.com/Andreagit97)

## v0.35.0

Released on 2023-06-07

### Major Changes

* BREAKING CHANGE: support for metadata enrichment from Mesos has been removed. [[#2465](https://github.com/falcosecurity/falco/pull/2465)] - [@leogr](https://github.com/leogr)

* new(falco): introduce new metrics w/ Falco internal: metrics snapshot option and new metrics config [[#2333](https://github.com/falcosecurity/falco/pull/2333)] - [@incertum](https://github.com/incertum)
* new(scripts): properly manage talos prebuilt drivers [[#2537](https://github.com/falcosecurity/falco/pull/2537)] - [@FedeDP](https://github.com/FedeDP)
* new(release): released container images are now signed with cosign [[#2546](https://github.com/falcosecurity/falco/pull/2546)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(ci): ported master and release artifacts publishing CI to gha [[#2501](https://github.com/falcosecurity/falco/pull/2501)] - [@FedeDP](https://github.com/FedeDP)
* new(app_actions): introduce base_syscalls user option [[#2428](https://github.com/falcosecurity/falco/pull/2428)] - [@incertum](https://github.com/incertum)
* new(falco/config): add new configurations for http_output that allow custom CA certificates and stores. [[#2458](https://github.com/falcosecurity/falco/pull/2458)] - [@alacuku](https://github.com/alacuku)
* new(userspace): add a new `syscall_drop_failed` config option to drop failed syscalls exit events [[#2456](https://github.com/falcosecurity/falco/pull/2456)] - [@FedeDP](https://github.com/FedeDP)


### Minor Changes

* update(cmake): bump Falco rules to 1.0.0 [[#2618](https://github.com/falcosecurity/falco/pull/2618)] - [@loresuso](https://github.com/loresuso)
* update(cmake): bump libs to 0.11.1 [[#2614](https://github.com/falcosecurity/falco/pull/2614)] - [@loresuso](https://github.com/loresuso)
* update(cmake): bump plugins to latest versions [[#2610](https://github.com/falcosecurity/falco/pull/2610)] - [@loresuso](https://github.com/loresuso)
* update(cmake): bump falco rules to 1.0.0-rc1 [[#2609](https://github.com/falcosecurity/falco/pull/2609)] - [@loresuso](https://github.com/loresuso)
* update(cmake): bump libs to 0.11.0 [[#2608](https://github.com/falcosecurity/falco/pull/2608)] - [@loresuso](https://github.com/loresuso)
* cleanup(docs): update release.md [[#2599](https://github.com/falcosecurity/falco/pull/2599)] - [@incertum](https://github.com/incertum)
* update(cmake): bump libs to 0.11.0-rc5 and driver to 5.0.1. [[#2600](https://github.com/falcosecurity/falco/pull/2600)] - [@FedeDP](https://github.com/FedeDP)
* cleanup(docs): adjust falco readme style and content [[#2594](https://github.com/falcosecurity/falco/pull/2594)] - [@incertum](https://github.com/incertum)
* cleanup(userspace, config): improve metrics UX, add include_empty_values option [[#2593](https://github.com/falcosecurity/falco/pull/2593)] - [@incertum](https://github.com/incertum)
* feat: add the curl and jq packages to the falco-no-driver docker image [[#2581](https://github.com/falcosecurity/falco/pull/2581)] - [@therealdwright](https://github.com/therealdwright)
* update: add missing exception, required_engine_version, required_plugin_version to -L json output [[#2584](https://github.com/falcosecurity/falco/pull/2584)] - [@loresuso](https://github.com/loresuso)
* feat: add image source OCI label to docker images [[#2592](https://github.com/falcosecurity/falco/pull/2592)] - [@therealdwright](https://github.com/therealdwright)
* cleanup(config): improve falco config [[#2571](https://github.com/falcosecurity/falco/pull/2571)] - [@incertum](https://github.com/incertum)
* update(cmake): bump libs and plugins to latest dev versions [[#2586](https://github.com/falcosecurity/falco/pull/2586)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore(userspace/falco): always print invalid syscalls from custom set [[#2578](https://github.com/falcosecurity/falco/pull/2578)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(build): upgrade falcoctl to 0.5.0 [[#2572](https://github.com/falcosecurity/falco/pull/2572)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(userspace/falco/app): print all supported plugin caps [[#2564](https://github.com/falcosecurity/falco/pull/2564)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: get rules details with `-l` or `-L` flags when json output format is specified [[#2544](https://github.com/falcosecurity/falco/pull/2544)] - [@loresuso](https://github.com/loresuso)
* update!: bump libs version, and support latest plugin features, add --nodriver option [[#2552](https://github.com/falcosecurity/falco/pull/2552)] - [@jasondellaluce](https://github.com/jasondellaluce)
* cleanup(actions): now modern bpf support `-A` flag [[#2551](https://github.com/falcosecurity/falco/pull/2551)] - [@Andreagit97](https://github.com/Andreagit97)
* update: `falco-driver-loader` now uses now uses $TMPDIR if set [[#2518](https://github.com/falcosecurity/falco/pull/2518)] - [@jabdr](https://github.com/jabdr)
* update: improve control and UX of ignored events [[#2509](https://github.com/falcosecurity/falco/pull/2509)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: bump libs and adapt Falco to new libsinsp event source management [[#2507](https://github.com/falcosecurity/falco/pull/2507)] - [@jasondellaluce](https://github.com/jasondellaluce)
* new(app_actions)!: adjust base_syscalls option, add base_syscalls.repair [[#2457](https://github.com/falcosecurity/falco/pull/2457)] - [@incertum](https://github.com/incertum)
* update(scripts): support al2022 and al2023 in falco-driver-loader. [[#2494](https://github.com/falcosecurity/falco/pull/2494)] - [@FedeDP](https://github.com/FedeDP)
* update: sync libs with newest event name APIs [[#2471](https://github.com/falcosecurity/falco/pull/2471)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update!: remove `--mesos-api`, `-pmesos`, and `-pm` command-line flags [[#2465](https://github.com/falcosecurity/falco/pull/2465)] - [@leogr](https://github.com/leogr)
* cleanup(unit_tests): try making test_configure_interesting_sets more robust [[#2464](https://github.com/falcosecurity/falco/pull/2464)] - [@incertum](https://github.com/incertum)


### Bug Fixes

* fix: unquote quoted URL's to avoid libcurl errors [[#2596](https://github.com/falcosecurity/falco/pull/2596)] - [@therealdwright](https://github.com/therealdwright)
* fix(userspace/engine): store alternatives as array in -L json output [[#2597](https://github.com/falcosecurity/falco/pull/2597)] - [@loresuso](https://github.com/loresuso)
* fix(userspace/engine): store required engine version as string in -L json output [[#2595](https://github.com/falcosecurity/falco/pull/2595)] - [@loresuso](https://github.com/loresuso)
* fix(userspace/falco): report plugin deps rules issues in any case [[#2589](https://github.com/falcosecurity/falco/pull/2589)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace): hotreload on wrong metrics [[#2582](https://github.com/falcosecurity/falco/pull/2582)] - [@therealbobo](https://github.com/therealbobo)
* fix(userspace): check the supported number of online CPUs with modern bpf [[#2575](https://github.com/falcosecurity/falco/pull/2575)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/falco): don't hang on terminating error when multi sourcing [[#2576](https://github.com/falcosecurity/falco/pull/2576)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/falco): properly format numeric values in metrics [[#2569](https://github.com/falcosecurity/falco/pull/2569)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(scripts): properly support debian kernel releases embedded in kernel version [[#2377](https://github.com/falcosecurity/falco/pull/2377)] - [@FedeDP](https://github.com/FedeDP)



### Non user-facing changes

* docs(README.md): add scope/status badge and simply doc structure [[#2611](https://github.com/falcosecurity/falco/pull/2611)] - [@leogr](https://github.com/leogr)
* build(deps): Bump submodules/falcosecurity-rules from `3471984` to `16fb709` [[#2598](https://github.com/falcosecurity/falco/pull/2598)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* docs(proposals): Falco roadmap management [[#2547](https://github.com/falcosecurity/falco/pull/2547)] - [@leogr](https://github.com/leogr)
* build(deps): Bump submodules/falcosecurity-rules from `b2290ad` to `3471984` [[#2577](https://github.com/falcosecurity/falco/pull/2577)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* update(build): libs 0.11.0-rc2 [[#2573](https://github.com/falcosecurity/falco/pull/2573)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `3f52480` to `b2290ad` [[#2570](https://github.com/falcosecurity/falco/pull/2570)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* update(ci): use repo instead of master branch for reusable workflows [[#2568](https://github.com/falcosecurity/falco/pull/2568)] - [@LucaGuerra](https://github.com/LucaGuerra)
* cleanup(ci): cleaned up circleci workflow. [[#2566](https://github.com/falcosecurity/falco/pull/2566)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump requests from 2.26.0 to 2.31.0 in /test [[#2567](https://github.com/falcosecurity/falco/pull/2567)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(ci): simplify and fix multi-arch image publishing process [[#2542](https://github.com/falcosecurity/falco/pull/2542)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): get the manifest for the correct tag [[#2563](https://github.com/falcosecurity/falco/pull/2563)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `3f52480` to `6da15ae` [[#2559](https://github.com/falcosecurity/falco/pull/2559)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(ci): properly use `docker save` to store images. [[#2560](https://github.com/falcosecurity/falco/pull/2560)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): docker arg is named `TARGETARCH`. [[#2558](https://github.com/falcosecurity/falco/pull/2558)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): set docker TARGET_ARCH [[#2557](https://github.com/falcosecurity/falco/pull/2557)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): use normal docker to build docker images, instead of buildx. [[#2556](https://github.com/falcosecurity/falco/pull/2556)] - [@FedeDP](https://github.com/FedeDP)
* docs: improve documentation and description of base_syscalls option [[#2515](https://github.com/falcosecurity/falco/pull/2515)] - [@Happy-Dude](https://github.com/Happy-Dude)
* Updating Falco branding guidelines [[#2493](https://github.com/falcosecurity/falco/pull/2493)] - [@aijamalnk](https://github.com/aijamalnk)
* build(deps): Bump submodules/falcosecurity-rules from `f773578` to `6da15ae` [[#2553](https://github.com/falcosecurity/falco/pull/2553)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* fix(cmake): properly exclude prereleases when fetching latest tag from cmake [[#2550](https://github.com/falcosecurity/falco/pull/2550)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): load falco image before building falco-driver-loader [[#2549](https://github.com/falcosecurity/falco/pull/2549)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): correctly tag slim manifest [[#2545](https://github.com/falcosecurity/falco/pull/2545)] - [@LucaGuerra](https://github.com/LucaGuerra)
* cleanup(config): modern bpf is no more experimental [[#2538](https://github.com/falcosecurity/falco/pull/2538)] - [@Andreagit97](https://github.com/Andreagit97)
* new(ci): add RC/prerelease support [[#2533](https://github.com/falcosecurity/falco/pull/2533)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): configure ECR public region [[#2531](https://github.com/falcosecurity/falco/pull/2531)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): falco images directory, ecr login [[#2528](https://github.com/falcosecurity/falco/pull/2528)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): separate rpm/bin/bin-static/deb packages before publication, rename bin-static [[#2527](https://github.com/falcosecurity/falco/pull/2527)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): add Cloudfront Distribution ID [[#2525](https://github.com/falcosecurity/falco/pull/2525)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): escape heredoc [[#2521](https://github.com/falcosecurity/falco/pull/2521)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(ci): build-musl-package does not need to wait for build-packages anymore [[#2520](https://github.com/falcosecurity/falco/pull/2520)] - [@FedeDP](https://github.com/FedeDP)
* fix: ci Falco version [[#2516](https://github.com/falcosecurity/falco/pull/2516)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): fetch version step, download rpms/debs, minor change [[#2519](https://github.com/falcosecurity/falco/pull/2519)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(ci): properly install recent version of git (needed >= 2.18 by checkout action) [[#2514](https://github.com/falcosecurity/falco/pull/2514)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): enable toolset before every make command [[#2513](https://github.com/falcosecurity/falco/pull/2513)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): remove unnecessary mv [[#2512](https://github.com/falcosecurity/falco/pull/2512)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): bucket -> bucket_suffix [[#2511](https://github.com/falcosecurity/falco/pull/2511)] - [@LucaGuerra](https://github.com/LucaGuerra)
* build(deps): Bump submodules/falcosecurity-rules from `5857874` to `1bd7e4a` [[#2478](https://github.com/falcosecurity/falco/pull/2478)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `694adf5` to `5857874` [[#2473](https://github.com/falcosecurity/falco/pull/2473)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* cleanup(ci): properly set a concurrency for CI workflows. [[#2470](https://github.com/falcosecurity/falco/pull/2470)] - [@FedeDP](https://github.com/FedeDP)
* build(deps): Bump submodules/falcosecurity-rules from `e0646a0` to `694adf5` [[#2466](https://github.com/falcosecurity/falco/pull/2466)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* build(deps): Bump submodules/falcosecurity-rules from `0b0f50f` to `e0646a0` [[#2460](https://github.com/falcosecurity/falco/pull/2460)] - [@dependabot[bot]](https://github.com/apps/dependabot)

## v0.34.1

Released on 2023-02-20

### Minor Changes

* fix(userspace/engine): correctly bump FALCO_ENGINE_VERSION after introduction of new fields [[#2418](https://github.com/falcosecurity/falco/pull/2418)] - [@loresuso](https://github.com/loresuso/)

### Non user-facing changes

* fix(dockerfile/no-driver): install ca-certificates [[#2412](https://github.com/falcosecurity/falco/pull/2412)] - [@alacuku](https://github.com/alacuku)

## v0.34.0

Released on 2023-02-07

### Major Changes

* BREAKING CHANGE: if you relied upon `application_rules.yaml` you can download it from https://github.com/falcosecurity/rules/tree/main/rules and manually install it. [[#2389](https://github.com/falcosecurity/falco/pull/2389)] - [@leogr](https://github.com/leogr)

* new(rules): New rule to detect attempts to inject code into a process using PTRACE [[#2226](https://github.com/falcosecurity/falco/pull/2226)] - [@Brucedh](https://github.com/Brucedh)
* new(engine): Also include exact locations for rule condition compile errors (missing macros, etc). [[#2216](https://github.com/falcosecurity/falco/pull/2216)] - [@mstemm](https://github.com/mstemm)
* new(scripts): Support older RHEL distros in falco-driver-loader script [[#2312](https://github.com/falcosecurity/falco/pull/2312)] - [@gentooise](https://github.com/gentooise)
* new(scripts): add `falcoctl` config into Falco package [[#2390](https://github.com/falcosecurity/falco/pull/2390)] - [@Andreagit97](https://github.com/Andreagit97)
* new(userspace/falco): [EXPERIMENTAL] allow modern bpf probe to assign more than one CPU to a single ring buffer [[#2363](https://github.com/falcosecurity/falco/pull/2363)] - [@Andreagit97](https://github.com/Andreagit97)
* new(userspace/falco): add webserver endpoint for retrieving internal version numbers [[#2356](https://github.com/falcosecurity/falco/pull/2356)] - [@jasondellaluce](https://github.com/jasondellaluce)
* new(falco): add --version-json to print version information in json format [[#2331](https://github.com/falcosecurity/falco/pull/2331)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(scripts): support multiple drivers in systemd units [[#2242](https://github.com/falcosecurity/falco/pull/2242)] - [@FedeDP](https://github.com/FedeDP)
* new(scripts): add bottlerocket support in falco-driver-loader [[#2318](https://github.com/falcosecurity/falco/pull/2318)] - [@FedeDP](https://github.com/FedeDP)
* new(falco): add more version fields to --support and --version [[#2325](https://github.com/falcosecurity/falco/pull/2325)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(config): explicitly add the `simulate_drops` config [[#2260](https://github.com/falcosecurity/falco/pull/2260)] - [@Andreagit97](https://github.com/Andreagit97)


### Minor Changes

* build: upgrade to `falcoctl` v0.4.0 [[#2406](https://github.com/falcosecurity/falco/pull/2406)] - [@loresuso](https://github.com/loresuso)
* update(userspace): change `modern_bpf.cpus_for_each_syscall_buffer` default value [[#2404](https://github.com/falcosecurity/falco/pull/2404)] - [@Andreagit97](https://github.com/Andreagit97)
* update(build): update falcoctl to 0.3.0 [[#2401](https://github.com/falcosecurity/falco/pull/2401)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(build): update falcoctl to 0.3.0-rc7 [[#2396](https://github.com/falcosecurity/falco/pull/2396)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(cmake): bump libs to 0.10.3 [[#2392](https://github.com/falcosecurity/falco/pull/2392)] - [@FedeDP](https://github.com/FedeDP)
* build: `/etc/falco/rules.available` has been deprecated [[#2389](https://github.com/falcosecurity/falco/pull/2389)] - [@leogr](https://github.com/leogr)
* build: `application_rules.yaml` is not shipped anymore with Falco [[#2389](https://github.com/falcosecurity/falco/pull/2389)] - [@leogr](https://github.com/leogr)
* build: upgrade k8saudit plugin to v0.5.0 [[#2381](https://github.com/falcosecurity/falco/pull/2381)] - [@leogr](https://github.com/leogr)
* build: upgrade cloudtrail plugin to v0.6.0 [[#2381](https://github.com/falcosecurity/falco/pull/2381)] - [@leogr](https://github.com/leogr)
* new!: ship falcoctl inside Falco [[#2345](https://github.com/falcosecurity/falco/pull/2345)] - [@FedeDP](https://github.com/FedeDP)
* refactor: remove rules and add submodule to falcosecurity/rules [[#2359](https://github.com/falcosecurity/falco/pull/2359)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(scripts): add option for regenerating signatures of all dev and release packages [[#2364](https://github.com/falcosecurity/falco/pull/2364)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: print JSON version output when json_output is enabled [[#2351](https://github.com/falcosecurity/falco/pull/2351)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(cmake): updated libs to 0.10.1 tag. [[#2362](https://github.com/falcosecurity/falco/pull/2362)] - [@FedeDP](https://github.com/FedeDP)
* Install the certificates of authorities in falco:no-driver docker image [[#2355](https://github.com/falcosecurity/falco/pull/2355)] - [@Issif](https://github.com/Issif)
* update: Mesos support is now deprecated and will be removed in the next version. [[#2328](https://github.com/falcosecurity/falco/pull/2328)] - [@leogr](https://github.com/leogr)
* update(scripts/falco-driver-loader): optimize the resiliency of module download script for air-gapped environments [[#2336](https://github.com/falcosecurity/falco/pull/2336)] - [@Dentrax](https://github.com/Dentrax)
* doc(userspace): provide users with a correct message when some syscalls are not defined [[#2329](https://github.com/falcosecurity/falco/pull/2329)] - [@Andreagit97](https://github.com/Andreagit97)
* update(ci): update ci jobs to generate Falco images with the modern BPF probe [[#2320](https://github.com/falcosecurity/falco/pull/2320)] - [@Andreagit97](https://github.com/Andreagit97)
* rules: add Falco container lists [[#2290](https://github.com/falcosecurity/falco/pull/2290)] - [@oscr](https://github.com/oscr)
* rules(macro: private_key_or_password): now also check for OpenSSH private keys [[#2284](https://github.com/falcosecurity/falco/pull/2284)] - [@oscr](https://github.com/oscr)
* update(cmake): bump libs and driver to latest RC. [[#2302](https://github.com/falcosecurity/falco/pull/2302)] - [@FedeDP](https://github.com/FedeDP)
* Ensure that a ruleset object is copied properly in falco_engine::add_source(). [[#2271](https://github.com/falcosecurity/falco/pull/2271)] - [@mstemm](https://github.com/mstemm)
* update(userspace/falco): enable using zlib with webserver [[#2125](https://github.com/falcosecurity/falco/pull/2125)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(falco): add container-gvisor and kubernetes-gvisor print options [[#2288](https://github.com/falcosecurity/falco/pull/2288)] - [@LucaGuerra](https://github.com/LucaGuerra)
* cleanup: always use bundled libz and libelf in BUNDLED_DEPS mode. [[#2277](https://github.com/falcosecurity/falco/pull/2277)] - [@FedeDP](https://github.com/FedeDP)
* update: updated libs and driver to version dd443b67c6b04464cb8ee2771af8ada8777e7fac [[#2277](https://github.com/falcosecurity/falco/pull/2277)] - [@FedeDP](https://github.com/FedeDP)
* update(falco.yaml): `open_params` under plugins configuration is now trimmed from surrounding whitespace [[#2267](https://github.com/falcosecurity/falco/pull/2267)] - [@yardenshoham](https://github.com/yardenshoham)


### Bug Fixes

* fix(engine): Avoid crash related to caching syscall source when the falco engine uses multiple sources at the same time. [[#2272](https://github.com/falcosecurity/falco/pull/2272)] - [@mstemm](https://github.com/mstemm)
* fix(scripts): use falco-driver-loader only into install scripts [[#2391](https://github.com/falcosecurity/falco/pull/2391)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/falco): fix grpc server shutdown [[#2350](https://github.com/falcosecurity/falco/pull/2350)] - [@FedeDP](https://github.com/FedeDP)
* fix(docker/falco): trust latest GPG key [[#2365](https://github.com/falcosecurity/falco/pull/2365)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/engine): improve rule loading validation results [[#2344](https://github.com/falcosecurity/falco/pull/2344)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix: graceful error handling for macros/lists reference loops [[#2311](https://github.com/falcosecurity/falco/pull/2311)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Rule Changes

* rules(tagging): enhanced rules tagging for inventory / threat modeling [[#2167](https://github.com/falcosecurity/falco/pull/2167)] - [@incertum](https://github.com/incertum)
* rule(Outbound Connection to C2 Server): Update the "Outbound connection to C2 server" rule to match both FQDN and IP addresses. Prior to this change, the rule only matched IP addresses and not FQDN. [[#2241](https://github.com/falcosecurity/falco/pull/2241)] - [@Nicolas-Peiffer](https://github.com/Nicolas-Peiffer)
* rule(Execution from /dev/shm): new rule to detect execution from /dev/shm [[#2225](https://github.com/falcosecurity/falco/pull/2225)] - [@AlbertoPellitteri](https://github.com/AlbertoPellitteri)
* rule(Find AWS Credentials): new rule to detect executions looking for AWS credentials [[#2224](https://github.com/falcosecurity/falco/pull/2224)] - [@AlbertoPellitteri](https://github.com/AlbertoPellitteri)
* rule(Linux Kernel Module Injection Detected): improve insmod detection within container using CAP_SYS_MODULE [[#2305](https://github.com/falcosecurity/falco/pull/2305)] - [@loresuso](https://github.com/loresuso)
* rule(Read sensitive file untrusted): let salt-call read sensitive files [[#2291](https://github.com/falcosecurity/falco/pull/2291)] - [@vin01](https://github.com/vin01)
* rule(macro: rpm_procs): let salt-call write to rpm database [[#2291](https://github.com/falcosecurity/falco/pull/2291)] - [@vin01](https://github.com/vin01)


### Non user-facing changes

* fix(ci): fix rpm sign job dependencies [[#2324](https://github.com/falcosecurity/falco/pull/2324)] - [@cappellinsamuele](https://github.com/cappellinsamuele)
* chore(userspace): add `njson` lib as a dependency for `falco_engine` [[#2316](https://github.com/falcosecurity/falco/pull/2316)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(scripts): force rpm postinstall script to always show dialog, even on upgrade [[#2405](https://github.com/falcosecurity/falco/pull/2405)] - [@FedeDP](https://github.com/FedeDP)
* fix(scripts): fixed falcoctl config install dir. [[#2399](https://github.com/falcosecurity/falco/pull/2399)] - [@FedeDP](https://github.com/FedeDP)
* fix(scripts): make /usr writable [[#2398](https://github.com/falcosecurity/falco/pull/2398)] - [@therealbobo](https://github.com/therealbobo)
* fix(scripts): driver loader insmod [[#2388](https://github.com/falcosecurity/falco/pull/2388)] - [@FedeDP](https://github.com/FedeDP)
* update(systemd): solve some issues with systemd unit [[#2385](https://github.com/falcosecurity/falco/pull/2385)] - [@Andreagit97](https://github.com/Andreagit97)
* build(cmake): upgrade falcoctl to v0.3.0-rc6 [[#2383](https://github.com/falcosecurity/falco/pull/2383)] - [@leogr](https://github.com/leogr)
* docs(.github): rules are no longer in this repo [[#2382](https://github.com/falcosecurity/falco/pull/2382)] - [@leogr](https://github.com/leogr)
* update(CI): mitigate frequent failure in CircleCI jobs [[#2375](https://github.com/falcosecurity/falco/pull/2375)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace): use the right path for the `cpus_for_each_syscall_buffer` config [[#2378](https://github.com/falcosecurity/falco/pull/2378)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(scripts): fixed incorrect bash var expansion [[#2367](https://github.com/falcosecurity/falco/pull/2367)] - [@therealbobo](https://github.com/therealbobo)
* update(CI): upgrade toolchain in modern falco builder dockerfile [[#2337](https://github.com/falcosecurity/falco/pull/2337)] - [@Andreagit97](https://github.com/Andreagit97)
* cleanup(ci): move static analysis job from circle CI to GHA [[#2332](https://github.com/falcosecurity/falco/pull/2332)] - [@Andreagit97](https://github.com/Andreagit97)
* update(falco): update cpp-httplib to 0.11.3 [[#2327](https://github.com/falcosecurity/falco/pull/2327)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(script): makes user able to pass custom option to driver-loade… [[#1901](https://github.com/falcosecurity/falco/pull/1901)] - [@andreabonanno](https://github.com/andreabonanno)
* cleanup(ci): remove some unused jobs and remove some `falco-builder` reference where possible [[#2322](https://github.com/falcosecurity/falco/pull/2322)] - [@Andreagit97](https://github.com/Andreagit97)
* docs(proposal): new artifacts distribution proposal [[#2304](https://github.com/falcosecurity/falco/pull/2304)] - [@leogr](https://github.com/leogr)
* fix(cmake): properly fetch dev version by appending latest Falco tag, delta between master and tag, and hash [[#2292](https://github.com/falcosecurity/falco/pull/2292)] - [@FedeDP](https://github.com/FedeDP)
* chore(deps): Bump certifi from 2020.4.5.1 to 2022.12.7 in /test [[#2313](https://github.com/falcosecurity/falco/pull/2313)] - [@dependabot[bot]](https://github.com/apps/dependabot)
* chore: remove string view lite [[#2307](https://github.com/falcosecurity/falco/pull/2307)] - [@leogr](https://github.com/leogr)
* new(CHANGELOG): add entry for 0.33.1 (in master branch this time) [[#2303](https://github.com/falcosecurity/falco/pull/2303)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update(docs): add overview and versioning sections to falco release.md [[#2205](https://github.com/falcosecurity/falco/pull/2205)] - [@incertum](https://github.com/incertum)
* Add Xenit AB to adopters [[#2285](https://github.com/falcosecurity/falco/pull/2285)] - [@NissesSenap](https://github.com/NissesSenap)
* fix(userspace/falco): verify engine fields only for syscalls [[#2281](https://github.com/falcosecurity/falco/pull/2281)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(output): do not print syscall_buffer_size when gvisor is enabled [[#2283](https://github.com/falcosecurity/falco/pull/2283)] - [@alacuku](https://github.com/alacuku)
* fix(engine): fix warning about redundant std::move [[#2286](https://github.com/falcosecurity/falco/pull/2286)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(scripts): force falco-driver-loader script to try to compile the driver anyway even on unsupported platforms [[#2219](https://github.com/falcosecurity/falco/pull/2219)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): fixed version bucket for release jobs. [[#2266](https://github.com/falcosecurity/falco/pull/2266)] - [@FedeDP](https://github.com/FedeDP)

## v0.33.1

Released on 2022-11-24

### Minor Changes

* update(falco): fix container-gvisor and kubernetes-gvisor print options [[#2288](https://github.com/falcosecurity/falco/pull/2288)]
* Update libs to 0.9.2, fixing potential CLBO on gVisor+Kubernetes and crash with eBPF when some CPUs are offline [[#2299](https://github.com/falcosecurity/falco/pull/2299)] - [@LucaGuerra](https://github.com/LucaGuerra)

## v0.33.0

Released on 2022-10-19

### Major Changes


* new: add a `drop_pct` referred to the global number of events [[#2130](https://github.com/falcosecurity/falco/pull/2130)] - [@Andreagit97](https://github.com/Andreagit97)
* new: print some info about eBPF and enabled sources when Falco starts [[#2133](https://github.com/falcosecurity/falco/pull/2133)] - [@Andreagit97](https://github.com/Andreagit97)
* new(userspace): print architecture information [[#2147](https://github.com/falcosecurity/falco/pull/2147)] - [@Andreagit97](https://github.com/Andreagit97)
* new(CI): add CodeQL security scanning to Falco. [[#2171](https://github.com/falcosecurity/falco/pull/2171)] - [@Andreagit97](https://github.com/Andreagit97)
* new: configure syscall buffer dimension from Falco [[#2214](https://github.com/falcosecurity/falco/pull/2214)] - [@Andreagit97](https://github.com/Andreagit97)
* new(cmdline): add development support for modern BPF probe [[#2221](https://github.com/falcosecurity/falco/pull/2221)] - [@Andreagit97](https://github.com/Andreagit97)
* new(falco-driver-loader): `DRIVERS_REPO` now supports the use of multiple download URLs (comma separated) [[#2165](https://github.com/falcosecurity/falco/pull/2165)] - [@IanRobertson-wpe](https://github.com/IanRobertson-wpe)
* new(userspace/engine): support alternative plugin version requirements in checks [[#2190](https://github.com/falcosecurity/falco/pull/2190)] - [@jasondellaluce](https://github.com/jasondellaluce)
* new: support running multiple event sources in parallel [[#2182](https://github.com/falcosecurity/falco/pull/2182)] - [@jasondellaluce](https://github.com/jasondellaluce)
* new(userspace/falco): automatically create paths for grpc unix socket and gvisor endpoint. [[#2189](https://github.com/falcosecurity/falco/pull/2189)] - [@FedeDP](https://github.com/FedeDP)
* new(scripts): allow falco-driver-loader to properly distinguish any ubuntu flavor [[#2178](https://github.com/falcosecurity/falco/pull/2178)] - [@FedeDP](https://github.com/FedeDP)
* new: add option to enable event sources selectively [[#2085](https://github.com/falcosecurity/falco/pull/2085)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Minor Changes

* docs(falco-driver-loader): add some comments in `falco-driver-loader` [[#2153](https://github.com/falcosecurity/falco/pull/2153)] - [@Andreagit97](https://github.com/Andreagit97)
* update(cmake): use latest libs tag `0.9.0` [[#2257](https://github.com/falcosecurity/falco/pull/2257)] - [@Andreagit97](https://github.com/Andreagit97)
* update(.circleci): re-enabled cppcheck [[#2186](https://github.com/falcosecurity/falco/pull/2186)] - [@leogr](https://github.com/leogr)
* update(userspace/engine): improve falco files loading performance [[#2151](https://github.com/falcosecurity/falco/pull/2151)] - [@VadimZy](https://github.com/VadimZy)
* update(cmake): use latest driver tag 3.0.1+driver [[#2251](https://github.com/falcosecurity/falco/pull/2251)] - [@Andreagit97](https://github.com/Andreagit97)
* update(userspace/falco)!: adapt stats writer for multiple parallel event sources [[#2182](https://github.com/falcosecurity/falco/pull/2182)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): remove falco engine APIs that returned a required_engine_version [[#2096](https://github.com/falcosecurity/falco/pull/2096)] - [@mstemm](https://github.com/mstemm)
* update(userspace/engine): add some small changes to rules matching that reduce cpu usage with high event volumes (> 1M syscalls/sec) [[#2210](https://github.com/falcosecurity/falco/pull/2210)] - [@mstemm](https://github.com/mstemm)
* rules: added process IDs to default rules [[#2211](https://github.com/falcosecurity/falco/pull/2211)] - [@spyder-kyle](https://github.com/spyder-kyle)
* update(scripts/debian): falco.service systemd unit is now cleaned-up during (re)install and removal via the DEB and RPM packages [[#2138](https://github.com/falcosecurity/falco/pull/2138)] - [@Happy-Dude](https://github.com/Happy-Dude)
* update(userspace/falco): move on from deprecated libs API for printing event list [[#2253](https://github.com/falcosecurity/falco/pull/2253)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore(userspace/falco): improve cli helper and log options with debug level [[#2252](https://github.com/falcosecurity/falco/pull/2252)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace): minor pre-release improvements [[#2236](https://github.com/falcosecurity/falco/pull/2236)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: bumped libs to fd46dd139a8e35692a7d40ab2f0ed2016df827cf. [[#2201](https://github.com/falcosecurity/falco/pull/2201)] - [@FedeDP](https://github.com/FedeDP)
* update!: gVisor sock default path changed from `/tmp/gvisor.sock` to `/run/falco/gvisor.sock`  [[#2163](https://github.com/falcosecurity/falco/pull/2163)] - [@vjjmiras](https://github.com/vjjmiras)
* update!: gRPC server sock default path changed from `/run/falco.sock.sock` to `/run/falco/falco.sock` [[#2163](https://github.com/falcosecurity/falco/pull/2163)] - [@vjjmiras](https://github.com/vjjmiras)
* update(scripts/falco-driver-loader): minikube environment is now correctly detected [[#2191](https://github.com/falcosecurity/falco/pull/2191)] - [@alacuku](https://github.com/alacuku)
* update(rules/falco_rules.yaml): `required_engine_version` changed to 13 [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* refactor(userspace/falco): re-design stats writer and make it thread-safe [[#2109](https://github.com/falcosecurity/falco/pull/2109)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/falco): make signal handlers thread safe [[#2091](https://github.com/falcosecurity/falco/pull/2091)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): strengthen and document thread-safety guarantees of falco_engine::process_event [[#2082](https://github.com/falcosecurity/falco/pull/2082)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace/falco): make webserver threadiness configurable [[#2090](https://github.com/falcosecurity/falco/pull/2090)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/falco): reduce app actions dependency on app state and inspector [[#2097](https://github.com/falcosecurity/falco/pull/2097)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace/falco): use move semantics in falco logger [[#2095](https://github.com/falcosecurity/falco/pull/2095)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: use `FALCO_HOSTNAME` env var to override the hostname value [[#2174](https://github.com/falcosecurity/falco/pull/2174)] - [@leogr](https://github.com/leogr)
* update: bump libs and driver versions to 6599e2efebce30a95f27739d655d53f0d5f686e4 [[#2177](https://github.com/falcosecurity/falco/pull/2177)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/falco): make output rate limiter optional and output engine explicitly thread-safe [[#2139](https://github.com/falcosecurity/falco/pull/2139)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(falco.yaml)!: notification rate limiter disabled by default. [[#2139](https://github.com/falcosecurity/falco/pull/2139)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Bug Fixes

* fix: compute the `drop ratio` in the right way [[#2128](https://github.com/falcosecurity/falco/pull/2128)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(falco_service): falco service needs to write under /sys/module/falco [[#2238](https://github.com/falcosecurity/falco/pull/2238)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace): cleanup output of ruleset validation result [[#2248](https://github.com/falcosecurity/falco/pull/2248)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace): properly print ignored syscalls messages when not in `-A` mode [[#2243](https://github.com/falcosecurity/falco/pull/2243)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(falco): clarify pid/tid and container info in gvisor [[#2223](https://github.com/falcosecurity/falco/pull/2223)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(userspace/engine): avoid reading duplicate exception values [[#2200](https://github.com/falcosecurity/falco/pull/2200)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix: hostname was not present when `json_output: true` [[#2174](https://github.com/falcosecurity/falco/pull/2174)] - [@leogr](https://github.com/leogr)


### Rule Changes

* rule(macro: known_gke_mount_in_privileged_containers): add new macro [[#2198](https://github.com/falcosecurity/falco/pull/2198)] - [@hi120ki](https://github.com/hi120ki)
* rule(Mount Launched in Privileged Container): add GKE default pod into allowlist in Mount Launched of Privileged Container rule [[#2198](https://github.com/falcosecurity/falco/pull/2198)] - [@hi120ki](https://github.com/hi120ki)
* rule(list: known_binaries_to_read_environment_variables_from_proc_files): add new list [[#2193](https://github.com/falcosecurity/falco/pull/2193)] - [@hi120ki](https://github.com/hi120ki)
* rule(Read environment variable from /proc files): add rule to detect an attempt to read process environment variables from /proc files [[#2193](https://github.com/falcosecurity/falco/pull/2193)] - [@hi120ki](https://github.com/hi120ki)
* rule(macro: k8s_containers): add falco no-driver images [[#2234](https://github.com/falcosecurity/falco/pull/2234)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(macro: open_file_failed): add new macro [[#2118](https://github.com/falcosecurity/falco/pull/2118)] - [@incertum](https://github.com/incertum)
* rule(macro: directory_traversal): add new macro [[#2118](https://github.com/falcosecurity/falco/pull/2118)] - [@incertum](https://github.com/incertum)
* rule(Directory traversal monitored file read): add new rule [[#2118](https://github.com/falcosecurity/falco/pull/2118)] - [@incertum](https://github.com/incertum)
* rule(Modify Container Entrypoint): new rule created to detect CVE-2019-5736 [[#2188](https://github.com/falcosecurity/falco/pull/2188)] - [@darryk10](https://github.com/darryk10)
* rule(Program run with disallowed http proxy env)!: disabled by default [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* rule(Container Drift Detected (chmod))!: disabled by default [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* rule(Container Drift Detected (open+create))!: disabled by default [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* rule(Packet socket created in container)!: removed consider_packet_socket_communication macro [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_packet_socket_communication)!: remove unused macro [[#2179](https://github.com/falcosecurity/falco/pull/2179)] - [@incertum](https://github.com/incertum)
* rule(Interpreted procs outbound network activity)!: disabled by default [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(Interpreted procs inbound network activity)!: disabled by default [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(Contact cloud metadata service from container)!: disabled by default [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_interpreted_outbound)!: remove unused macro [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_interpreted_inbound)!: remove unused macro [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_metadata_access)!: remove unused macro [[#2166](https://github.com/falcosecurity/falco/pull/2166)] - [@incertum](https://github.com/incertum)
* rule(Unexpected outbound connection destination)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Unexpected inbound connection source)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Read Shell Configuration File)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Schedule Cron Jobs)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Launch Suspicious Network Tool on Host)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Create Hidden Files or Directories)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Outbound or Inbound Traffic not to Authorized Server Process and Port)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Network Connection outside Local Subnet)!: disabled by default [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_all_outbound_conns)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_all_inbound_conns)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_shell_config_reads)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_all_cron_jobs)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_all_inbound_conns)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_hidden_file_creation)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: allowed_port)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: enabled_rule_network_only_subnet)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_userfaultfd_activities)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(macro: consider_all_chmods)!: remove unused macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Set Setuid or Setgid bit)!: removed consider_all_chmods macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Container Drift Detected (chmod))!: removed consider_all_chmods macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)
* rule(Unprivileged Delegation of Page Faults Handling to a Userspace Process)!: removed consider_userfaultfd_activities macro [[#2168](https://github.com/falcosecurity/falco/pull/2168)] - [@incertum](https://github.com/incertum)


### Non user-facing changes

* new(userspace): support `SCAP_FILTERED_EVENT` return code [[#2148](https://github.com/falcosecurity/falco/pull/2148)] - [@Andreagit97](https://github.com/Andreagit97)
* chore(test/utils): remove unused script [[#2157](https://github.com/falcosecurity/falco/pull/2157)] - [@Andreagit97](https://github.com/Andreagit97)
* Enrich pull request template [[#2162](https://github.com/falcosecurity/falco/pull/2162)] - [@Andreagit97](https://github.com/Andreagit97)
* vote: update(OWNERS): add Andrea Terzolo to owners [[#2185](https://github.com/falcosecurity/falco/pull/2185)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(CI): codespell should ignore `ro` word [[#2173](https://github.com/falcosecurity/falco/pull/2173)] - [@Andreagit97](https://github.com/Andreagit97)
* chore: bump plugin version [[#2256](https://github.com/falcosecurity/falco/pull/2256)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/falco): avoid using CPU when main thread waits for parallel event sources [[#2255](https://github.com/falcosecurity/falco/pull/2255)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(scripts): inject kmod script fails with some systemd versions [[#2250](https://github.com/falcosecurity/falco/pull/2250)] - [@Andreagit97](https://github.com/Andreagit97)
* chore(userspace/falco): make logging optional when terminating, restarting, and reopening outputs [[#2249](https://github.com/falcosecurity/falco/pull/2249)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore: bump libs version [[#2244](https://github.com/falcosecurity/falco/pull/2244)] - [@Andreagit97](https://github.com/Andreagit97)
* update(userspace): solve warnings and performance tips from cppcheck [[#2247](https://github.com/falcosecurity/falco/pull/2247)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/falco): make signal termination more robust with multi-threading [[#2235](https://github.com/falcosecurity/falco/pull/2235)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/falco): make termination and signal handlers more stable [[#2239](https://github.com/falcosecurity/falco/pull/2239)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace): safely check string bounded access [[#2237](https://github.com/falcosecurity/falco/pull/2237)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore: bump libs/driver to the latest release branch commit [[#2232](https://github.com/falcosecurity/falco/pull/2232)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/falco): check plugin requirements when validating rule files [[#2233](https://github.com/falcosecurity/falco/pull/2233)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace): add explicit constructors and initializations [[#2229](https://github.com/falcosecurity/falco/pull/2229)] - [@jasondellaluce](https://github.com/jasondellaluce)
* Add StackRox to adopters [[#2187](https://github.com/falcosecurity/falco/pull/2187)] - [@Molter73](https://github.com/Molter73)
* fix(process_events): check the return value of `open_live_inspector` [[#2215](https://github.com/falcosecurity/falco/pull/2215)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/engine): properly include stdexcept header to fix build. [[#2197](https://github.com/falcosecurity/falco/pull/2197)] - [@FedeDP](https://github.com/FedeDP)
* refactor(userspace/engine): split rule loader classes for a more testable design [[#2206](https://github.com/falcosecurity/falco/pull/2206)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore(OWNERS): cleanup inactive reviewer [[#2204](https://github.com/falcosecurity/falco/pull/2204)] - [@leogr](https://github.com/leogr)
* fix(circleci): falco-driver-loader image build must be done starting from just-pushed falco master image. [[#2194](https://github.com/falcosecurity/falco/pull/2194)] - [@FedeDP](https://github.com/FedeDP)
* Support condition parse errors in rule loading results [[#2155](https://github.com/falcosecurity/falco/pull/2155)] - [@mstemm](https://github.com/mstemm)
* docs: readme update [[#2183](https://github.com/falcosecurity/falco/pull/2183)] - [@leogr](https://github.com/leogr)
* cleanup: rename legacy references [[#2180](https://github.com/falcosecurity/falco/pull/2180)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): increase const coherence in falco engine [[#2081](https://github.com/falcosecurity/falco/pull/2081)] - [@jasondellaluce](https://github.com/jasondellaluce)
* Rules result handle multiple files [[#2158](https://github.com/falcosecurity/falco/pull/2158)] - [@mstemm](https://github.com/mstemm)
* fix: print full rule load errors/warnings without verbose/-v [[#2156](https://github.com/falcosecurity/falco/pull/2156)] - [@mstemm](https://github.com/mstemm)


## v0.32.2

Released on 2022-08-09

### Major Changes


### Bug Fixes

* fix: Added ARCH to bpf download URL [[#2142](https://github.com/falcosecurity/falco/pull/2142)] - [@eric-engberg](https://github.com/eric-engberg)


## v0.32.1

Released on 2022-07-11

### Major Changes

* new(falco): add gVisor support [[#2078](https://github.com/falcosecurity/falco/pull/2078)] - [@LucaGuerra](https://github.com/LucaGuerra)
* new(docker,scripts): add multiarch images and ARM64 packages [[#1990](https://github.com/falcosecurity/falco/pull/1990)] - [@FedeDP](https://github.com/FedeDP)


### Minor Changes

* update(build): Switch from RSA/SHA1 to RSA/SHA256 signature in the RPM package [[#2044](https://github.com/falcosecurity/falco/pull/2044)] - [@vjjmiras](https://github.com/vjjmiras)
* refactor(userspace/engine): drop macro source field in rules and rule loader [[#2094](https://github.com/falcosecurity/falco/pull/2094)] - [@jasondellaluce](https://github.com/jasondellaluce)
* build: introduce `DRIVER_VERSION` that allows setting a driver version (which may differ from the falcosecurity/libs version) [[#2086](https://github.com/falcosecurity/falco/pull/2086)] - [@leogr](https://github.com/leogr)
* update: add more info to `--version` output [[#2086](https://github.com/falcosecurity/falco/pull/2086)] - [@leogr](https://github.com/leogr)
* build(scripts): publish deb repo has now a InRelease file [[#2060](https://github.com/falcosecurity/falco/pull/2060)] - [@FedeDP](https://github.com/FedeDP)
* update(userspace/falco): make plugin init config optional and add --plugin-info CLI option [[#2059](https://github.com/falcosecurity/falco/pull/2059)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace/falco): support libs logging [[#2093](https://github.com/falcosecurity/falco/pull/2093)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(falco): update libs to 0.7.0 [[#2119](https://github.com/falcosecurity/falco/pull/2119)] - [@LucaGuerra](https://github.com/LucaGuerra)

### Bug Fixes

* fix(userspace/falco): ensure that only rules files named with `-V` are loaded when validating rules files. [[#2088](https://github.com/falcosecurity/falco/pull/2088)] - [@mstemm](https://github.com/mstemm)
* fix(rules): use exit event in reverse shell detection rule [[#2076](https://github.com/falcosecurity/falco/pull/2076)] - [@alacuku](https://github.com/alacuku)
* fix(scripts): falco-driver-loader script will now seek for drivers in driver/${ARCH}/ for x86_64 too. [[#2057](https://github.com/falcosecurity/falco/pull/2057)] - [@FedeDP](https://github.com/FedeDP)
* fix(falco-driver-loader): building falco module with DKMS on Flatcar and supporting fetching pre-built module/eBPF probe [[#2043](https://github.com/falcosecurity/falco/pull/2043)] - [@jepio](https://github.com/jepio)


### Rule Changes

* rule(Redirect STDOUT/STDIN to Network Connection in Container): changed priority to NOTICE [[#2092](https://github.com/falcosecurity/falco/pull/2092)] - [@leogr](https://github.com/leogr)
* rule(Java Process Class Download): detect potential log4shell exploitation [[#2041](https://github.com/falcosecurity/falco/pull/2041)] - [@pirxthepilot](https://github.com/pirxthepilot)


### Non user-facing changes

* remove kaizhe from falco rule owner [[#2050](https://github.com/falcosecurity/falco/pull/2050)] - [@Kaizhe](https://github.com/Kaizhe)
* docs(readme): added arm64 mention + packages + badge. [[#2101](https://github.com/falcosecurity/falco/pull/2101)] - [@FedeDP](https://github.com/FedeDP)
* new(circleci): enable integration tests for arm64. [[#2099](https://github.com/falcosecurity/falco/pull/2099)] - [@FedeDP](https://github.com/FedeDP)
* chore(cmake): bump plugins versions [[#2102](https://github.com/falcosecurity/falco/pull/2102)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(docker): fixed deb tester sub image. [[#2100](https://github.com/falcosecurity/falco/pull/2100)] - [@FedeDP](https://github.com/FedeDP)
* fix(ci): fix sign script - avoid interpreting '{*}$argv' too soon [[#2075](https://github.com/falcosecurity/falco/pull/2075)] - [@vjjmiras](https://github.com/vjjmiras)
* fix(tests): make tests run locally (take 2) [[#2089](https://github.com/falcosecurity/falco/pull/2089)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(ci): creates ~/sign instead of ./sign [[#2072](https://github.com/falcosecurity/falco/pull/2072)] - [@vjjmiras](https://github.com/vjjmiras)
* fix(ci): sign arm64 rpm packages. [[#2069](https://github.com/falcosecurity/falco/pull/2069)] - [@FedeDP](https://github.com/FedeDP)
* update(falco_scripts): Change Flatcar dynlinker path [[#2066](https://github.com/falcosecurity/falco/pull/2066)] - [@jepio](https://github.com/jepio)
* fix(scripts): fixed path in publish-deb script. [[#2062](https://github.com/falcosecurity/falco/pull/2062)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): docker-container buildx engine does not support retagging images. Tag all images together. [[#2058](https://github.com/falcosecurity/falco/pull/2058)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): fixed publish-docker-dev job context. [[#2056](https://github.com/falcosecurity/falco/pull/2056)] - [@FedeDP](https://github.com/FedeDP)
* Correct linting issue in rules [[#2055](https://github.com/falcosecurity/falco/pull/2055)] - [@stephanmiehe](https://github.com/stephanmiehe)
* Fix falco compilation issues with new libs [[#2053](https://github.com/falcosecurity/falco/pull/2053)] - [@alacuku](https://github.com/alacuku)
* fix(scripts): forcefully create packages dir for debian packages. [[#2054](https://github.com/falcosecurity/falco/pull/2054)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): removed leftover line in circleci config. [[#2052](https://github.com/falcosecurity/falco/pull/2052)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): fixed circleCI artifacts publish for arm64. [[#2051](https://github.com/falcosecurity/falco/pull/2051)] - [@FedeDP](https://github.com/FedeDP)
* update(docker): updated falco-builder to fix multiarch support. [[#2049](https://github.com/falcosecurity/falco/pull/2049)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): use apt instead of apk when installing deps for aws ecr publish [[#2047](https://github.com/falcosecurity/falco/pull/2047)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): try to use root user for cimg/base [[#2045](https://github.com/falcosecurity/falco/pull/2045)] - [@FedeDP](https://github.com/FedeDP)
* update(build): avoid double build of docker images when pushing to aws ecr [[#2046](https://github.com/falcosecurity/falco/pull/2046)] - [@FedeDP](https://github.com/FedeDP)
* chore(k8s_audit_plugin): bump k8s audit plugin version [[#2042](https://github.com/falcosecurity/falco/pull/2042)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(tests): make run_regression_tests.sh work locally [[#2020](https://github.com/falcosecurity/falco/pull/2020)] - [@LucaGuerra](https://github.com/LucaGuerra)
* Circle CI build job for ARM64 [[#1997](https://github.com/falcosecurity/falco/pull/1997)] - [@odidev](https://github.com/odidev)


## v0.32.0

Released on 2022-06-03

### Major Changes


* new: added new `watch_config_files` config option, to trigger a Falco restart whenever a change is detected in the rules or config files [[#1991](https://github.com/falcosecurity/falco/pull/1991)] - [@FedeDP](https://github.com/FedeDP)
* new(rules): add rule to detect excessively capable container [[#1963](https://github.com/falcosecurity/falco/pull/1963)] - [@loresuso](https://github.com/loresuso)
* new(rules): add rules to detect pods sharing host pid and IPC namespaces [[#1951](https://github.com/falcosecurity/falco/pull/1951)] - [@loresuso](https://github.com/loresuso)
* new(image): add Falco image based on RedHat UBI [[#1943](https://github.com/falcosecurity/falco/pull/1943)] - [@araujof](https://github.com/araujof)
* new(falco): add --markdown and --list-syscall-events [[#1939](https://github.com/falcosecurity/falco/pull/1939)] - [@LucaGuerra](https://github.com/LucaGuerra)


### Minor Changes

* update(build): updated plugins to latest versions. [[#2033](https://github.com/falcosecurity/falco/pull/2033)] - [@FedeDP](https://github.com/FedeDP)
* refactor(userspace/falco): split the currently monolithic falco_init into smaller "actions", managed by the falco application's action manager. [[#1953](https://github.com/falcosecurity/falco/pull/1953)] - [@mstemm](https://github.com/mstemm)
* rules: out of the box ruleset for OKTA Falco Plugin [[#1955](https://github.com/falcosecurity/falco/pull/1955)] - [@darryk10](https://github.com/darryk10)
* update(build): updated libs to 39ae7d40496793cf3d3e7890c9bbdc202263836b [[#2031](https://github.com/falcosecurity/falco/pull/2031)] - [@FedeDP](https://github.com/FedeDP)
* update!: moving out plugins ruleset files [[#1995](https://github.com/falcosecurity/falco/pull/1995)] - [@leogr](https://github.com/leogr)
* update: added `hostname` as a field in JSON output [[#1989](https://github.com/falcosecurity/falco/pull/1989)] - [@Milkshak3s](https://github.com/Milkshak3s)
* refactor!: remove K8S audit logs from Falco [[#1952](https://github.com/falcosecurity/falco/pull/1952)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): use supported_operators helper from libsinsp filter parser [[#1975](https://github.com/falcosecurity/falco/pull/1975)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor!: deprecate PSP regression tests and warn for unsafe usage of <NA> in k8s audit filters [[#1976](https://github.com/falcosecurity/falco/pull/1976)] - [@jasondellaluce](https://github.com/jasondellaluce)
* build(cmake): upgrade catch2 to 2.13.9 [[#1977](https://github.com/falcosecurity/falco/pull/1977)] - [@leogr](https://github.com/leogr)
* refactor(userspace/engine): reduce memory usage for resolving evttypes [[#1965](https://github.com/falcosecurity/falco/pull/1965)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): remove Lua from Falco and re-implement the rule loader [[#1966](https://github.com/falcosecurity/falco/pull/1966)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor(userspace/engine): decoupling ruleset reading, parsing, and compilation steps [[#1970](https://github.com/falcosecurity/falco/pull/1970)] - [@jasondellaluce](https://github.com/jasondellaluce)
* refactor: update definitions of falco_common [[#1967](https://github.com/falcosecurity/falco/pull/1967)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: improved Falco engine event processing performance [[#1944](https://github.com/falcosecurity/falco/pull/1944)] - [@deepskyblue86](https://github.com/deepskyblue86)
* refactor(userspace/engine): use libsinsp filter parser and compiler inside rule loader [[#1947](https://github.com/falcosecurity/falco/pull/1947)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Bug Fixes

* fix(userspace/engine): skip rules with unknown sources that also have exceptions, and skip macros with unknown sources. [[#1920](https://github.com/falcosecurity/falco/pull/1920)] - [@mstemm](https://github.com/mstemm)
* fix(userspace/falco): enable k8s and mesos clients only when syscall source is enabled [[#2019](https://github.com/falcosecurity/falco/pull/2019)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Rule Changes

* rule(Launch Excessively Capable Container): fix typo in description [[#1996](https://github.com/falcosecurity/falco/pull/1996)] - [@mmonitz](https://github.com/mmonitz)
* rule(macro: known_shell_spawn_cmdlines): add `sh -c /usr/share/lighttpd/create-mime.conf.pl` to macro [[#1996](https://github.com/falcosecurity/falco/pull/1996)] - [@mmonitz](https://github.com/mmonitz)
* rule(macro net_miner_pool): additional syscall for detection [[#2011](https://github.com/falcosecurity/falco/pull/2011)] - [@beryxz](https://github.com/beryxz)
* rule(macro truncate_shell_history): include .ash_history [[#1956](https://github.com/falcosecurity/falco/pull/1956)] - [@bdashrad](https://github.com/bdashrad)
* rule(macro modify_shell_history): include .ash_history [[#1956](https://github.com/falcosecurity/falco/pull/1956)] - [@bdashrad](https://github.com/bdashrad)
* rule(Detect release_agent File Container Escapes): new rule created to detect an attempt to exploit a container escape using release_agent file [[#1969](https://github.com/falcosecurity/falco/pull/1969)] - [@darryk10](https://github.com/darryk10)
* rule(k8s: secret): detect `get` attempts for both successful and unsuccessful attempts [[#1949](https://github.com/falcosecurity/falco/pull/1949)] - [@Dentrax](https://github.com/Dentrax)
* rule(K8s Serviceaccount Created/Deleted): Fixed output for the rules [[#1973](https://github.com/falcosecurity/falco/pull/1973)] - [@darryk10](https://github.com/darryk10)
* rule(Disallowed K8s User): exclude allowed EKS users [[#1960](https://github.com/falcosecurity/falco/pull/1960)] - [@darryk10](https://github.com/darryk10)
* rule(Launch Ingress Remote File Copy Tools in Container): Removed use cases not triggering the rule [[#1968](https://github.com/falcosecurity/falco/pull/1968)] - [@darryk10](https://github.com/darryk10)
* rule(Mount Launched in Privileged Container): added allowlist macro user_known_mount_in_privileged_containers. [[#1930](https://github.com/falcosecurity/falco/pull/1930)] - [@mmoyerfigma](https://github.com/mmoyerfigma)
* rule(macro user_known_shell_config_modifiers): allow to allowlist shell config modifiers [[#1938](https://github.com/falcosecurity/falco/pull/1938)] - [@claudio-vellage](https://github.com/claudio-vellage)


### Non user-facing changes

* new: update plugins [[#2023](https://github.com/falcosecurity/falco/pull/2023)] - [@FedeDP](https://github.com/FedeDP)
* update(build): updated libs version for Falco 0.32.0 release. [[#2022](https://github.com/falcosecurity/falco/pull/2022)] - [@FedeDP](https://github.com/FedeDP)
* update(build): updated libs to 1be924900a09cf2e4db4b4ae13d03d838959f350 [[#2024](https://github.com/falcosecurity/falco/pull/2024)] - [@FedeDP](https://github.com/FedeDP)
* chore(userspace/falco): do not print error code in process_events.cpp [[#2030](https://github.com/falcosecurity/falco/pull/2030)] - [@alacuku](https://github.com/alacuku)
* fix(falco-scripts): remove driver versions with `dkms-3.0.3` [[#2027](https://github.com/falcosecurity/falco/pull/2027)] - [@Andreagit97](https://github.com/Andreagit97)
* chore(userspace/falco): fix punctuation typo in output message when loading plugins [[#2026](https://github.com/falcosecurity/falco/pull/2026)] - [@alacuku](https://github.com/alacuku)
* refactor(userspace): change falco engine design to properly support multiple sources [[#2017](https://github.com/falcosecurity/falco/pull/2017)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update(userspace/falco): improve falco termination [[#2012](https://github.com/falcosecurity/falco/pull/2012)] - [@Andreagit97](https://github.com/Andreagit97)
* update(userspace/engine): introduce new `check_plugin_requirements` API [[#2009](https://github.com/falcosecurity/falco/pull/2009)] - [@Andreagit97](https://github.com/Andreagit97)
* fix(userspace/engine): improve rule loader source checks [[#2010](https://github.com/falcosecurity/falco/pull/2010)] - [@Andreagit97](https://github.com/Andreagit97)
* fix: split filterchecks per source-idx [[#1999](https://github.com/falcosecurity/falco/pull/1999)] - [@FedeDP](https://github.com/FedeDP)
* new: port CI builds to github actions [[#2000](https://github.com/falcosecurity/falco/pull/2000)] - [@FedeDP](https://github.com/FedeDP)
* build(userspace/engine): cleanup unused include dir [[#1987](https://github.com/falcosecurity/falco/pull/1987)] - [@leogr](https://github.com/leogr)
* rule(Anonymous Request Allowed): exclude {/livez, /readyz} [[#1954](https://github.com/falcosecurity/falco/pull/1954)] - [@sledigabel](https://github.com/sledigabel)
* chore(falco_scripts): Update `falco-driver-loader` cleaning phase [[#1950](https://github.com/falcosecurity/falco/pull/1950)] - [@Andreagit97](https://github.com/Andreagit97)
* new(userspace/falco): use new plugin caps API [[#1982](https://github.com/falcosecurity/falco/pull/1982)] - [@FedeDP](https://github.com/FedeDP)
* build: correct conffiles for DEB packages [[#1980](https://github.com/falcosecurity/falco/pull/1980)] - [@leogr](https://github.com/leogr)
* Fix exception parsing regressions [[#1985](https://github.com/falcosecurity/falco/pull/1985)] - [@mstemm](https://github.com/mstemm)
* Add codespell GitHub Action [[#1962](https://github.com/falcosecurity/falco/pull/1962)] - [@invidian](https://github.com/invidian)
* build: components opt-in mechanism for packages [[#1979](https://github.com/falcosecurity/falco/pull/1979)] - [@leogr](https://github.com/leogr)
* add gVisor to ADOPTERS.md [[#1974](https://github.com/falcosecurity/falco/pull/1974)] - [@kevinGC](https://github.com/kevinGC)
* rules: whitelist GCP's container threat detection image [[#1959](https://github.com/falcosecurity/falco/pull/1959)] - [@clmssz](https://github.com/clmssz)
* Fix some typos [[#1961](https://github.com/falcosecurity/falco/pull/1961)] - [@invidian](https://github.com/invidian)
* chore(rules): remove leftover [[#1958](https://github.com/falcosecurity/falco/pull/1958)] - [@leogr](https://github.com/leogr)
* docs: readme update and plugins [[#1940](https://github.com/falcosecurity/falco/pull/1940)] - [@leogr](https://github.com/leogr)


## v0.31.1

Released on 2022-03-09

### Major Changes


* new: add a new drop category `n_drops_scratch_map` [[#1916](https://github.com/falcosecurity/falco/pull/1916)] - [@Andreagit97](https://github.com/Andreagit97)
* new: allow to specify multiple --cri options [[#1893](https://github.com/falcosecurity/falco/pull/1893)] - [@FedeDP](https://github.com/FedeDP)


### Minor Changes

* refactor(userspace/falco): replace direct getopt_long() cmdline option parsing with third-party cxxopts library. [[#1886](https://github.com/falcosecurity/falco/pull/1886)] - [@mstemm](https://github.com/mstemm)
* update: driver version is b7eb0dd [[#1923](https://github.com/falcosecurity/falco/pull/1923)] - [@LucaGuerra](https://github.com/LucaGuerra)


### Bug Fixes

* fix(userspace/falco): correct plugins init config conversion from YAML to JSON [[#1907](https://github.com/falcosecurity/falco/pull/1907)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/engine): for rules at the informational level being loaded at the notice level [[#1885](https://github.com/falcosecurity/falco/pull/1885)] - [@mike-stewart](https://github.com/mike-stewart)
* chore(userspace/falco): fixes truncated -b option description. [[#1915](https://github.com/falcosecurity/falco/pull/1915)] - [@andreabonanno](https://github.com/andreabonanno)
* update(falco): updates usage description for -o, --option [[#1903](https://github.com/falcosecurity/falco/pull/1903)] - [@andreabonanno](https://github.com/andreabonanno)

### Security Fixes

* Fix for a TOCTOU issue that could lead to rule bypass (CVE-2022-26316). For more information, see the [advisory](https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7).

### Rule Changes

* rule(Detect outbound connections to common miner pool ports): fix url in rule output [[#1918](https://github.com/falcosecurity/falco/pull/1918)] - [@jsoref](https://github.com/jsoref)
* rule(macro somebody_becoming_themself): renaming macro to somebody_becoming_themselves [[#1918](https://github.com/falcosecurity/falco/pull/1918)] - [@jsoref](https://github.com/jsoref)
* rule(list package_mgmt_binaries): `npm` added [[#1866](https://github.com/falcosecurity/falco/pull/1866)] - [@rileydakota](https://github.com/rileydakota)
* rule(Launch Package Management Process in Container): support for detecting `npm` usage [[#1866](https://github.com/falcosecurity/falco/pull/1866)] - [@rileydakota](https://github.com/rileydakota)
* rule(Polkit Local Privilege Escalation Vulnerability): new rule created to detect CVE-2021-4034 [[#1877](https://github.com/falcosecurity/falco/pull/1877)] - [@darryk10](https://github.com/darryk10)
* rule(macro: modify_shell_history): avoid false-positive alerts triggered by modifications to .zsh_history.new and .zsh_history.LOCK files [[#1832](https://github.com/falcosecurity/falco/pull/1832)] - [@m4wh6k](https://github.com/m4wh6k)
* rule(macro: truncate_shell_history): avoid false-positive alerts triggered by modifications to .zsh_history.new and .zsh_history.LOCK files [[#1832](https://github.com/falcosecurity/falco/pull/1832)] - [@m4wh6k](https://github.com/m4wh6k)
* rule(macro sssd_writing_krb): fixed a false-positive alert that was being generated when SSSD updates /etc/krb5.keytab [[#1825](https://github.com/falcosecurity/falco/pull/1825)] - [@mac-chaffee](https://github.com/mac-chaffee)
* rule(macro write_etc_common): fixed a false-positive alert that was being generated when SSSD updates /etc/krb5.keytab [[#1825](https://github.com/falcosecurity/falco/pull/1825)] - [@mac-chaffee](https://github.com/mac-chaffee)
* upgrade macro(keepalived_writing_conf) [[#1742](https://github.com/falcosecurity/falco/pull/1742)] - [@pabloopez](https://github.com/pabloopez)
* rule_output(Delete Bucket Public Access Block) typo [[#1888](https://github.com/falcosecurity/falco/pull/1888)] - [@pabloopez](https://github.com/pabloopez)


### Non user-facing changes

* fix(build): fix civetweb linking in cmake module [[#1919](https://github.com/falcosecurity/falco/pull/1919)] - [@LucaGuerra](https://github.com/LucaGuerra)
* chore(userspace/engine): remove unused lua functions and state vars [[#1908](https://github.com/falcosecurity/falco/pull/1908)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/falco): applies FALCO_INSTALL_CONF_FILE as the default … [[#1900](https://github.com/falcosecurity/falco/pull/1900)] - [@andreabonanno](https://github.com/andreabonanno)
* fix(scripts): correct typo in `falco-driver-loader` help message [[#1899](https://github.com/falcosecurity/falco/pull/1899)] - [@leogr](https://github.com/leogr)
* update(build)!: replaced various `PROBE` with `DRIVER` where necessary. [[#1887](https://github.com/falcosecurity/falco/pull/1887)] - [@FedeDP](https://github.com/FedeDP)
* Add [Fairwinds](https://fairwinds.com) to the adopters list [[#1917](https://github.com/falcosecurity/falco/pull/1917)] - [@sudermanjr](https://github.com/sudermanjr)
* build(cmake): several cmake changes to speed up/simplify builds for external projects and copying files from source-to-build directories [[#1905](https://github.com/falcosecurity/falco/pull/1905)] - [@mstemm](https://github.com/mstemm)


## v0.31.0

Released on 2022-01-31

### Major Changes


* new: add support for plugins to extend Falco functionality to new event sources and custom fields [[#1753](https://github.com/falcosecurity/falco/pull/1753)] - [@mstemm](https://github.com/mstemm)
* new: add ability to set User-Agent http header when sending http output. Provide default value of 'falcosecurity/falco'. [[#1850](https://github.com/falcosecurity/falco/pull/1850)] - [@yoshi314](https://github.com/yoshi314)
* new(configuration): support defining plugin init config as a YAML [[#1852](https://github.com/falcosecurity/falco/pull/1852)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Minor Changes

* rules: add the official Falco ECR repository to rules [[#1817](https://github.com/falcosecurity/falco/pull/1817)] - [@calvinbui](https://github.com/calvinbui)
* build: update CircleCI machine image for eBPF tests to a newer version of ubuntu [[#1764](https://github.com/falcosecurity/falco/pull/1764)] - [@mstemm](https://github.com/mstemm)
* update(engine): refactor Falco engine to be agnostic to specific event sources [[#1715](https://github.com/falcosecurity/falco/pull/1715)] - [@mstemm](https://github.com/mstemm)
* build: upgrade civetweb to v1.15 [[#1782](https://github.com/falcosecurity/falco/pull/1782)] - [@FedeDP](https://github.com/FedeDP)
* update: driver version is 319368f1ad778691164d33d59945e00c5752cd27 now [[#1861](https://github.com/falcosecurity/falco/pull/1861)] - [@FedeDP](https://github.com/FedeDP)
* build: allow using local libs source dir by setting `FALCOSECURITY_LIBS_SOURCE_DIR` in cmake [[#1791](https://github.com/falcosecurity/falco/pull/1791)] - [@jasondellaluce](https://github.com/jasondellaluce)
* build: the statically linked binary package is now published with the `-static` suffix [[#1873](https://github.com/falcosecurity/falco/pull/1873)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update!: removed "--alternate-lua-dir" cmdline option as lua scripts are now embedded in Falco executable. [[#1872](https://github.com/falcosecurity/falco/pull/1872)] - [@FedeDP](https://github.com/FedeDP)
* build: switch to dynamic build for the binary package (`.tar.gz`) [[#1853](https://github.com/falcosecurity/falco/pull/1853)] - [@LucaGuerra](https://github.com/LucaGuerra)
* update: simpleconsumer filtering is now being done at kernel level [[#1846](https://github.com/falcosecurity/falco/pull/1846)] - [@FedeDP](https://github.com/FedeDP)
* update(scripts/falco-driver-loader): first try to load the latest kmod version, then fallback to an already installed if any [[#1863](https://github.com/falcosecurity/falco/pull/1863)] - [@leogr](https://github.com/leogr)
* refactor: clean up --list output with better formatting and no duplicate sections across event sources. [[#1816](https://github.com/falcosecurity/falco/pull/1816)] - [@mstemm](https://github.com/mstemm)
* update: embed .lua files used to load/compile rules into the main falco executable, for simplicity and to avoid tampering. [[#1843](https://github.com/falcosecurity/falco/pull/1843)] - [@mstemm](https://github.com/mstemm)
* update: support non-enumerable event sources in gRPC outputs service [[#1840](https://github.com/falcosecurity/falco/pull/1840)] - [@jasondellaluce](https://github.com/jasondellaluce)
* docs: add jasondellaluce to OWNERS [[#1818](https://github.com/falcosecurity/falco/pull/1818)] - [@jasondellaluce](https://github.com/jasondellaluce)
* chore: --list option can be used to selectively list fields related to new sources that are introduced by plugins [[#1839](https://github.com/falcosecurity/falco/pull/1839)] - [@loresuso](https://github.com/loresuso)
* update(userspace/falco): support arbitrary-depth nested values in YAML configuration [[#1792](https://github.com/falcosecurity/falco/pull/1792)] - [@jasondellaluce](https://github.com/jasondellaluce)
* build: bump FakeIt version to 2.0.9 [[#1797](https://github.com/falcosecurity/falco/pull/1797)] - [@jasondellaluce](https://github.com/jasondellaluce)
* update: allow append of new exceptions to rules [[#1780](https://github.com/falcosecurity/falco/pull/1780)] - [@sai-arigeli](https://github.com/sai-arigeli)
* update: Linux packages are now signed with SHA256 [[#1758](https://github.com/falcosecurity/falco/pull/1758)] - [@twa16](https://github.com/twa16)


### Bug Fixes

* fix(scripts/falco-driver-loader): fix for SELinux insmod denials [[#1756](https://github.com/falcosecurity/falco/pull/1756)] - [@dwindsor](https://github.com/dwindsor)
* fix(scripts/falco-driver-loader): correctly clean loaded drivers when using `--clean` [[#1795](https://github.com/falcosecurity/falco/pull/1795)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(userspace/falco): in case output_file cannot be opened, throw a falco exception [[#1773](https://github.com/falcosecurity/falco/pull/1773)] - [@FedeDP](https://github.com/FedeDP)
* fix(userspace/engine): support jsonpointer escaping in rule parser [[#1777](https://github.com/falcosecurity/falco/pull/1777)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(scripts/falco-driver-loader): support kernel object files in `.zst` and `.gz` compression formats [[#1863](https://github.com/falcosecurity/falco/pull/1863)] - [@leogr](https://github.com/leogr)
* fix(engine): correctly format json output in json_event [[#1847](https://github.com/falcosecurity/falco/pull/1847)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix: set http output content type to text/plain when json output is disabled [[#1829](https://github.com/falcosecurity/falco/pull/1829)] - [@FedeDP](https://github.com/FedeDP)
* fix(userspace/falco): accept 'Content-Type' header that contains "application/json", but it is not strictly equal to it [[#1800](https://github.com/falcosecurity/falco/pull/1800)] - [@FedeDP](https://github.com/FedeDP)
* fix(userspace/engine): supporting enabled-only overwritten rules [[#1775](https://github.com/falcosecurity/falco/pull/1775)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Rule Changes

* rule(Create Symlink Over Sensitive File): corrected typo in rule output [[#1820](https://github.com/falcosecurity/falco/pull/1820)] - [@deepskyblue86](https://github.com/deepskyblue86)
* rule(macro open_write): add support to openat2 [[#1796](https://github.com/falcosecurity/falco/pull/1796)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(macro open_read): add support to openat2 [[#1796](https://github.com/falcosecurity/falco/pull/1796)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(macro open_directory): add support to openat2 [[#1796](https://github.com/falcosecurity/falco/pull/1796)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(Create files below dev): add support to openat2 [[#1796](https://github.com/falcosecurity/falco/pull/1796)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(Container Drift Detected (open+create)): add support to openat2 [[#1796](https://github.com/falcosecurity/falco/pull/1796)] - [@jasondellaluce](https://github.com/jasondellaluce)
* rule(macro sensitive_mount): add containerd socket [[#1815](https://github.com/falcosecurity/falco/pull/1815)] - [@loresuso](https://github.com/loresuso)
* rule(macro spawned_process): monitor also processes spawned by `execveat` [[#1868](https://github.com/falcosecurity/falco/pull/1868)] - [@Andreagit97](https://github.com/Andreagit97)
* rule(Create Hardlink Over Sensitive Files): new rule to detect hard links created over sensitive files [[#1810](https://github.com/falcosecurity/falco/pull/1810)] - [@sberkovich](https://github.com/sberkovich)
* rule(Detect crypto miners using the Stratum protocol): add `stratum2+tcp` and `stratum+ssl` protocols detection [[#1810](https://github.com/falcosecurity/falco/pull/1810)] - [@sberkovich](https://github.com/sberkovich)
* rule(Sudo Potential Privilege Escalation): correct special case for the CVE-2021-3156 exploit [[#1810](https://github.com/falcosecurity/falco/pull/1810)] - [@sberkovich](https://github.com/sberkovich)
* rule(list falco_hostnetwork_images): moved to k8s_audit_rules.yaml to avoid a warning when using falco_rules.yaml only [[#1681](https://github.com/falcosecurity/falco/pull/1681)] - [@leodido](https://github.com/leodido)
* rule(list deb_binaries): remove `apt-config` [[#1860](https://github.com/falcosecurity/falco/pull/1860)] - [@Andreagit97](https://github.com/Andreagit97)
* rule(Launch Remote File Copy Tools in Container): add additional binaries: curl and wget. [[#1771](https://github.com/falcosecurity/falco/pull/1771)] - [@ec4n6](https://github.com/ec4n6)
* rule(list known_sa_list): add coredns, coredns-autoscaler, endpointslicemirroring-controller, horizontal-pod-autoscaler, job-controller, node-controller (nodelifecycle), persistent-volume-binder, pv-protection-controller, pvc-protection-controller, root-ca-cert-publisher and service-account-controller as allowed service accounts in the kube-system namespace [[#1760](https://github.com/falcosecurity/falco/pull/1760)] - [@sboschman](https://github.com/sboschman)


### Non user-facing changes

* fix: force-set evt.type for plugin source events [[#1878](https://github.com/falcosecurity/falco/pull/1878)] - [@FedeDP](https://github.com/FedeDP)
* fix: updated some warning strings; properly refresh lua files embedded in falco [[#1864](https://github.com/falcosecurity/falco/pull/1864)] - [@FedeDP](https://github.com/FedeDP)
* style(userspace/engine): avoid creating multiple versions of methods only to assume default ruleset. Use a default argument instead. [[#1754](https://github.com/falcosecurity/falco/pull/1754)] - [@FedeDP](https://github.com/FedeDP)
* add raft in the adopters list [[#1776](https://github.com/falcosecurity/falco/pull/1776)] - [@teshsharma](https://github.com/teshsharma)
* build: always populate partial version variables [[#1778](https://github.com/falcosecurity/falco/pull/1778)] - [@dnwe](https://github.com/dnwe)
* build: updated cloudtrail plugin to latest version [[#1865](https://github.com/falcosecurity/falco/pull/1865)] - [@FedeDP](https://github.com/FedeDP)
* replace ".." concatenation with table.concat [[#1834](https://github.com/falcosecurity/falco/pull/1834)] - [@VadimZy](https://github.com/VadimZy)
* fix(userspace/engine): actually make m_filter_all_event_types useful by properly using it as fallback when no filter event types is provided [[#1875](https://github.com/falcosecurity/falco/pull/1875)] - [@FedeDP](https://github.com/FedeDP)
* fix(build): do not show plugin options in musl optimized builds [[#1871](https://github.com/falcosecurity/falco/pull/1871)] - [@LucaGuerra](https://github.com/LucaGuerra)
* fix(aws_cloudtrail_rules.yaml): correct required plugin versions [[#1867](https://github.com/falcosecurity/falco/pull/1867)] - [@FedeDP](https://github.com/FedeDP)
* docs: fix priority level "info" to "informational" [[#1858](https://github.com/falcosecurity/falco/pull/1858)] - [@Andreagit97](https://github.com/Andreagit97)
* Field properties changes [[#1838](https://github.com/falcosecurity/falco/pull/1838)] - [@mstemm](https://github.com/mstemm)
* update(build): updated libs to latest master version; updated plugins versions [[#1856](https://github.com/falcosecurity/falco/pull/1856)] - [@FedeDP](https://github.com/FedeDP)
* Add Giant Swarm to Adopters list [[#1842](https://github.com/falcosecurity/falco/pull/1842)] - [@stone-z](https://github.com/stone-z)
* update(tests): remove `token_bucket` unit tests [[#1798](https://github.com/falcosecurity/falco/pull/1798)] - [@jasondellaluce](https://github.com/jasondellaluce)
* fix(build): use consistent 7-character build abbrev sha [[#1830](https://github.com/falcosecurity/falco/pull/1830)] - [@LucaGuerra](https://github.com/LucaGuerra)
* add Phoenix to adopters list [[#1806](https://github.com/falcosecurity/falco/pull/1806)] - [@kaldyka](https://github.com/kaldyka)
* remove unused files in test directory [[#1801](https://github.com/falcosecurity/falco/pull/1801)] - [@jasondellaluce](https://github.com/jasondellaluce)
* drop Falco luajit module, use the one provided by libs [[#1788](https://github.com/falcosecurity/falco/pull/1788)] - [@FedeDP](https://github.com/FedeDP)
* chore(build): update libs version to 7906f7e [[#1790](https://github.com/falcosecurity/falco/pull/1790)] - [@LucaGuerra](https://github.com/LucaGuerra)
* Add SysFlow to list of libs adopters [[#1747](https://github.com/falcosecurity/falco/pull/1747)] - [@araujof](https://github.com/araujof)
* build: dropped centos8 circleci build because it is useless [[#1882](https://github.com/falcosecurity/falco/pull/1882)] - [@FedeDP](https://github.com/FedeDP)


## v0.30.0

Released on 2021-10-01

### Major Changes

* new: add `--k8s-node` command-line options, which allows filtering by a node when requesting metadata of pods to the K8s API server [[#1671](https://github.com/falcosecurity/falco/pull/1671)] - [@leogr](https://github.com/leogr)
* new(outputs): expose rule tags and event source in gRPC and json outputs [[#1714](https://github.com/falcosecurity/falco/pull/1714)] - [@jasondellaluce](https://github.com/jasondellaluce)
* new(userspace/falco): add customizable metadata fetching params [[#1667](https://github.com/falcosecurity/falco/pull/1667)] - [@zuc](https://github.com/zuc)


### Minor Changes

* update: bump driver version to 3aa7a83bf7b9e6229a3824e3fd1f4452d1e95cb4 [[#1744](https://github.com/falcosecurity/falco/pull/1744)] - [@zuc](https://github.com/zuc)
* docs: clarify that previous Falco drivers will remain available at https://download.falco.org and no automated cleanup is run anymore [[#1738](https://github.com/falcosecurity/falco/pull/1738)] - [@leodido](https://github.com/leodido)
* update(outputs): add configuration option for tags in json outputs [[#1733](https://github.com/falcosecurity/falco/pull/1733)] - [@jasondellaluce](https://github.com/jasondellaluce)


### Bug Fixes

* fix(scripts): correct standard output redirection in systemd config (DEB and RPM packages) [[#1697](https://github.com/falcosecurity/falco/pull/1697)] - [@chirabino](https://github.com/chirabino)
* fix(scripts): correct lookup order when trying multiple `gcc` versions in the `falco-driver-loader` script [[#1716](https://github.com/falcosecurity/falco/pull/1716)] - [@Spartan-65](https://github.com/Spartan-65)


### Rule Changes

* rule(list miner_domains): add new miner domains [[#1729](https://github.com/falcosecurity/falco/pull/1729)] - [@AlbertoPellitteri](https://github.com/AlbertoPellitteri)
* rule(list https_miner_domains): add new miner domains [[#1729](https://github.com/falcosecurity/falco/pull/1729)] - [@AlbertoPellitteri](https://github.com/AlbertoPellitteri)


### Non user-facing changes

* add Qonto as adopter [[#1717](https://github.com/falcosecurity/falco/pull/1717)] - [@Issif](https://github.com/Issif)
* docs(proposals): proposal for a libs plugin system [[#1637](https://github.com/falcosecurity/falco/pull/1637)] - [@ldegio](https://github.com/ldegio)
* build: remove unused `ncurses` dependency [[#1658](https://github.com/falcosecurity/falco/pull/1658)] - [@leogr](https://github.com/leogr)
* build(.circleci): use new Debian 11 package names for python-pip [[#1712](https://github.com/falcosecurity/falco/pull/1712)] - [@zuc](https://github.com/zuc)
* build(docker): adding libssl-dev, upstream image reference pinned to `debian:buster` [[#1719](https://github.com/falcosecurity/falco/pull/1719)] - [@michalschott](https://github.com/michalschott)
* fix(test): avoid output_strictly_contains failures [[#1724](https://github.com/falcosecurity/falco/pull/1724)] - [@jasondellaluce](https://github.com/jasondellaluce)
* Remove duplicate allowed ecr registry rule [[#1725](https://github.com/falcosecurity/falco/pull/1725)] - [@TomKeyte](https://github.com/TomKeyte)
* docs(RELEASE.md): switch to 3 releases per year [[#1711](https://github.com/falcosecurity/falco/pull/1711)] - [@leogr](https://github.com/leogr)


## v0.29.1

Released on 2021-06-29

### Minor Changes

* update: bump the Falco engine version to version 9 [[#1675](https://github.com/falcosecurity/falco/pull/1675)] - [@leodido](https://github.com/leodido)

### Rule Changes

* rule(list user_known_userfaultfd_processes): list to exclude processes known to use userfaultfd syscall [[#1675](https://github.com/falcosecurity/falco/pull/1675)] - [@leodido](https://github.com/leodido)
* rule(macro consider_userfaultfd_activities): macro to gate the "Unprivileged Delegation of Page Faults Handling to a Userspace Process" rule [[#1675](https://github.com/falcosecurity/falco/pull/1675)] - [@leodido](https://github.com/leodido)
* rule(Unprivileged Delegation of Page Faults Handling to a Userspace Process): new rule to detect successful unprivileged userfaultfd syscalls [[#1675](https://github.com/falcosecurity/falco/pull/1675)] - [@leodido](https://github.com/leodido)
* rule(Linux Kernel Module Injection Detected): adding container info to the output of the rule [[#1675](https://github.com/falcosecurity/falco/pull/1675)] - [@leodido](https://github.com/leodido)

### Non user-facing changes

* docs(release.md): update steps [[#1684](https://github.com/falcosecurity/falco/pull/1684)] - [@maxgio92](https://github.com/maxgio92)


## v0.29.0

Released on 2021-06-21

### Minor Changes

* update: driver version is 17f5df52a7d9ed6bb12d3b1768460def8439936d now [[#1669](https://github.com/falcosecurity/falco/pull/1669)] - [@leogr](https://github.com/leogr)

### Rule Changes

* rule(list miner_domains): add rx.unmineable.com for anti-miner detection [[#1676](https://github.com/falcosecurity/falco/pull/1676)] - [@fntlnz](https://github.com/fntlnz)
* rule(Change thread namespace and Set Setuid or Setgid bit): disable by default [[#1632](https://github.com/falcosecurity/falco/pull/1632)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(list known_sa_list): add namespace-controller, statefulset-controller, disruption-controller, job-controller, horizontal-pod-autoscaler and persistent-volume-binder as allowed service accounts in the kube-system namespace [[#1659](https://github.com/falcosecurity/falco/pull/1659)] - [@sboschman](https://github.com/sboschman)
* rule(Non sudo setuid): check user id as well in case user name info is not available [[#1665](https://github.com/falcosecurity/falco/pull/1665)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Debugfs Launched in Privileged Container): fix typo in description [[#1657](https://github.com/falcosecurity/falco/pull/1657)] - [@Kaizhe](https://github.com/Kaizhe)

### Non user-facing changes

* Fix link to CONTRIBUTING.md in the Pull Request Template [[#1679](https://github.com/falcosecurity/falco/pull/1679)] - [@tspearconquest](https://github.com/tspearconquest)
* fetch libs and drivers from the new repo [[#1552](https://github.com/falcosecurity/falco/pull/1552)] - [@leogr](https://github.com/leogr)
* build(test): upgrade urllib3 to 1.26.5 [[#1666](https://github.com/falcosecurity/falco/pull/1666)] - [@leogr](https://github.com/leogr)
* revert: add notes for 0.28.2 release [[#1663](https://github.com/falcosecurity/falco/pull/1663)] - [@maxgio92](https://github.com/maxgio92)
* changelog: add notes for 0.28.2 release [[#1661](https://github.com/falcosecurity/falco/pull/1661)] - [@maxgio92](https://github.com/maxgio92)
* docs(release.md): add blog announcement to post-release tasks [[#1652](https://github.com/falcosecurity/falco/pull/1652)] - [@maxgio92](https://github.com/maxgio92)
* add Yahoo!Japan as an adopter [[#1651](https://github.com/falcosecurity/falco/pull/1651)] - [@ukitazume](https://github.com/ukitazume)
* Add Replicated to adopters [[#1649](https://github.com/falcosecurity/falco/pull/1649)] - [@diamonwiggins](https://github.com/diamonwiggins)
* docs(proposals): fix libs contribution name [[#1641](https://github.com/falcosecurity/falco/pull/1641)] - [@leodido](https://github.com/leodido)


## v0.28.1

Released on 2021-05-07

### Major Changes

* new: `--support` output now includes info about the Falco engine version [[#1581](https://github.com/falcosecurity/falco/pull/1581)] - [@mstemm](https://github.com/mstemm)
* new: Falco outputs an alert in the unlikely situation it's receiving too many consecutive timeouts without an event [[#1622](https://github.com/falcosecurity/falco/pull/1622)] - [@leodido](https://github.com/leodido)
* new: configuration field `syscall_event_timeouts.max_consecutive` to configure after how many consecutive timeouts without an event Falco must alert [[#1622](https://github.com/falcosecurity/falco/pull/1622)] - [@leodido](https://github.com/leodido)

### Minor Changes

* build: enforcing hardening flags by default [[#1604](https://github.com/falcosecurity/falco/pull/1604)] - [@leogr](https://github.com/leogr)

### Bug Fixes

* fix: do not stop the webserver for k8s audit logs when invalid data is coming in the event to be processed [[#1617](https://github.com/falcosecurity/falco/pull/1617)] - [@fntlnz](https://github.com/fntlnz)

### Rule Changes

* rule(macro: allowed_aws_ecr_registry_root_for_eks): new macro for AWS EKS images hosted on ECR to use in rule: Launch Privileged Container [[#1640](https://github.com/falcosecurity/falco/pull/1640)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(macro: aws_eks_core_images): new macro for AWS EKS images hosted on ECR to use in rule: Launch Privileged Container [[#1640](https://github.com/falcosecurity/falco/pull/1640)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(macro: aws_eks_image_sensitive_mount): new macro for AWS EKS images hosted on ECR to use in rule: Launch Privileged Container [[#1640](https://github.com/falcosecurity/falco/pull/1640)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(list `falco_privileged_images`): remove deprecated Falco's OCI image repositories [[#1634](https://github.com/falcosecurity/falco/pull/1634)] - [@maxgio92](https://github.com/maxgio92)
* rule(list `falco_sensitive_mount_images`): remove deprecated Falco's OCI image repositories [[#1634](https://github.com/falcosecurity/falco/pull/1634)] - [@maxgio92](https://github.com/maxgio92)
* rule(macro `k8s_containers`): remove deprecated Falco's OCI image repositories [[#1634](https://github.com/falcosecurity/falco/pull/1634)] - [@maxgio92](https://github.com/maxgio92)
* rule(macro: python_running_sdchecks): macro removed [[#1620](https://github.com/falcosecurity/falco/pull/1620)] - [@leogr](https://github.com/leogr)
* rule(Change thread namespace): remove python_running_sdchecks exception [[#1620](https://github.com/falcosecurity/falco/pull/1620)] - [@leogr](https://github.com/leogr)

### Non user-facing changes

* urelease/docs: fix link and small refactor in the text [[#1636](https://github.com/falcosecurity/falco/pull/1636)] - [@cpanato](https://github.com/cpanato)
* Add Secureworks to adopters [[#1629](https://github.com/falcosecurity/falco/pull/1629)] - [@dwindsor-scwx](https://github.com/dwindsor-scwx)
* regression test for malformed k8s audit input (FAL-01-003) [[#1624](https://github.com/falcosecurity/falco/pull/1624)] - [@leodido](https://github.com/leodido)
* Add mathworks to adopterlist [[#1621](https://github.com/falcosecurity/falco/pull/1621)] - [@natchaphon-r](https://github.com/natchaphon-r)
* adding known users [[#1623](https://github.com/falcosecurity/falco/pull/1623)] - [@danpopSD](https://github.com/danpopSD)
* docs: update link for HackMD community call notes [[#1614](https://github.com/falcosecurity/falco/pull/1614)] - [@leodido](https://github.com/leodido)


## v0.28.0

Released on 2021-04-12

### Major Changes

* BREAKING CHANGE: Bintray is deprecated, no new packages will be published at https://dl.bintray.com/falcosecurity/ [[#1577](https://github.com/falcosecurity/falco/pull/1577)] - [@leogr](https://github.com/leogr)
* BREAKING CHANGE: SKIP_MODULE_LOAD env variable no more disables the driver loading (use SKIP_DRIVER_LOADER env variable introduced in Falco 0.24) [[#1599](https://github.com/falcosecurity/falco/pull/1599)] - [@leodido](https://github.com/leodido)
* BREAKING CHANGE: the init.d service unit is not shipped anymore in deb/rpm packages in favor of a systemd service file [[#1448](https://github.com/falcosecurity/falco/pull/1448)] - [@jenting](https://github.com/jenting)
* new: add support for exceptions as rule attributes to provide a compact way to add exceptions to Falco rules [[#1427](https://github.com/falcosecurity/falco/pull/1427)] - [@mstemm](https://github.com/mstemm)
* new: falco-no-driver container images on AWS ECR gallery (https://gallery.ecr.aws/falcosecurity/falco-no-driver) [[#1519](https://github.com/falcosecurity/falco/pull/1519)] - [@jonahjon](https://github.com/jonahjon)
* new: falco-driver-loader container images on AWS ECR gallery (https://gallery.ecr.aws/falcosecurity/falco-driver-loader) [[#1519](https://github.com/falcosecurity/falco/pull/1519)] - [@jonahjon](https://github.com/jonahjon)
* new: add healthz endpoint to the webserver [[#1546](https://github.com/falcosecurity/falco/pull/1546)] - [@cpanato](https://github.com/cpanato)
* new: introduce a new configuration field `syscall_event_drops.threshold` to tune the drop noisiness [[#1586](https://github.com/falcosecurity/falco/pull/1586)] - [@leodido](https://github.com/leodido)
* new: falco-driver-loader script can get a custom driver name from DRIVER_NAME env variable [[#1488](https://github.com/falcosecurity/falco/pull/1488)] - [@leodido](https://github.com/leodido)
* new: falco-driver-loader know the Falco version [[#1488](https://github.com/falcosecurity/falco/pull/1488)] - [@leodido](https://github.com/leodido)


### Minor Changes

* docs(proposals): libraries and drivers donation [[#1530](https://github.com/falcosecurity/falco/pull/1530)] - [@leodido](https://github.com/leodido)
* docs(docker): update links to the new Falco website URLs [[#1545](https://github.com/falcosecurity/falco/pull/1545)] - [@cpanato](https://github.com/cpanato)
* docs(test): update links to new Falco website URLs [[#1563](https://github.com/falcosecurity/falco/pull/1563)] - [@shane-lawrence](https://github.com/shane-lawrence)
* build: now Falco packages are published at https://download.falco.org [[#1577](https://github.com/falcosecurity/falco/pull/1577)] - [@leogr](https://github.com/leogr)
* update: lower the `syscall_event_drops.max_burst` default value to 1 [[#1586](https://github.com/falcosecurity/falco/pull/1586)] - [@leodido](https://github.com/leodido)
* update: falco-driver-loader tries to download a Falco driver before then compiling it on the fly for the host [[#1599](https://github.com/falcosecurity/falco/pull/1599)] - [@leodido](https://github.com/leodido)
* docs(test): document the prerequisites for running the integration test suite locally [[#1609](https://github.com/falcosecurity/falco/pull/1609)] - [@fntlnz](https://github.com/fntlnz)
* update: Debian/RPM package migrated from init to systemd [[#1448](https://github.com/falcosecurity/falco/pull/1448)] - [@jenting](https://github.com/jenting)


### Bug Fixes

* fix(userspace/engine): properly handle field extraction over lists of containers when not all containers match the specified sub-properties [[#1601](https://github.com/falcosecurity/falco/pull/1601)] - [@mstemm](https://github.com/mstemm)
* fix(docker/falco): add flex and bison dependency to container image [[#1562](https://github.com/falcosecurity/falco/pull/1562)] - [@schans](https://github.com/schans)
* fix: ignore action can not be used with log and alert ones (`syscall_event_drops` config) [[#1586](https://github.com/falcosecurity/falco/pull/1586)] - [@leodido](https://github.com/leodido)
* fix(userspace/engine): allows fields starting with numbers to be parsed properly [[#1598](https://github.com/falcosecurity/falco/pull/1598)] - [@mstemm](https://github.com/mstemm)


### Rule Changes

* rule(Write below monitored dir): improve rule description [[#1588](https://github.com/falcosecurity/falco/pull/1588)] - [@stevenshuang](https://github.com/stevenshuang)
* rule(macro allowed_aws_eks_registry_root): macro to match the official eks registry [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(macro aws_eks_image): match aws image repository for eks [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(macro aws_eks_image_sensitive_mount): match aws cni images [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(macro k8s_containers): include fluent/fluentd-kubernetes-daemonset and prom/prometheus [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(Launch Privileged Container): exclude aws_eks_image [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(Launch Sensitive Mount Container): exclude aws_eks_image_sensitive_mount [[#1555](https://github.com/falcosecurity/falco/pull/1555)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(Debugfs Launched in Privileged Container): new rule [[#1583](https://github.com/falcosecurity/falco/pull/1583)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Mount Launched in Privileged Container): new rule [[#1583](https://github.com/falcosecurity/falco/pull/1583)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Set Setuid or Setgid bit): add k3s-agent in the whitelist [[#1583](https://github.com/falcosecurity/falco/pull/1583)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro user_ssh_directory): using glob operator [[#1560](https://github.com/falcosecurity/falco/pull/1560)] - [@shane-lawrence](https://github.com/shane-lawrence)
* rule(list falco_sensitive_mount_containers): added image exceptions for IBM cloud [[#1337](https://github.com/falcosecurity/falco/pull/1337)] - [@nibalizer](https://github.com/nibalizer)
* rule(list rpm_binaries): add rhsmcertd [[#1385](https://github.com/falcosecurity/falco/pull/1385)] - [@epcim](https://github.com/epcim)
* rule(list deb_binaries): add apt.systemd.daily [[#1385](https://github.com/falcosecurity/falco/pull/1385)] - [@epcim](https://github.com/epcim)
* rule(Sudo Potential Privilege Escalation): new rule created to detect CVE-2021-3156 [[#1543](https://github.com/falcosecurity/falco/pull/1543)] - [@darryk10](https://github.com/darryk10)
* rule(list allowed_k8s_users): add `eks:node-manager` [[#1536](https://github.com/falcosecurity/falco/pull/1536)] - [@ismailyenigul](https://github.com/ismailyenigul)
* rule(list mysql_mgmt_binaries): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list db_mgmt_binaries): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_ansible_running_python): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_bro_running_python): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_python_running_denyhosts): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_linux_image_upgrade_script): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_java_running_echo): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_scripting_running_builds): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_Xvfb_running_xkbcomp): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_nginx_running_serf): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_node_running_npm): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_java_running_sbt): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list known_container_shell_spawn_cmdlines): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list known_shell_spawn_binaries): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro run_by_puppet): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro user_privileged_containers): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list rancher_images): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list images_allow_network_outside_subnet): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro parent_python_running_sdchecks): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(macro trusted_containers): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)
* rule(list authorized_server_binaries): removed [[#1602](https://github.com/falcosecurity/falco/pull/1602)] - [@fntlnz](https://github.com/fntlnz)


### Non user-facing changes

* chore(test): replace bucket url with official distribution url [[#1608](https://github.com/falcosecurity/falco/pull/1608)] - [@fntlnz](https://github.com/fntlnz)
* adding asapp as an adopter [[#1611](https://github.com/falcosecurity/falco/pull/1611)] - [@Stuxend](https://github.com/Stuxend)
* update: fixtures URLs [[#1603](https://github.com/falcosecurity/falco/pull/1603)] - [@leogr](https://github.com/leogr)
* cleanup publishing jobs [[#1596](https://github.com/falcosecurity/falco/pull/1596)] - [@leogr](https://github.com/leogr)
* fix(falco/test): bump pyyaml from 5.3.1 to 5.4 [[#1595](https://github.com/falcosecurity/falco/pull/1595)] - [@leodido](https://github.com/leodido)
* fix(.circleci): tar must be present in the image [[#1594](https://github.com/falcosecurity/falco/pull/1594)] - [@leogr](https://github.com/leogr)
* fix: publishing jobs [[#1591](https://github.com/falcosecurity/falco/pull/1591)] - [@leogr](https://github.com/leogr)
* Pocteo as an adopter [[#1574](https://github.com/falcosecurity/falco/pull/1574)] - [@pocteo-labs](https://github.com/pocteo-labs)
* build: fetch build deps from download.falco.org [[#1572](https://github.com/falcosecurity/falco/pull/1572)] - [@leogr](https://github.com/leogr)
* adding shapesecurity to adopters [[#1566](https://github.com/falcosecurity/falco/pull/1566)] - [@irivera007](https://github.com/irivera007)
* Use default pip version to get avocado version [[#1565](https://github.com/falcosecurity/falco/pull/1565)] - [@shane-lawrence](https://github.com/shane-lawrence)
* Added Swissblock to list of adopters [[#1551](https://github.com/falcosecurity/falco/pull/1551)] - [@bygui86](https://github.com/bygui86)
* Fix various typos in markdown files. [[#1514](https://github.com/falcosecurity/falco/pull/1514)] - [@didier-durand](https://github.com/didier-durand)
* docs: move governance to falcosecurity/.github [[#1524](https://github.com/falcosecurity/falco/pull/1524)] - [@leogr](https://github.com/leogr)
* ci: fix missing infra context to publish stable Falco packages [[#1615](https://github.com/falcosecurity/falco/pull/1615)] - [@leodido](https://github.com/leodido)


## v0.27.0

Released on 2021-01-18

### Major Changes

* new: Added falco engine version to grpc version service [[#1507](https://github.com/falcosecurity/falco/pull/1507)] - [@nibalizer](https://github.com/nibalizer)
* BREAKING CHANGE: Users who run Falco without a config file will be unable to do that any more, Falco now expects a configuration file to be passed all the times. Developers may need to adjust their processes. [[#1494](https://github.com/falcosecurity/falco/pull/1494)] - [@nibalizer](https://github.com/nibalizer)
* new: asynchronous outputs implementation, outputs channels will not block event processing anymore [[#1451](https://github.com/falcosecurity/falco/pull/1451)] - [@leogr](https://github.com/leogr)
* new: slow outputs detection [[#1451](https://github.com/falcosecurity/falco/pull/1451)] - [@leogr](https://github.com/leogr)
* new: `output_timeout` config option for slow outputs detection [[#1451](https://github.com/falcosecurity/falco/pull/1451)] - [@leogr](https://github.com/leogr)


### Minor Changes

* build: bump b64 to v2.0.0.1 [[#1441](https://github.com/falcosecurity/falco/pull/1441)] - [@fntlnz](https://github.com/fntlnz)
* rules(macro container_started): reuse `spawned_process` macro inside `container_started` macro [[#1449](https://github.com/falcosecurity/falco/pull/1449)] - [@leodido](https://github.com/leodido)
* docs: reach out documentation [[#1472](https://github.com/falcosecurity/falco/pull/1472)] - [@fntlnz](https://github.com/fntlnz)
* docs: Broken outputs.proto link [[#1493](https://github.com/falcosecurity/falco/pull/1493)] - [@deepskyblue86](https://github.com/deepskyblue86)
* docs(README.md): correct broken links [[#1506](https://github.com/falcosecurity/falco/pull/1506)] - [@leogr](https://github.com/leogr)
* docs(proposals): Exceptions handling proposal [[#1376](https://github.com/falcosecurity/falco/pull/1376)] - [@mstemm](https://github.com/mstemm)
* docs: fix a broken link of README [[#1516](https://github.com/falcosecurity/falco/pull/1516)] - [@oke-py](https://github.com/oke-py)
* docs: adding the kubernetes privileged use case to use cases [[#1484](https://github.com/falcosecurity/falco/pull/1484)] - [@fntlnz](https://github.com/fntlnz)
* rules(Mkdir binary dirs): Adds exe_running_docker_save as an exception as this rules can be triggered when a container is created. [[#1386](https://github.com/falcosecurity/falco/pull/1386)] - [@jhwbarlow](https://github.com/jhwbarlow)
* rules(Create Hidden Files): Adds exe_running_docker_save as an exception as this rules can be triggered when a container is created. [[#1386](https://github.com/falcosecurity/falco/pull/1386)] - [@jhwbarlow](https://github.com/jhwbarlow)
* docs(.circleci): welcome Jonah (Amazon) as a new Falco CI maintainer [[#1518](https://github.com/falcosecurity/falco/pull/1518)] - [@leodido](https://github.com/leodido)
* build: falcosecurity/falco:master also available on the AWS ECR Public registry [[#1512](https://github.com/falcosecurity/falco/pull/1512)] - [@leodido](https://github.com/leodido)
* build: falcosecurity/falco:latest also available on the AWS ECR Public registry [[#1512](https://github.com/falcosecurity/falco/pull/1512)] - [@leodido](https://github.com/leodido)
* update: gRPC clients can now subscribe to drop alerts via gRCP API [[#1451](https://github.com/falcosecurity/falco/pull/1451)] - [@leogr](https://github.com/leogr)
* macro(allowed_k8s_users): exclude cloud-controller-manage to avoid false positives on k3s [[#1444](https://github.com/falcosecurity/falco/pull/1444)] - [@fntlnz](https://github.com/fntlnz)


### Bug Fixes

* fix(userspace/falco): use given priority in falco_outputs::handle_msg() [[#1450](https://github.com/falcosecurity/falco/pull/1450)] - [@leogr](https://github.com/leogr)
* fix(userspace/engine): free formatters, if any [[#1447](https://github.com/falcosecurity/falco/pull/1447)] - [@leogr](https://github.com/leogr)
* fix(scripts/falco-driver-loader): lsmod usage [[#1474](https://github.com/falcosecurity/falco/pull/1474)] - [@dnwe](https://github.com/dnwe)
* fix: a bug that prevents Falco driver to be consumed by many Falco instances in some circumstances [[#1485](https://github.com/falcosecurity/falco/pull/1485)] - [@leodido](https://github.com/leodido)
* fix: set `HOST_ROOT=/host` environment variable for the `falcosecurity/falco-no-driver` container image by default [[#1492](https://github.com/falcosecurity/falco/pull/1492)] - [@leogr](https://github.com/leogr)


### Rule Changes

* rule(list user_known_change_thread_namespace_binaries): add crio and multus to the list [[#1501](https://github.com/falcosecurity/falco/pull/1501)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Container Run as Root User): new rule created [[#1500](https://github.com/falcosecurity/falco/pull/1500)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Linux Kernel Module injection detected): adds a new rule that detects when an LKM module is injected using `insmod` from a container (typically used by rootkits looking to obfuscate their behavior via kernel hooking). [[#1478](https://github.com/falcosecurity/falco/pull/1478)] - [@d1vious](https://github.com/d1vious)
* rule(macro multipath_writing_conf): create and use the macro [[#1475](https://github.com/falcosecurity/falco/pull/1475)] - [@nmarier-coveo](https://github.com/nmarier-coveo)
* rule(list falco_privileged_images): add calico/node without registry prefix to prevent false positive alerts [[#1457](https://github.com/falcosecurity/falco/pull/1457)] - [@czunker](https://github.com/czunker)
* rule(Full K8s Administrative Access): use the right list of admin users (fix) [[#1454](https://github.com/falcosecurity/falco/pull/1454)] - [@mstemm](https://github.com/mstemm)


### Non user-facing changes

* chore(cmake): remove unnecessary whitespace patch [[#1522](https://github.com/falcosecurity/falco/pull/1522)] - [@leogr](https://github.com/leogr)
* remove stale bot in favor of the new lifecycle bot [[#1490](https://github.com/falcosecurity/falco/pull/1490)] - [@leodido](https://github.com/leodido)
* chore(cmake): mark some variables as advanced [[#1496](https://github.com/falcosecurity/falco/pull/1496)] - [@deepskyblue86](https://github.com/deepskyblue86)
* chore(cmake/modules): avoid useless rebuild [[#1495](https://github.com/falcosecurity/falco/pull/1495)] - [@deepskyblue86](https://github.com/deepskyblue86)
* build: BUILD_BYPRODUCTS for civetweb [[#1489](https://github.com/falcosecurity/falco/pull/1489)] - [@fntlnz](https://github.com/fntlnz)
* build: remove duplicate item from FALCO_SOURCES [[#1480](https://github.com/falcosecurity/falco/pull/1480)] - [@leodido](https://github.com/leodido)
* build: make our integration tests report clear steps for CircleCI UI [[#1473](https://github.com/falcosecurity/falco/pull/1473)] - [@fntlnz](https://github.com/fntlnz)
* further improvements outputs impl.  [[#1443](https://github.com/falcosecurity/falco/pull/1443)] - [@leogr](https://github.com/leogr)
* fix(test): make integration tests properly fail [[#1439](https://github.com/falcosecurity/falco/pull/1439)] - [@leogr](https://github.com/leogr)
* Falco outputs refactoring [[#1412](https://github.com/falcosecurity/falco/pull/1412)] - [@leogr](https://github.com/leogr)



## v0.26.2

Released on 2020-11-10

### Major Changes

* update: DRIVERS_REPO now defaults to https://download.falco.org/driver [[#1460](https://github.com/falcosecurity/falco/pull/1460)] - [@leodido](https://github.com/leodido)

## v0.26.1

Released on 2020-10-01

### Major Changes

* new: CLI flag `--alternate-lua-dir` to load Lua files from arbitrary paths [[#1419](https://github.com/falcosecurity/falco/pull/1419)] - [@admiral0](https://github.com/admiral0)


### Rule Changes

* rule(Delete or rename shell history): fix warnings/FPs + container teardown [[#1423](https://github.com/falcosecurity/falco/pull/1423)] - [@mstemm](https://github.com/mstemm)
* rule(Write below root): ensure proc_name_exists too [[#1423](https://github.com/falcosecurity/falco/pull/1423)] - [@mstemm](https://github.com/mstemm)


## v0.26.0

Released on 2020-24-09

### Major Changes

* new: address several sources of FPs, primarily from GKE environments. [[#1372](https://github.com/falcosecurity/falco/pull/1372)] - [@mstemm](https://github.com/mstemm)
* new: driver updated to 2aa88dcf6243982697811df4c1b484bcbe9488a2 [[#1410](https://github.com/falcosecurity/falco/pull/1410)] - [@leogr](https://github.com/leogr)
* new(scripts/falco-driver-loader): detect and try to build the Falco kernel module driver using different GCC versions available in the current environment. [[#1408](https://github.com/falcosecurity/falco/pull/1408)] - [@fntlnz](https://github.com/fntlnz)
* new: tgz (tarball) containing the statically-linked (musl) binary of Falco is now automatically built and published on bintray [[#1377](https://github.com/falcosecurity/falco/pull/1377)] - [@leogr](https://github.com/leogr)


### Minor Changes

* update: bump Falco engine version to 7 [[#1381](https://github.com/falcosecurity/falco/pull/1381)] - [@leogr](https://github.com/leogr)
* update: the required_engine_version is now on by default [[#1381](https://github.com/falcosecurity/falco/pull/1381)] - [@leogr](https://github.com/leogr)
* update: falcosecurity/falco-no-driver image now uses the statically-linked Falco [[#1377](https://github.com/falcosecurity/falco/pull/1377)] - [@leogr](https://github.com/leogr)
* docs(proposals): artifacts storage [[#1375](https://github.com/falcosecurity/falco/pull/1375)] - [@leodido](https://github.com/leodido)
* docs(proposals): artifacts cleanup [[#1375](https://github.com/falcosecurity/falco/pull/1375)] - [@leodido](https://github.com/leodido)


### Rule Changes

* rule(macro inbound_outbound): add brackets to disambiguate operator precedence [[#1373](https://github.com/falcosecurity/falco/pull/1373)] - [@ldegio](https://github.com/ldegio)
* rule(macro redis_writing_conf): add brackets to disambiguate operator precedence [[#1373](https://github.com/falcosecurity/falco/pull/1373)] - [@ldegio](https://github.com/ldegio)
* rule(macro run_by_foreman): add brackets to disambiguate operator precedence [[#1373](https://github.com/falcosecurity/falco/pull/1373)] - [@ldegio](https://github.com/ldegio)
* rule(macro consider_packet_socket_communication): enable "Packet socket created in container" rule by default. [[#1402](https://github.com/falcosecurity/falco/pull/1402)] - [@rung](https://github.com/rung)
* rule(Delete or rename shell history): skip docker overlay filesystems when considering bash history [[#1393](https://github.com/falcosecurity/falco/pull/1393)] - [@mstemm](https://github.com/mstemm)
* rule(Disallowed K8s User): quote colons in user names [[#1393](https://github.com/falcosecurity/falco/pull/1393)] - [@mstemm](https://github.com/mstemm)
* rule(macro falco_sensitive_mount_containers): Adds a trailing slash to avoid repo naming issues [[#1394](https://github.com/falcosecurity/falco/pull/1394)] - [@bgeesaman](https://github.com/bgeesaman)
* rule: adds user.loginuid to the default Falco rules that also contain user.name [[#1369](https://github.com/falcosecurity/falco/pull/1369)] - [@csschwe](https://github.com/csschwe)

## v0.25.0

Released on 2020-08-25

### Major Changes

* new(userspace/falco): print the Falco and driver versions at the very beginning of the output. [[#1303](https://github.com/falcosecurity/falco/pull/1303)] - [@leogr](https://github.com/leogr)
* new: libyaml is now bundled in the release process. Users can now avoid installing libyaml directly when getting Falco from the official release. [[#1252](https://github.com/falcosecurity/falco/pull/1252)] - [@fntlnz](https://github.com/fntlnz)


### Minor Changes

* docs(test): step-by-step instructions to run integration tests locally [[#1313](https://github.com/falcosecurity/falco/pull/1313)] - [@leodido](https://github.com/leodido)
* update: renameat2 syscall support [[#1355](https://github.com/falcosecurity/falco/pull/1355)] - [@fntlnz](https://github.com/fntlnz)
* update: support for 5.8.x kernels [[#1355](https://github.com/falcosecurity/falco/pull/1355)] - [@fntlnz](https://github.com/fntlnz)


### Bug Fixes

* fix(userspace/falco): correct the fallback mechanism for loading the kernel module [[#1366](https://github.com/falcosecurity/falco/pull/1366)] - [@leogr](https://github.com/leogr)
* fix(falco-driver-loader): script crashing when using arguments [[#1330](https://github.com/falcosecurity/falco/pull/1330)] - [@antoinedeschenes](https://github.com/antoinedeschenes)


### Rule Changes

* rule(macro user_trusted_containers): add `sysdig/node-image-analyzer` and `sysdig/agent-slim` [[#1321](https://github.com/falcosecurity/falco/pull/1321)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro falco_privileged_images): add `docker.io/falcosecurity/falco` [[#1326](https://github.com/falcosecurity/falco/pull/1326)] - [@nvanheuverzwijn](https://github.com/nvanheuverzwijn)
* rule(EphemeralContainers Created): add new rule to detect ephemeral container created [[#1339](https://github.com/falcosecurity/falco/pull/1339)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro user_read_sensitive_file_containers): replace endswiths with exact image repo name [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro user_trusted_containers): replace endswiths with exact image repo name [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro user_privileged_containers): replace endswiths with exact image repo name [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro trusted_images_query_miner_domain_dns): replace endswiths with exact image repo name [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro falco_privileged_containers): append "/" to quay.io/sysdig [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(list falco_privileged_images): add images docker.io/sysdig/agent-slim and docker.io/sysdig/node-image-analyzer [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(list falco_sensitive_mount_images): add image docker.io/sysdig/agent-slim [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(list k8s_containers): prepend docker.io to images [[#1349](https://github.com/falcosecurity/falco/pull/1349)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(macro exe_running_docker_save): add better support for centos [[#1350](https://github.com/falcosecurity/falco/pull/1350)] - [@admiral0](https://github.com/admiral0)
* rule(macro rename): add `renameat2` syscall [[#1359](https://github.com/falcosecurity/falco/pull/1359)] - [@leogr](https://github.com/leogr)
* rule(Read sensitive file untrusted): add trusted images into whitelist [[#1327](https://github.com/falcosecurity/falco/pull/1327)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(Pod Created in Kube Namespace): add new list k8s_image_list as white list [[#1336](https://github.com/falcosecurity/falco/pull/1336)] - [@Kaizhe](https://github.com/Kaizhe)
* rule(list allowed_k8s_users): add "kubernetes-admin" user [[#1323](https://github.com/falcosecurity/falco/pull/1323)] - [@leogr](https://github.com/leogr)

## v0.24.0

Released on 2020-07-16

### Major Changes

* new: Falco now supports userspace instrumentation with the -u flag [[#1195](https://github.com/falcosecurity/falco/pull/1195)]
* BREAKING CHANGE: --stats_interval is now --stats-interval [[#1308](https://github.com/falcosecurity/falco/pull/1308)]
* new: auto threadiness for gRPC server [[#1271](https://github.com/falcosecurity/falco/pull/1271)]
* BREAKING CHANGE: server streaming gRPC outputs method is now `falco.outputs.service/get` [[#1241](https://github.com/falcosecurity/falco/pull/1241)]
* new: new bi-directional async streaming gRPC outputs (`falco.outputs.service/sub`)  [[#1241](https://github.com/falcosecurity/falco/pull/1241)]
* new: unix socket for the gRPC server [[#1217](https://github.com/falcosecurity/falco/pull/1217)]


### Minor Changes

* update: driver version is 85c88952b018fdbce2464222c3303229f5bfcfad now [[#1305](https://github.com/falcosecurity/falco/pull/1305)]
* update: `SKIP_MODULE_LOAD` renamed to `SKIP_DRIVER_LOADER` [[#1297](https://github.com/falcosecurity/falco/pull/1297)]
* docs: add leogr to OWNERS [[#1300](https://github.com/falcosecurity/falco/pull/1300)]
* update: default threadiness to 0 ("auto" behavior) [[#1271](https://github.com/falcosecurity/falco/pull/1271)]
* update: k8s audit endpoint now defaults to /k8s-audit everywhere [[#1292](https://github.com/falcosecurity/falco/pull/1292)]
* update(falco.yaml): `webserver.k8s_audit_endpoint` default value changed from `/k8s_audit` to `/k8s-audit` [[#1261](https://github.com/falcosecurity/falco/pull/1261)]
* docs(test): instructions to run regression test suites locally [[#1234](https://github.com/falcosecurity/falco/pull/1234)]


### Bug Fixes

* fix: --stats-interval correctly accepts values >= 999 (ms) [[#1308](https://github.com/falcosecurity/falco/pull/1308)]
* fix: make the eBPF driver build work on CentOS 8 [[#1301](https://github.com/falcosecurity/falco/pull/1301)]
* fix(userspace/falco): correct options handling for `buffered_output: false` which was not honored for the `stdout` output [[#1296](https://github.com/falcosecurity/falco/pull/1296)]
* fix(userspace/falco): honor -M also when using a trace file [[#1245](https://github.com/falcosecurity/falco/pull/1245)]
* fix: high CPU usage when using server streaming gRPC outputs [[#1241](https://github.com/falcosecurity/falco/pull/1241)]
* fix: missing newline from some log messages (eg., token bucket depleted) [[#1257](https://github.com/falcosecurity/falco/pull/1257)]


### Rule Changes

* rule(Container Drift Detected (chmod)): disabled by default [[#1316](https://github.com/falcosecurity/falco/pull/1316)]
* rule(Container Drift Detected (open+create)): disabled by default [[#1316](https://github.com/falcosecurity/falco/pull/1316)]
* rule(Write below etc): allow snapd to write its unit files [[#1289](https://github.com/falcosecurity/falco/pull/1289)]
* rule(macro remote_file_copy_procs): fix reference to remote_file_copy_binaries [[#1224](https://github.com/falcosecurity/falco/pull/1224)]
* rule(list allowed_k8s_users): whitelisted kube-apiserver-healthcheck user created by kops >= 1.17.0 for the kube-apiserver-healthcheck sidecar [[#1286](https://github.com/falcosecurity/falco/pull/1286)]
* rule(Change thread namespace): Allow `protokube`, `dockerd`, `tini` and `aws` binaries to change thread namespace. [[#1222](https://github.com/falcosecurity/falco/pull/1222)]
* rule(macro exe_running_docker_save): to filter out cmdlines containing `/var/run/docker`. [[#1222](https://github.com/falcosecurity/falco/pull/1222)]
* rule(macro user_known_cron_jobs): new macro to be overridden to list known cron jobs   [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Schedule Cron Jobs): exclude known cron jobs  [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_update_package_registry): new macro to be overridden to list known package registry update  [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Update Package Registry): exclude known package registry update [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_read_ssh_information_activities): new macro to be overridden to list known activities that read SSH info  [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Read ssh information): do not throw for activities known to read SSH info [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_read_sensitive_files_activities): new macro to be overridden to list activities known to read sensitive files [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Read sensitive file trusted after startup): do not throw for activities known to read sensitive files [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Read sensitive file untrusted): do not throw for activities known to read sensitive files [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_write_rpm_database_activities): new macro to be overridden to list activities known to write RPM database [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Write below rpm database): do not throw for activities known to write RPM database [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_db_spawned_processes): new macro to be overridden to list processes known to spawn DB [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(DB program spawned process): do not throw for processes known to spawn DB [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_modify_bin_dir_activities): new macro to be overridden to list activities known to modify bin directories [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Modify binary dirs): do not throw for activities known to modify bin directories [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_mkdir_bin_dir_activities): new macro to be overridden to list activities known to create directories below bin directories [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Mkdir binary dirs): do not throw for activities known to create directories below bin directories [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_system_user_login): new macro to exclude known system user logins [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(System user interactive): do not throw for known system user logins [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_user_management_activities): new macro to be overridden to list activities known to do user managements activities [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(User mgmt binaries): do not throw for activities known to do user managements activities [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_create_files_below_dev_activities): new macro to be overridden to list activities known to create files below dev [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Create files below dev): do not throw for activities known to create files below dev [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_contact_k8s_api_server_activities): new macro to be overridden to list activities known to contact Kubernetes API server [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Contact K8S API Server From Container): do not throw for activities known to contact Kubernetes API server [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_network_tool_activities): new macro to be overridden to list activities known to spawn/use network tools [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Launch Suspicious Network Tool in Container): do not throw for activities known to spawn/use network tools [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_remove_data_activities): new macro to be overridden to list activities known to perform data remove commands [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Remove Bulk Data from Disk): do not throw for activities known to perform data remove commands [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_create_hidden_file_activities): new macro to be overridden to list activities known to create hidden files [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Create Hidden Files or Directories): do not throw for activities known to create hidden files [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_stand_streams_redirect_activities): new macro to be overridden to list activities known to redirect stream to network connection (in containers) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Redirect STDOUT/STDIN to Network Connection in Container): do not throw for activities known to redirect stream to network connection (in containers) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_container_drift_activities): new macro to be overridden to list activities known to create executables in containers [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Container Drift Detected (chmod)): do not throw for activities known to give execution permissions to files in containers [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Container Drift Detected (open+create)): do not throw for activities known to create executables in containers [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_node_port_service): do not throw for services known to start with a NopePort service type (k8s) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Create NodePort Service): do not throw for services known to start with a NopePort service type (k8s) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro user_known_exec_pod_activities): do not throw for activities known to attach/exec to a pod (k8s) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Attach/Exec Pod): do not throw for activities known to attach/exec to a pod (k8s) [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro trusted_pod): defines trusted pods by an image list  [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Pod Created in Kube Namespace): do not throw for trusted pods [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(macro trusted_sa): define trusted ServiceAccount [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(Service Account Created in Kube Namespace): do not throw for trusted ServiceAccount [[#1294](https://github.com/falcosecurity/falco/pull/1294)]
* rule(list network_tool_binaries): add zmap to the list [[#1284](https://github.com/falcosecurity/falco/pull/1284)]
* rule(macro root_dir): correct macro to exactly match the `/root` dir and not other with just `/root` as a prefix [[#1279](https://github.com/falcosecurity/falco/pull/1279)]
* rule(macro user_expected_terminal_shell_in_container_conditions): allow whitelisting terminals in containers under specific conditions [[#1154](https://github.com/falcosecurity/falco/pull/1154)]
* rule(macro user_known_write_below_binary_dir_activities): allow writing to a binary dir in some conditions [[#1260](https://github.com/falcosecurity/falco/pull/1260)]
* rule(macro trusted_logging_images): Add addl fluentd image [[#1230](https://github.com/falcosecurity/falco/pull/1230)]
* rule(macro trusted_logging_images): Let azure-npm image write to /var/log [[#1230](https://github.com/falcosecurity/falco/pull/1230)]
* rule(macro lvprogs_writing_conf): Add lvs as a lvm program [[#1230](https://github.com/falcosecurity/falco/pull/1230)]
* rule(macro user_known_k8s_client_container): Allow hcp-tunnelfront to run kubectl in containers [[#1230](https://github.com/falcosecurity/falco/pull/1230)]
* rule(list allowed_k8s_users): Add vertical pod autoscaler as known k8s users [[#1230](https://github.com/falcosecurity/falco/pull/1230)]
* rule(Anonymous Request Allowed): update to checking auth decision equals to allow [[#1267](https://github.com/falcosecurity/falco/pull/1267)]
* rule(Container Drift Detected (chmod)): new rule to detect if an existing file get exec permissions in a container [[#1254](https://github.com/falcosecurity/falco/pull/1254)]
* rule(Container Drift Detected (open+create)): new rule to detect if a new file with execution permission is created in a container [[#1254](https://github.com/falcosecurity/falco/pull/1254)]
* rule(Mkdir binary dirs): correct condition in macro `bin_dir_mkdir` to catch `mkdirat` syscall [[#1250](https://github.com/falcosecurity/falco/pull/1250)]
* rule(Modify binary dirs): correct condition in macro `bin_dir_rename` to catch `rename`, `renameat`, and `unlinkat` syscalls [[#1250](https://github.com/falcosecurity/falco/pull/1250)]
* rule(Create files below dev): correct condition to catch `openat` syscall [[#1250](https://github.com/falcosecurity/falco/pull/1250)]
* rule(macro user_known_set_setuid_or_setgid_bit_conditions): create macro [[#1213](https://github.com/falcosecurity/falco/pull/1213)]

## v0.23.0

Released on 2020-05-18

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

Released on 2020-04-17

### Major Changes

* Same as v0.22.0

### Minor Changes

* Same as v0.22.0

### Bug Fixes

* fix: correct driver path (/usr/src/falco-%driver_version%) for RPM package [[#1148](https://github.com/falcosecurity/falco/pull/1148)]

### Rule Changes

* Same as v0.22.0

## v0.22.0

Released on 2020-04-16

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
* rule(write below etc): allow writes to /etc/pki from openshift secrets dir [[#1028](https://github.com/falcosecurity/falco/pull/1028)]
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
* fix: prevent throwing json type error c++ exceptions outside of the falco engine when processing k8s audit events. [[#928](https://github.com/falcosecurity/falco/pull/928)]
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

* Allow rule priorities to be expressed as lowercase and a mix of lower/uppercase [[#737](https://github.com/falcosecurity/falco/pull/737)]

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

* Several small docs changes to improve clarity and readability [[#524](https://github.com/falcosecurity/falco/pull/524)] [[#540](https://github.com/falcosecurity/falco/pull/540)] [[#541](https://github.com/falcosecurity/falco/pull/541)] [[#542](https://github.com/falcosecurity/falco/pull/542)]

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

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, `Launch Suspicious Network Tool in Container` look for host-level network tools like `netcat`, package management tools like `apt-get`, or network tool binaries being run in a container. [[#490](https://github.com/falcosecurity/falco/pull/490)]

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

* New rules `Launch Package Management Process in Container`, `Netcat Remote Code Execution in Container`, and `Launch Suspicious Network Tool in Container` look for running various suspicious programs in a container. [[#461](https://github.com/falcosecurity/falco/pull/461)]

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

* Rules may now have an `skip-if-unknown-filter` property. If set to true, a rule will be skipped if its condition/output property refers to a filtercheck (e.g. `fd.some-new-attribute`) that is not present in the current falco version. [[#364](https://github.com/draios/falco/pull/364)] [[#345](https://github.com/draios/falco/issues/345)]
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

**Important**: the location for falco's configuration file has moved from `/etc/falco.yaml` to `/etc/falco/falco.yaml`. The default rules file has moved from `/etc/falco_rules.yaml` to `/etc/falco/falco_rules.yaml`. In addition, 0.8.0 has added a _local_ rules file to `/etc/falco/falco_rules.local.yaml`. See [the documentation](https://github.com/draios/falco/wiki/Falco-Default-and-Local-Rules-Files) for more details.

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
