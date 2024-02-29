# Falco

[![Latest release](https://img.shields.io/github/v/release/falcosecurity/falco?style=for-the-badge)](https://github.com/falcosecurity/falco/releases/latest) [![Supported Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=for-the-badge)](https://github.com/falcosecurity/falco/releases/latest) [![License](https://img.shields.io/github/license/falcosecurity/falco?style=for-the-badge)](COPYING) [![Docs](https://img.shields.io/badge/docs-latest-green.svg?style=for-the-badge)](https://falco.org/docs)

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable)  [![OpenSSF Best Practices](https://img.shields.io/cii/summary/2317?label=OpenSSF%20Best%20Practices&style=for-the-badge)](https://bestpractices.coreinfrastructure.org/projects/2317) <a href="https://actuated.dev/"><img alt="Arm CI sponsored by Actuated" src="https://docs.actuated.dev/images/actuated-badge.png" width="120px"></img></a>

[![Falco](https://falco.org/img/brand/falco-horizontal-color.svg)](https://falco.org)

[Falco](https://falco.org/) is a cloud native runtime security tool for Linux operating systems. It is designed to detect and alert on abnormal behavior and potential security threats in real-time.

At its core, Falco is a kernel monitoring and detection agent that observes events, such as syscalls, based on custom rules. Falco can enhance these events by integrating metadata from the container runtime and Kubernetes. The collected events can be analyzed off-host in SIEM or data lake systems.

Falco, originally created by [Sysdig](https://sysdig.com), is a **graduated project** under the [Cloud Native Computing Foundation](https://cncf.io) (CNCF) used in production by various [organisations](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md).

For detailed technical information and insights into the cyber threats that Falco can detect, visit the official [Falco](https://falco.org/) website.

For comprehensive information on the latest updates and changes to the project, please refer to the [Change Log](CHANGELOG.md). Additionally, we have documented the [Release Process](RELEASE.md) for delivering new versions of Falco.

## Falco Repo: Powering the Core of The Falco Project

This is the main Falco repository which contains the source code for building the Falco binary. By utilizing its [libs](https://github.com/falcosecurity/libs) and the [falco.yaml](falco.yaml) configuration file, this repository forms the foundation of Falco's functionality. The Falco repository is closely interconnected with the following *core* repositories:

- [falcosecurity/libs](https://github.com/falcosecurity/libs): Falco's libraries are key to its fundamental operations, making up the greater portion of the source code of the Falco binary and providing essential features such as kernel drivers.
- [falcosecurity/rules](https://github.com/falcosecurity/rules): Contains the official ruleset for Falco, providing pre-defined detection rules for various security threats and abnormal behaviors.
- [falcosecurity/plugins](https://github.com/falcosecurity/plugins/): Falco plugins facilitate integration with external services, expand Falco's capabilities beyond syscalls and container events, and are designed to evolve with specialized functionality in future releases.
- [falcosecurity/falcoctl](https://github.com/falcosecurity/falcoctl): Command-line utility for managing and interacting with Falco.

For more information, visit the official hub of The Falco Project: [falcosecurity/evolution](https://github.com/falcosecurity/evolution). It provides valuable insights and information about the project's repositories.

## Getting Started with Falco

Carefully review and follow the [Official Documentation](https://falco.org/docs/install-operate/).

Considerations and guidance for Falco adopters:

1. Understand dependencies: Assess the environment where you'll run Falco and consider kernel versions and architectures.

2. Define threat detection objectives: Clearly identify the threats you want to detect and evaluate Falco's strengths and limitations.

3. Consider performance and cost: Assess compute performance overhead and align with system administrators or SREs. Budget accordingly.

4. Choose build and customization approach: Decide between the open source Falco build or creating a custom build pipeline. Customize the build and deployment process as necessary, including incorporating unique tests or approaches, to ensure a resilient deployment with fast deployment cycles.

5. Integrate with output destinations: Integrate Falco with SIEM, data lake systems, or other preferred output destinations to establish a robust foundation for comprehensive data analysis and enable effective incident response workflows.


## How to Contribute

Please refer to the [Contributing](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) guide and the [Code of Conduct](https://github.com/falcosecurity/evolution/blob/main/CODE_OF_CONDUCT.md) for more information on how to contribute.

## Join the Community

To get involved with the Falco Project please visit the [Community](https://github.com/falcosecurity/community) repository to find more information and ways to get involved.

If you have any questions about Falco or contributing, do not hesitate to file an issue or contact the Falco maintainers and community members for assistance.

How to reach out?

 - Join the [#falco](https://kubernetes.slack.com/messages/falco) channel on the [Kubernetes Slack](https://slack.k8s.io).
 - Join the [Falco mailing list](https://lists.cncf.io/g/cncf-falco-dev).
 - File an [issue](https://github.com/falcosecurity/falco/issues) or make feature requests.

## Commitment to Falco's Own Security

Full reports of various security audits can be found [here](./audits/).

In addition, you can refer to the [falco](https://github.com/falcosecurity/falco/security) and [libs](https://github.com/falcosecurity/libs/security) security sections for detailed updates on security advisories and policies.

To report security vulnerabilities, please follow the community process outlined in the documentation found [here](https://github.com/falcosecurity/.github/blob/main/SECURITY.md).

## What's next for Falco?

Stay updated with Falco's evolving capabilities by exploring the [Falco Roadmap](https://github.com/orgs/falcosecurity/projects/5), which provides insights into the features currently under development and planned for future releases.

## License

Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.

## Testing

<details>
	<summary>Expand Testing Instructions</summary>

Falco's [Build Falco from source](https://falco.org/docs/install-operate/source/) is the go-to resource to understand how to build Falco from source. In addition, the [falcosecurity/libs](https://github.com/falcosecurity/libs) repository offers additional valuable information about tests and debugging of Falco's underlying libraries and kernel drivers.

Here's an example of a `cmake` command that will enable everything you need for all unit tests of this repository:

```bash
cmake \
-DUSE_BUNDLED_DEPS=ON \
-DBUILD_LIBSCAP_GVISOR=ON \
-DBUILD_BPF=ON \
-DBUILD_DRIVER=ON \
-DBUILD_FALCO_MODERN_BPF=ON \
-DCREATE_TEST_TARGETS=ON \
-DBUILD_FALCO_UNIT_TESTS=ON ..;
```

Build and run the unit test suite:

```bash
nproc=$(grep processor /proc/cpuinfo | tail -n 1 | awk '{print $3}');
make -j$(($nproc-1)) falco_unit_tests;
# Run the tests
sudo ./unit_tests/falco_unit_tests;
```

Optionally, build the driver of your choice and test run the Falco binary to perform manual tests.

Lastly, The Falco Project has moved its Falco regression tests to [falcosecurity/testing](https://github.com/falcosecurity/testing).


</details>

</br>

## Why is Falco in C++ rather than Go or {language}?

<details>
	<summary>Expand Information</summary>

1. The first lines of code at the base of Falco were written some time ago, where Go didn't yet have the same level of maturity and adoption as today.
2. The Falco execution model is sequential and mono-thread due to the statefulness requirements of the tool, and so most of the concurrency-related selling points of the Go runtime would not be leveraged at all.
3. The Falco code deals with very low-level programming in many places (e.g. some headers are shared with the eBPF probe and the Kernel module), and we all know that interfacing Go with C is possible but brings tons of complexity and tradeoffs to the table.
4. As a security tool meant to consume a crazy high throughput of events per second, Falco needs to squeeze performance in all hot paths at runtime and requires deep control on memory allocation, which the Go runtime can't provide (there's also garbage collection involved).
5. Although Go didn't suit the engineering requirements of the core of Falco, we still thought that it could be a good candidate for writing Falco extensions through the plugin system. This is the main reason we gave special attention and high priority to the development of the plugin-sdk-go.
6. Go is not a requirement for having statically-linked binaries. In fact, we provide fully-static Falco builds since few years. The only issue with those is that the plugin system can't be supported with the current dynamic library model we currently have.
7. The plugin system has been envisioned to support multiple languages, so on our end maintaining a C-compatible codebase is the best strategy to ensure maximum cross-language compatibility.
8. In general, plugins have GLIBC requirements/dependencies because they have low-level C bindings required for dynamic loading. A potential solution for the future could be to also support plugin to be statically-linked at compilation time and so released as bundled in the Falco binary. Although no work started yet in this direction, this would solve most issues you reported and would provide a totally-static binary too. Of course, this would not be compatible with dynamic loading anymore, but it may be a viable solution for our static-build flavor of Falco.
9. Memory safety is definitely a concern and we try our best to keep an high level of quality even though C++ is quite error prone. For instance, we try to use smart pointers whenever possible, we build the libraries with an address sanitizer in our CI, we run Falco through Valgrind before each release, and have ways to stress-test it to detect performance regressions or weird memory usage (e.g. https://github.com/falcosecurity/event-generator). On top of that, we also have third parties auditing the codebase by time to time. None of this make a perfect safety standpoint of course, but we try to maximize our odds. Go would definitely make our life easier from this perspective, however the tradeoffs never made it worth it so far due to the points above.
10. The C++ codebase of falcosecurity/libs, which is at the core of Falco, is quite large and complex. Porting all that code to another language would be a major effort requiring lots of development resource and with an high chance of failure and regression. As such, our approach so far has been to choose refactors and code polishing instead, up until we'll reach an optimal level of stability, quality, and modularity, on that portion of code. This would allow further developments to be smoother and more feasibile in the future.

</details>
</br>

## Resources

 - [Governance](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md)
 - [Code Of Conduct](https://github.com/falcosecurity/evolution/blob/main/CODE_OF_CONDUCT.md)
 - [Maintainers Guidelines](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS_GUIDELINES.md)
 - [Maintainers List](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS.md)
 - [Repositories Guidelines](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md)
 - [Repositories List](https://github.com/falcosecurity/evolution/blob/main/README.md#repositories)
 - [Adopters List](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md)
 - [Install and Operate](https://falco.org/docs/install-operate/)
 - [Troubleshooting](https://falco.org/docs/troubleshooting/)
