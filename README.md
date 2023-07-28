# Falco

[![Latest release](https://img.shields.io/github/v/release/falcosecurity/falco?style=for-the-badge)](https://github.com/falcosecurity/falco/releases/latest) [![Supported Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=for-the-badge)](https://github.com/falcosecurity/falco/releases/latest) [![License](https://img.shields.io/github/license/falcosecurity/falco?style=for-the-badge)](COPYING) [![Docs](https://img.shields.io/badge/docs-latest-green.svg?style=for-the-badge)](https://falco.org/docs)

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable)  [![OpenSSF Best Practices](https://img.shields.io/cii/summary/2317?label=OpenSSF%20Best%20Practices&style=for-the-badge)](https://bestpractices.coreinfrastructure.org/projects/2317)

[![Falco](https://falco.org/img/brand/falco-horizontal-color.svg)](https://falco.org)

[Falco](https://falco.org/) is a cloud native runtime security tool for Linux operating systems. It is designed to detect and alert on abnormal behavior and potential security threats in real-time.

At its core, Falco is a kernel monitoring and detection agent that observes events, such as syscalls, based on custom rules. Falco can enhance these events by integrating metadata from the container runtime and Kubernetes. The collected events can be analyzed off-host in SIEM or data lake systems.

Falco, originally created by [Sysdig](https://sysdig.com), is an incubating project under the [Cloud Native Computing Foundation](https://cncf.io) (CNCF) used in producation by various [organisations](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md).

For detailed technical information and insights into the cyber threats that Falco can detect, visit the official [Falco](https://falco.org/) website.

For comprehensive information on the latest updates and changes to the project, please refer to the [change log](CHANGELOG.md). Additionally, we have documented the [release process](RELEASE.md) for delivering new versions of Falco.

## Falco Repo: Powering the Core of The Falco Project

This is the main Falco repository which contains the source code for building the Falco binary. By utilizing its [libraries](https://github.com/falcosecurity/libs) and the [falco.yaml](falco.yaml) configuration file, this repository forms the foundation of Falco's functionality. The Falco repository is closely interconnected with the following *core* repositories:

- [falcosecurity/libs](https://github.com/falcosecurity/libs): Falco's libraries are key to its fundamental operations, making up the greater portion of the source code of the Falco binary and providing essential features such as kernel drivers.
- [falcosecurity/rules](https://github.com/falcosecurity/rules): Contains the official ruleset for Falco, providing pre-defined detection rules for various security threats and abnormal behaviors.
- [falcosecurity/plugins](https://github.com/falcosecurity/plugins/): Falco plugins facilitate integration with external services, expand Falco's capabilities beyond syscalls and container events, and are designed to evolve with specialized functionality in future releases.
- [falcosecurity/falcoctl](https://github.com/falcosecurity/falcoctl): Command-line utility for managing and interacting with Falco.

For more information, visit the official hub of The Falco Project: [falcosecurity/evolution](https://github.com/falcosecurity/evolution). It provides valuable insights and information about the project's repositories.

## Getting Started with Falco

Carefully review and follow the [official guide and documentation](https://falco.org/docs/getting-started/).

Considerations and guidance for Falco adopters:

1. Understand dependencies: Assess the environment where you'll run Falco and consider kernel versions and architectures.

2. Define threat detection objectives: Clearly identify the threats you want to detect and evaluate Falco's strengths and limitations.

3. Consider performance and cost: Assess compute performance overhead and align with system administrators or SREs. Budget accordingly.

4. Choose build and customization approach: Decide between the open source Falco build or creating a custom build pipeline. Customize the build and deployment process as necessary, including incorporating unique tests or approaches, to ensure a resilient deployment with fast deployment cycles.

5. Integrate with output destinations: Integrate Falco with SIEM, data lake systems, or other preferred output destinations to establish a robust foundation for comprehensive data analysis and enable effective incident response workflows.


## How to Contribute

Please refer to the [contributing guide](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) and the [code of conduct](https://github.com/falcosecurity/evolution/CODE_OF_CONDUCT.md) for more information on how to contribute.


## Join the Community

To get involved with the Falco Project please visit the [community repository](https://github.com/falcosecurity/community) to find more information and ways to get involved.

If you have any questions about Falco or contributing, do not hesitate to file an issue or contact the Falco maintainers and community members for assistance.

How to reach out?

 - Join the [#falco](https://kubernetes.slack.com/messages/falco) channel on the [Kubernetes Slack](https://slack.k8s.io).
 - Join the [Falco mailing list](https://lists.cncf.io/g/cncf-falco-dev).
 - File an [issue](https://github.com/falcosecurity/falco/issues) or make feature requests.

## Commitment to Falco's Own Security

Full reports of various security audits can be found [here](./audits/).

In addition, you can refer to the [falco security](https://github.com/falcosecurity/falco/security) and [libs security](https://github.com/falcosecurity/libs/security) sections for detailed updates on security advisories and policies.

To report security vulnerabilities, please follow the community process outlined in the documentation found [here](https://github.com/falcosecurity/.github/blob/main/SECURITY.md).

## What's next for Falco?

Stay updated with Falco's evolving capabilities by exploring the [Falco Roadmap](https://github.com/orgs/falcosecurity/projects/5), which provides insights into the features currently under development and planned for future releases.


## License

Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.

## Resources

 - [Governance](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md)
 - [Code Of Conduct](https://github.com/falcosecurity/evolution/blob/main/CODE_OF_CONDUCT.md)
 - [Maintainers Guidelines](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS_GUIDELINES.md)
 - [Maintainers List](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS.md)
 - [Repositories Guidelines](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md)
 - [Repositories List](https://github.com/falcosecurity/evolution/blob/main/README.md#repositories)
 - [Adopters List](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md)
