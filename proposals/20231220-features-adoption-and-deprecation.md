# Features Adoption and Deprecation Policies Proposal

This proposal aims to introduce a balance between maintaining adopter trust and the need for The Falco Project to evolve. Historically, Falco has favored rapid evolution over providing long-term support for features and interfaces. However, some project subsystems have been implicitly assumed not to allow backward-incompatible changes (e.g., we have almost never removed a condition syntax field). These implicit conventions have never been formalized, and decisions in this regard have been left unspecified.

## Goals

- Establish adopter expectations on the operational cost of using Falco.
- Provide a clear path for features to be adopted and dismissed.
- Allow quick evolution and experimentation without disrupting our adopters' deployments.
- Detail the process for introducing new features, following a "sandbox" to "incubating" to "stable" progression.
- Define the scope of the policy, including which aspects of Falco are covered (e.g., command line flags, configuration files, rules syntax).
- Establish stages for deprecating features, aligning with the project's current status (pre- and post-1.0 stages).
- Adopt a semantic versioning (semver) approach.

## Non-Goals

- Define the number of previous releases that will receive patches or security updates and the duration of this support.
- Define the criteria for Falco 1.0.

## Scope

The proposed policies apply to Falco, its subsystems (e.g., rules, the plugin system), and all [core projects](https://github.com/falcosecurity/evolution#core) which are deemed [stable](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable), thus officially supported by The Falco Project.

## Definitions

### Feature Changes

A feature is a distinct and specific functionality or characteristic of Falco and its core components that provides value to the user by enabling them to perform particular tasks. Features encompass aspects such as functionality, user value, usability, integrability, scalability, configurability, and discoverability. Features can range from essential user interface elements to complex, multifunctional operations.

A feature change refers to any modification or update to an existing feature or the addition of a new feature. This does not include documentation, Falco compatibility across different environments, platforms, systems, or other software or hardware, bug fixing (stated it does not require a feature change to overcome the problem), and performance (unless a change produces a measurable effect on usability).

### Behavior Changes

A behavior change refers to alterations in how Falco, or a specific feature within it, operates or responds under certain conditions. Unlike feature changes, behavior changes are more about tweaking the underlying logic or the way existing features interact or perform, particularly the expected behavior of Falco when run with the default configuration.

Behaviors are generally documented. Any modification that does not meet the conditions and expectations of an already documented feature is assumed to be a behavior change.

Undocumented behaviors may be included in this definition if there's strong evidence or suspicion that users rely on those undocumented behaviors.

### User-Facing Changes

User-facing changes refer to any feature changes, behavior changes, modifications, or additions that are directly noticeable and interactable by the end users. These changes affect how Falco operates from the user's perspective (notably any change that can lead to user disruption). Unlike internal changes (i.e., code refactoring, CI, maintenance-related changes), which are under-the-hood improvements not directly visible to the user, user-facing changes are evident in the Falco and its core components interface and functionality.

### CLI/Config Area

Falco is comprised of the Falco binary and other programs and tools cooperating (notably [falcoctl](https://github.com/falcosecurity/falcoctl)). These programs are the primary user interface for Falco. Any feature or behavior changes to the following elements of these programs are assumed to be user-facing changes to the CLI/Config area:

- Program name.
- Distribution mechanism and packaging (e.g., a container image).
- Command line flags and options.
- Environment variables.
- Configurations.
- Elements that affect the program's lifecycle (e.g., the effect of sending a SIGINT to the program).
- Elements that allow scripting, automation, or interaction with other programs (e.g., piping and redirection).
- Program inputs, excluding elements explicitly governed by other areas (e.g., [Falco rules](#rules-area)).
- Program outputs excluding elements explicitly governed by other areas (e.g., [Falco outputs/alerts](#outputs-alerts-area)).

### Rules System Area

Rules are the primary input for Falco. Any feature or behavior changes to the following aspects or elements are assumed to be user-facing changes to the rules system area:

- Syntax.
- File format.
- Schema (i.e., supported fields).
- Elements that affect the way users can implement rules.
- Elements that affect the way rules are triggered.

However, any change related to the rule's output when triggered (i.e., the alert) is out of scope for this area (see next section).

Note that this area does not include changes related to the ruleset files. Ruleset distributions follow their own [Rules Maturity Framework](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#rules-maturity-framework) policies. 

### Outputs/Alerts Area

Alerts, delivered through Falco output channels, are Falco's primary output. The way and the format in which alerts are produced can have a significant impact on adopters. For example, removing a supported rule field also impacts this area, as adopters may have relied on that field when consuming Falco output.

Any feature or behavior changes to the following aspects or elements are assumed to be user-facing changes to the Outputs/Alerts area:

- Output and logging formats.
- Schema of outputted data (i.e., supported fields).
- Falco output channels.
- Any element that might be consumed from the output.

### Subsystem APIs (Plugins, gRPC Output, Metrics, etc.) Area

Falco is also comprised of several subsystems providing specific APIs. These subsystems notably include plugin system API, gRPC output API, and metrics API.

In the context of this proposal, only changes to **public APIs** are assumed to be user-facing changes to this area.

Public APIs are defined as those supporting Falco functioning and explicitly intended for user usage. Internal APIs consumed by Falco or other tools are out of scope for this area. For instance, the driver APIs or libs APIs are intended to be mainly consumed by Falco and not by users.

### Platform Support Area

Platform support for Falco encompasses the range of platforms, systems, and environments it is designed to operate in. Platform support may significantly vary by Falco's data sources and use cases. For example, its compatibility differs when utilized for Kubernetes audit events versus system call events. Additionally, platform support can be influenced by deployment methods (e.g., directly on a host versus within Kubernetes) or configurations (e.g., running in privileged versus least privileged mode).

Given the diversity of potential platforms and setups, only those explicitly listed in Falco's documentation are considered officially supported. While Falco may function on other platforms, official support is guaranteed solely for documented ones.

Therefore, changes in platform compatibility or behavior that are documented explicitly assumed to be user-facing changes to the Platform Support area.

### Release Cycle

In the context of this proposal, a release cycle is the period between two consecutive major or minor releases of Falco. Hotfix/Patch releases must not be counted.

The actual duration of a release cycle can vary. Still, it's assumed to be about 16 weeks (as per our current defined [Release Cycles and Development Iterations](https://github.com/falcosecurity/falco/blob/master/proposals/20230511-roadmap-management.md#release-cycles-and-development-iterations)). In case of future modification to the Falco release schedule, a period of minimum 3 months must be assumed.

## Proposal

### Maturation Levels

Maturation levels (inspired by those we already have in place for [repositories](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#status)) are used to characterize the maturity of a feature. Each feature will have an assigned level  at any specific time (i.e., a Falco release). Levels are shown in the table below.

| Maturity Level | Intended for |
| --- | --- |
| Sandbox |  Experimental/alpha features, not recommended for production use, can be removed at any time without further notice. |
| Incubating | Beta features, long-term support is not guaranteed. |
| Stable | General Availability (GA) features for which long-term support is expected. |
| Deprecated | See the [deprecation policy](#Deprecation-policy) section below. |

### Adoption Policy

The adoption policy applies to any backward compatible user-facing changes which add functionalities. For non-backward compatible changes see the [deprecation policy](#Deprecation-policy) below.

**Adoption rules**:
1. A feature can be introduced at only one of the following levels:
   - Sandbox: The feature must be opt-in (e.g., not enabled by default), labeled as *Sandbox* and the user must be proactively informed by the experimental nature of the feature (i.e. emitting a notice when the feature is being enabled).
   - Incubating: The feature must be labeled as *Incubating*.
2. Any functionality additions to an existing feature are inherently introduced at the same level as the feature itself unless logically separable (for instance, a sub-feature that may be enabled separately).
3. A feature can be promoted *from Sandbox to Incubating* or *from Incubating to Stable* only after at least one release cycle has passed without user-facing changes to the feature.
4. A feature cannot be demoted to a previous level.


_Note about behaviors_:
This policy indirectly applies to behaviors, too. Behavior changes are assumed to be a consequence of a feature change. The adoption level of a documented behavior is considered to be the same as the related feature. Furthermore, behavior changes are particularly relevant in the context of deprecation (see the next section).


### Deprecation Policy

The deprecation policy applies to any non-backward compatible user-facing changes. Any other changes introduced in a backward-compatible manner does not fall under the scope of this deprecation policy.

**Deprecation rules**:
1. Sandbox features can be removed or changed at any time without notice. No deprecation period is required.
2. Incubating or Stable features and documented behaviors must enter a deprecation period and function for no less than the indicated release cycles (see tables below) after their announced deprecation. 
   - If the change affects the feature partially, the deprecation applies only to that feature part. 
   - If the change removes the feature entirely, the deprecation applies to the entire feature.
3. At least for the entire deprecation period, the feature must be labeled as *Deprecated* in all relevant documentation, and:
   - for deprecated configurations or CLI elements, a warning must be emitted warnings when the feature is being enabled or used;
   - for deprecated APIs, when technically feasible, the API should be signal the deprecation status (this may vary depending on the specific subsystem);
   - for deprecated behaviors the documentation must highlight the _before_ and _after_ behavior, alongside with a prominent deprecation notice.
4. Any Pull Request introducing a deprecation notice must be labeled and include a note in the format `DEPRECATION NOTICE: ...`.
5. Any Pull Request introducing a breaking change due to the end of the deprecation notice period must be labeled and include a note in the format `BREAKING CHANGE: ...`. 
   - It is also recommended for code commits that introduce a breaking change to follow the related [conventional commit spec](https://www.conventionalcommits.org/en/v1.0.0/#specification).

The minimum deprecation period length depends on the affected area. If a single change spans multiple areas, the area with the most extended deprecation period is assumed. Longer deprecation periods are allowed if the feature is deemed to be particularly critical or widely used.

#### Deprecation Period Lengths

_The units represent the number of releases._

##### Before Falco 1.0

| Area           | Stable | Incubating |
| -------------- | ------ | ---------- |
| *all areas*    | 1      | 0          |

##### Since Falco 1.0 onward

| Area           | Stable | Incubating |
| -------------- | ------ | ---------- |
| Behaviors      | 2      | 1          |
| Rules System   | 2      | 1          |
| Output/Alerts  | 2      | 1          |
| Platform       | 2      | 1          |
| CLI/Config     | 1      | 1          |
| Subsystem APIs | 1      | 0          |

### Examples

**Example 1** Let's consider a feature _foo_ in the Output/Alerts Area introduced in Falco 1.0.0 and labeled as *Incubating*. The feature is promoted to *Stable* in Falco 1.1.0 (because the feature did not get any user-facing change).
Subsequently, maintainers decide that backward-compatible changes must be introduced in _foo_ to improve its functionality. The part of the feature to be changed is labeled as *Deprecated* in Falco 1.2.0, and the deprecation period starts. The non-backward compatible change is then introduced in Falco 1.4.0.

**Example 2** The `--bar` flag in the CLI/Config Area has been introduced since Falco 1.1.0 and is labeled as *Stable*. Before releasing Falco 1.5.0, maintainers realize `--bar` is redundant and should be removed. The flag is labeled as *Deprecated* in Falco 1.5.0, and the deprecation period starts. The flag is removed in Falco 1.6.0.

### Exceptions

- Ruleset in the official distributions follow the [Rules Maturity Framework](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#rules-maturity-framework) policies.
- Subsystems or subcomponents may have additional criteria and exceptions. Stated other criteria and exceptions must not directly affect the main Falco distribution (e.g., *falcoctl* can have a different release cycle and different policies; however, if Falco relies on a specific *falcoctl* feature, that *falcoctl* feature adoption and deprecation must be strictly compatible with the rules described in this proposal).
- Internal APIs are out of scope for this policy. Their adoption models and deprecation policies might be regulated separately.
- Different parties may provide plugins, and each plugin may have a different maturity level. Only those plugins officially maintained by The Falco Project and identified as "core" for Falco are in scope for this policy; all others are excluded.
- Any other exceptions to the rules provided by this policy require a formal core maintainer majority vote.

### Versioning

Regarding the above policies, component versioning must adhere to [Semantic Versioning 2.0.0](https://semver.org/). However, in the context of Falco core components, the scope extends beyond the strict API definition and includes any user-facing changes.

Thus, given a version number `MAJOR.MINOR.PATCH` increment the:

- *MAJOR* version when the deprecation period of one or more _stable_ features ends, thus introducing incompatible user-facing or API changes.
- *MINOR* version when adding functionality in a backward-compatible manner.
- *PATCH* version when making backward-compatible bug fixes.

Moreover, *MAJOR* version zero (0.y.z) is for versioning stabilization (i.e., before defining the public set of user-facing features and APIs). At this stage, the *MINOR* version is allowed to be incremented instead of the *MAJOR* version.

### Documentation

Documentation must be tied to a specific release and reflect the adoption level status of a feature at that specific release. In particular:

- Deprecated items must be labeled `DEPRECATED` in all relevant documentation.
- Stable items must be sufficiently documented. Explicitly labeling the Stable status is not required or recommended.
- Incubating items must be sufficiently documented and labeled  `INCUBATING` in all relevant documentation.
- Sandbox items may be partially documented and labeled `SANDBOX` in all relevant documentation, if any. The relevant documentation must also explicitly state the experimental nature of the item.

## Transition Phases

Since software components may need to adapt to implement the requirements this proposal mandates, we assume the following stages are required to transition from the current state to the desired state fully:

- Within Falco 0.38, at least stable features must be identified, and the adoption policy and relevant documentation should be implemented in Falco. Exceptions may be made temporarily for the deprecation policy.
- Within subsequent releases and no later than Falco 1.0.0 (still not scheduled to date), all the policies must be strictly implemented in Falco and documented in [falco.org](falco.org). The [Rules Maturity Framework](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#rules-maturity-framework) must be adapted to ensure it aligns with the spirit of this proposal. Exceptions may be made temporarily for other [core projects](https://github.com/falcosecurity/evolution#core) with [stable](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) status, assuming exceptions don't severely affect the main Falco distribution.
- Within Falco 1.1.0, all the policies must be strictly implemented in Falco and in all [core projects](https://github.com/falcosecurity/evolution#core) with [stable](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) status.

During the transition phases, maintainers can fine-tune these policies and add further exceptions, eventually. After this initial transition phases, the policy is assumed to be established. From then on, any policy modifications, updates, and exceptions must be subject to a core maintainer majority vote to ensure the policy remains relevant and practical.
