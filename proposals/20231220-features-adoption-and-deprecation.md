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

### Rules Area

Rules are the primary input for Falco. Any feature or behavior changes to the following aspects or elements are assumed to be user-facing changes to the rules area:

- Syntax.
- File format.
- Schema (i.e., supported fields).
- Elements that affect the way users can implement rules.
- Elements that affect the way rules are triggered.

However, any change related to the rule's output when triggered (i.e., the alert) is out of scope for this area (see next section).

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

### Release Cycle

In the context of this proposal, a release cycle is the period between two consecutive major or minor releases of Falco. Hotfix/Patch releases must not be counted.

The actual duration of a release cycle can vary. Still, it's assumed to be about 16 weeks (as per our current defined [Release Cycles and Development Iterations](https://github.com/falcosecurity/falco/blob/master/proposals/20230511-roadmap-management.md#release-cycles-and-development-iterations)). In case of future modification to the Falco release schedule, a period of minimum 3 months must be assumed.

## Proposal

### Adoption Policy

Feature additions will follow a straightforward adoption model with defined status levels (inspired by those we already have in place for [repositories](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#status)) aiming to characterize the current maturity level.

Each feature will have an assigned status level at any specific time (i.e., a Falco release). Statuses are shown in the table below.

| Status | Feature Gate | Intended for |
| --- | --- | --- |
| Sandbox | Disabled by default | Experimental/alpha features, not recommended for production use, can be removed at any time without further notice. |
| Incubating | Enabled by default | Beta features, long-term support is not guaranteed. |
| Stable | No feature gate needed. All features with this status are always enabled. | General Availability (GA) features for which long-term support is expected. |
| Deprecated | Enabled by default | See the [deprecation policy](#Deprecation-policy) section below. |

**Adoption rules**:
1. Only Sandbox or Incubating status can be assigned (at the maintainers' discretion) when introducing a new feature. Incubating is the recommended path.
2. A feature can be promoted to a higher status level only after at least one release cycle has passed without user-facing changes to the feature.
3. Demoting a feature to a lower status is not allowed; use deprecation instead.

_Note_: 
 - Behavior additions are assumed to be a consequence of a feature introduction, so this adoption policy does not directly apply to behaviors. However, behavior changes are still relevant in the context of deprecation.

#### Feature Gates

Implementing a features gate config option is mandatory for the Falco binary and recommended for other tools where applicable.

For Falco, the suggested configuration option and defaults are as follows:

```yaml
feature_gates:
    sandbox: false
    incubating: true
    deprecated: true
```
The feature gates are a global configuration. For instance, if a specific status level is enabled, all features with that status will be activated in bulk. 

Other configuration schemes are allowed for specific areas. For instance, the rules area can be configured either by [loading files or using rules tags](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#overall-guidelines). This aligns perfectly with this proposal, provided the feature gate configuration is officially documented.


### Deprecation Policy

The deprecation policy applies to any non-backward compatible user-facing changes. Adding functionality in a backward-compatible manner or bug fixes do not fall under the scope of this deprecation policy.

**Deprecation Rules**:
1. Sandbox features can be deprecated at any time without notice.
2. Incubating/Stable features and documented behaviors must enter a deprecation period and function for no less than the indicated release cycle (see tables below) after their announced deprecation.
3. Deprecated behaviors must be reported in the documentation for at least the entire deprecation period.
4. Deprecated configurations or CLI elements must emit warnings when used and be signaled in the documentation for at least the entire deprecation period.
5. Deprecated APIs should have a way to signal the deprecation status, which may vary depending on the specific subsystem.
6. Any Pull Request introducing a deprecation notice must be labeled and include a note in the format `DEPRECATION NOTICE: <description>`.
7. Any Pull Request introducing a breaking change due to the end of the deprecation notice period must be labeled and include a note in the format `BREAKING CHANGE:`. 
   - It is also recommended for code commits that introduce a breaking change to follow the related [conventional commit spec](https://www.conventionalcommits.org/en/v1.0.0/#specification).

The minimum deprecation period length depends on the specific subsystem. If changes span multiple areas, the area with the most extended deprecation period is assumed.

**Deprecation Periods (up to Falco 0.x)**

| Area           | Stable | Incubating |
| -------------- | ------ | ---------- |
| Behaviors      | 1      | 1          |
| Output/Alerts  | 1      | 1          |
| CLI/Config     | 1      | 0          |
| Rules          | 1      | 0          |
| Subsystem APIs | 0      | 0          |

**Deprecation Periods (since Falco 1.0 onward)**

| Area           | Stable | Incubating |
| -------------- | ------ | ---------- |
| Behaviors      | 2      | 1          |
| Output/Alerts  | 2      | 1          |
| CLI/Config     | 2      | 1          |
| Rules          | 2      | 1          |
| Subsystem APIs | 1      | 1          |

### Exceptions

- Subsystems or subcomponents may have additional criteria and exceptions (for instance, [the rules maturity framework](https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md#rules-maturity-framework)). Stated other criteria and exceptions must not directly affect the main Falco distribution (e.g., *falcoctl* can have a different release cycle and different policies; however, if Falco relies on a specific *falcoctl* feature, that *falcoctl* feature adoption and deprecation must be strictly compatible with the rules described in this proposal).
- Internal APIs are out of scope for this policy. Their adoption models and deprecation policies might be regulated separately.
- Different parties may provide plugins, and each plugin may have a different maturity level. Only those plugins officially maintained by The Falco Project and identified as "core" for Falco are in scope for this policy; all others are excluded.
- Any other exceptions to the rules provided by this policy require a formal core maintainer majority vote.

### Versioning

Regarding the above policies, component versioning must adhere to [Semantic Versioning 2.0.0](https://semver.org/). However, in the context of Falco core components, the scope extends beyond the strict API definition and includes any user-facing changes.

Thus, given a version number `MAJOR.MINOR.PATCH` increment the:

- *MAJOR* version when the deprecation period ends, thus introducing incompatible user-facing or API changes.
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

- With Falco 0.38, the policy must be partially implemented, at least in Falco and relevant documentation. Exceptions may be made temporarily.
- Within Falco 0.39, the feature gates system must be implemented in the Falco executable, and the policy must be part of the official documentation (i.e., published both on GitHub and [falco.org](https://falco.org)).
- Within Falco 1.0.0 (still not scheduled to date), the policy must be strictly implemented in Falco and all [core projects](https://github.com/falcosecurity/evolution#core) with [stable](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) status.

During the transition phases, maintainers can fine-tune these policies and add further exceptions, eventually. After this initial transition phases, the policy is assumed to be established. From then on, any policy modifications, updates, and exceptions must be subject to a core maintainer majority vote to ensure the policy remains relevant and practical.
