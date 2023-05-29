# Falco Roadmap Management Proposal

## Summary 

This document proposes the introduction of a structured process for managing Falco's roadmap and implementing related changes in our development process. The goal is to ensure the efficient execution of our roadmap objectives.

### Goals

The pillars of this proposal are:

- Define processes for release cycles and development iterations
- Provide guidelines for planning and prioritizing efforts
- Introduce regular meetings for core maintainers
- Using *GitHub Project* as the primary tool for managing *The Falco Project* roadmap


### Non-Goals

- Providing an exact set of criteria for task prioritization
- Detailing testing procedures
- Providing detailed instructions for GitHub Project usage
- Addressing hotfix releases

### Scope of this Proposal

Primarily, the roadmap targets the planning of Falco development and releases. However, given Falco's dependence on numerous components, it's inevitable that scheduling and planning activities span across multiple repositories. We anticipate that all [core repositories](https://github.com/falcosecurity/evolution#official) will be interconnected with the roadmap, making it comprehensive enough to incorporate items from all related [Falcosecurity repositories](https://github.com/falcosecurity) as necessary.

This proposal does **not apply to hotfix releases** that may happen whenever needed at the maintainers' discretion.

## Release Cycles and Development Iterations

Falco releases happen 3 times per year. Each release cycle completes, respectively, by the end of January, May, and September.

A **release cycle is a 16-week time frame** between two subsequent releases.

Using this schema, in a 52-week calendar year, we allocate 48 weeks for scheduled activities (16 weeks *x* 3 releases), leaving 4 weeks for breaks.

The 16-week release cycle is further divided into three distinct iterations:

| Iteration Name | Duration | Description |
|---------------|----------|-------------|
| Development | 8 weeks | Development phase |
| Stabilization | 4 weeks | Feature completion and bug fixing |
| Release Preparation | 4 weeks | Release preparation, testing, bug fixing, no new feature |

### Targeted Release Date

The final week of the *Release Preparation* should conclude before the *last Monday of the release month* (ie. January/May/September). This *last Monday* is designated as the **targeted release date** (when the release is being published), and the remaining part of the week is considered a break period.

### Milestones

For each release, we create a [GitHub Milestone](https://github.com/falcosecurity/falco/milestones) (whose due date must be equal to the target release date). We use the milestone to collect all items to be tentatively completed within the release. 

### Alignment of Falco Components

The release schedule of the [components Falco depends on](https://github.com/falcosecurity/falco/blob/master/RELEASE.md#falco-components-versioning) needs to be synchronized to conform to these stipulations. For instance, a [falcosecurity/libs](https://github.com/falcosecurity/libs) release may be required at least one week prior to the termination of each iteration.

The maintainers are responsible for adapting those components' release schedules and procedures to release cycles and development iterations of Falco. Furthermore, all release processes must be documented and provide clear expectations regarding release dates.

## Project Roadmap

We use the [GitHub Project called *Falco Roadmap*](https://github.com/orgs/falcosecurity/projects/5) to plan and track the progress of each release cycle. The GitHub Project needs to be configured with the above mentioned iterations and break periods, compiled with actual dates. It's recommended to preconfigure the GitHub Project to accommodate the current plus the following three release cycles.

### Roadmap Planning

The roadmap serves as a strategic planning tool that outlines the goals and objectives for Falco. Its purpose is to visually represent the overall direction and timeline, enhance transparency and engage the community.

The onus is on the [Core Maintainers](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md#core-maintainers) to manage the roadmap. In this regard, Core Maintainers meet in **planning sessions on the first week of each calendar month**. 

During these planning sessions, tasks are allocated to the current iteration or postponed to one of the following iterations. The assigned iteration indicates the projected completion date for a particular workstream.

When a session matches with the commencement of an iteration, maintainers convene to assess the planning and prioritize tasks for the iteration. The first planning session of a release cycle must define top priorities for the related release.

## Testing and Quality Assurance (QA)

Each iteration's output must include at least one Falco pre-release (or a viable development build) designated for testing and QA activities. While it's acceptable for these builds to contain unfinished features or known bugs, they must enable any community member to contribute to the testing and QA efforts.

The targeted schedule for these Testing/QA activities should be the **last week of each iteration** (or earlier during the *Release Preparation*).

Testing and Quality Assurance criteria and procedures must be defined and documented across relevant repositories.

Furthermore, given the strong reliance of Falco on [falcosecurity/libs](https://github.com/falcosecurity/libs), the above-mentioned pre-release/build for Testing/QA purposes must be based on the most recent *libs* development for the intended iteration. This means that during each interaction, a *libs* release (either pre or stable) must happen early enough to be used for this purpose.

## Next Steps and Conclusions

The Falco 0.36 release cycle, running from June to September 2023, will mark the initiation of the new process. This cycle will also serve as an experimental phase for refining the process.

Furthermore, as soon as possible, we will kick off a Working Group specifically to ensure smooth execution. This group will involve community members in assisting maintainers with roadmap management. It will provide curated feature suggestions for the roadmap, informed by community needs. This approach would facilitate the core maintainers' decisions, as they would mostly need just to review and adopt these pre-vetted recommendations, enhancing efficiency.

The Working Group's responsibilities will include (non-exhaustive list):

- Address input from the [2023-04-27 Core Maintainers meeting](https://github.com/falcosecurity/community/blob/main/meeting-notes/2023-04-27-Falco-Roadmap-Discussion.md)
- Sorting and reviewing pending issues to identify key topics for discussion and potential inclusion in the roadmap
- Establishing protocols not explicitly covered in this document
- Updating the documentation accordingly
- Supporting Core Maintainers in managing the [Falco Roadmap GitHub project](https://github.com/orgs/falcosecurity/projects/5)
- Gathering suggestions from all involved stakeholders to put forward potential enhancements

Finally, we anticipate the need for minor adjustments, which will become apparent only after an initial period of experimentation. Thus we have to intend this process to be flexible enough to adapt to emerging needs and improvements as long as the fundamental spirit of this proposal is upheld.

