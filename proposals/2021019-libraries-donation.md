# OSS Libraries Donation Plan

## Summary

Sysdig Inc. intends to donate **libsinsp**, **libscap**, the **kernel module driver** and the **eBPF driver sources** by moving them to the Falco project.

This means that some parts of the [draios/sysdig](https://github.com/draios/sysdig) repository will be moved to a new GitHub repository called [falcosecurity/libs](https://github.com/falcosecurity/libs).

This plan aims to describe and clarify the terms and goals to get the donation done.

## Motivation

There are two main OSS projects using the libraries and drivers that we are aware of:

- [sysdig](https://github.com/draios/sysdig)  the command line tool
- [Falco](https:/github.com/falcosecurity/falco), the CNCF project.

Since the Falco project is a heavy user of the libraries, a lot more than the sysdig cli tool, Sysdig (the company) decided to donate the libraries and the driver to the Falco community.

Sysdig (the command line tool) will continue to use the libraries now provided by the Falco community underneath.

This change is win-win for both parties because of the following reasons:

- The Falco community owns the source code of the three most important parts of the software it distributes.
  - Right now it is "only" an engine on top of the libraries. This **donation** helps in making the scope of the Falco project broader. Having the majority of the source code under an **open governance** in the same organization gives the Falco project more contribution opportunities, helps it in **evolving independently** and makes the whole Falco community a strong owner of the processes and decision making regarding those crucial parts.

- Given the previous point, Sysdig (the command line tool) will benefit from the now **extended contributors base**

- Sysdig (the company) can now focus on the user experience and user space features

- **Contributions** to the libraries and drivers will be **easier** to spread across the Falco community

- By being donated, with their own **release process**, **release artifacts**, and **documentation**, the libraries can now live on their own and possibly be used directly in other projects by becoming fundamental pieces for their success.

## Goals

There are many sub-projects and each of them interacts in a different way in this donation.

Let's see the goals per sub-project.

### libsinsp

1. Extract libsinsp from `draios/sysdig/userspace/libsinsp` (keeping the commit history) into [falcosecurity/libs](https://github.com/falcosecurity/libs)

2. The migration comes first, then we can do additional PRs for the points below so that we do only one thing at a time and keep the history linear

3. Keep the same code, refactorings will need to be done in subsequent PRs and approved separately

4. Adapt the CMake and build files

5. Install [poiana](https://github.com/poiana) and its workflows on it

6. Define the `OWNERS`

   - Owners are chosen from the current major contributors (considering the past two years) to this project, given their availability, commitment is key

7. When possible, migrate issues and PRs to the new repository

8. Distribute the `libsinsp.so` library and headers as an artifact (rpm, deb, tar.gz) following the falcosecurity current process

9. Distribute the `libsinsp.a` library and headers as an artifact (rpm, deb, tar.gz) following the falcosecurity current process

10. Creation of the CI scripts using the Falco CI and Falco Infra

11. The CI scripts will need to publish the artifacts in the current falcosecurity artifacts repository

12. Artifacts will be pushed for every tag (release) and for every master merge (development release)

13. Falco follows a [multi-stage model for adopting new projects](https://github.com/falcosecurity/evolution#falco-project-evolution), in this case we will do an exception since the library is foundational for Falco and it has a very good track record already

14. This project will go already "Official support" once the donation is completed

15. Contributing, Code of Conduct, Governance, Security, and Support will be the same as the rest of the organization, find them [here](https://github.com/falcosecurity/.github)

16. Every other additional change will need to have its own process with a proposal

17. Implement the release process as described above

18. Propose a change to Falco repository to use the artifacts produced by the libsinsp release process for the build

19. Document the API

### libscap

1. Extract libscap from `draios/sysdig/userspace/libscap` (keeping the commit history) into [falcosecurity/libs](https://github.com/falcosecurity/libs)

2. The migration comes first, then we can do additional PRs for the points below so that we do only one thing at a time and keep the history linear

3. Keep the same code, refactorings will need to be done in subsequent PRs and approved separately

4. Adapt the CMake and build files

5. Install [poiana](https://github.com/poiana) and its workflows on it

6. Define the `OWNERS`

   - Owners are chosen from the current major contributors (considering the past two years) to this project, given their availability, commitment is key

7. When possible, migrate issues and PRs to the new repository

8. Distribute the `libscap.so` library and headers as an artifact (rpm, deb, tar.gz) following the falcosecurity current process

9. Distribute the `libscap.a` library and headers as an artifact (rpm, deb, tar.gz) following the falcosecurity current process

10. Creation of the CI scripts using the Falco CI and Falco Infra

11. The CI scripts will need to publish the artifacts in the current falcosecurity artifacts repository

12. Artifacts will be pushed for every tag (release) and for every master merge (development release)

13. Falco follows a [multi-stage model for adopting new projects](https://github.com/falcosecurity/evolution#falco-project-evolution), in this case we will do an exception since the library is foundational for Falco and it has a very good track record already

14. This project will go already "Official support" once the donation is completed

15. Contributing, Code of Conduct, Governance, Security, and Support will be the same as the rest of the organization, find them [here](https://github.com/falcosecurity/.github)

16. Every other additional change will need to have its own process with a proposal

17. Implement the release process as described above

18. Propose a change to Falco repository to use the artifacts produced by the libscap  release process for the build

19. Document the API

### Drivers: Kernel module and eBPF probe

1. Extract them from `draios/sysdig/driver` (keeping the commit history) into [falcosecurity/libs](https://github.com/falcosecurity/libs)

2. The migration comes first, then we can do additional PRs for the point below so that we do only one thing at a time and keep the history linear

3. Keep the same code, refactorings will need to be done in subsequent PRs and approved separately

4. Adapt the Makefiles and build files

5. Install [poiana](https://github.com/poiana) and its workflows on it

6. Define the `OWNERS`

   - Owners are chosen from the current major contributors (considering the past two years) to this project, given their availability, commitment is key

7. When possible, migrate issues and PRs to the new repository

8. Falco follows a [multi-stage model for adopting new projects](https://github.com/falcosecurity/evolution#falco-project-evolution), in this case we will do an exception since the library is foundational for Falco and it has a very good track record already. We are just changing maintenance ownership

9. Contributing, Code of Conduct, Governance, Security, and Support will be the same as the rest of the organization, find them [here](https://github.com/falcosecurity/.github)

10. Every other additional change will need to have its own process with a proposal

11. The Falco community already ships driver artifacts using [driverkit](https://github.com/falcosecurity/driverkit) and the [test-infra repository](https://github.com/falcosecurity/test-infra)

    - Adapt the place from which [driverkit](https://github.com/falcosecurity/driverkit) grabs the drivers source

12. This project will go already "Official support" once the migration is completed.

### Falco

1. Adapt the CMake files to point to the new homes for libscap, libsinsp and the drivers

2. When distributing the deb and rpm, libscap and libsinsp will need to be install dependencies and not anymore compiled into Falco

### Driverkit

1. Change the source location for the drivers to point to the new driver repository

### pdig

1. The project will need to be adapted to use libscap and libsinsp and the fillers from their new location
