# Falco Release Process

Our release process is mostly automated, but we still need some manual steps to initiate and complete it.

Changes and new features are grouped in [milestones](https://github.com/falcosecurity/falco/milestones), the milestone with the next version represents what is going to be released.

A release happens every two months ([as per community discussion](https://github.com/falcosecurity/community/blob/master/meeting-notes/2020-09-30.md#agenda)), and we need to assign owners for each (usually we pair a new person with an experienced one). Assignees and the due date are proposed during the [weekly community call](https://github.com/falcosecurity/community). Note that hotfix releases can happen as soon as it is needed.

Finally, on the proposed due date the assignees for the upcoming release proceed with the processes described below.

## Pre-Release Checklist

Before cutting a release we need to do some homework in the Falco repository. This should take 5 minutes using the GitHub UI.

### 1. Release notes
- Find the LAST release (-1) and use `YYYY-MM-DD` as the day before of the [latest release](https://github.com/falcosecurity/falco/releases)
- Check the release note block of every PR matching the `is:pr is:merged closed:>YYYY-MM-DD` [filter](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+closed%3A%3EYYYY-MM-DD)
    - Ensure the release note block follows the [commit convention](https://github.com/falcosecurity/falco/blob/master/CONTRIBUTING.md#commit-convention), otherwise fix its content
    - If the PR has no milestone, assign it to the milestone currently undergoing release
- Check issues without a milestone (using [is:pr is:merged no:milestone closed:>YYYY-MM-DD](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+no%3Amilestone+closed%3A%3EYYYY-MM-DD) filter) and add them to the milestone currently undergoing release
- Double-check that there are no more merged PRs without the target milestone assigned with the `is:pr is:merged no:milestone closed:>YYYY-MM-DD` [filters](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+no%3Amilestone+closed%3A%3EYYYY-MM-DD), if any, fix them

### 2. Milestones

- Move the [tasks not completed](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Aopen) to a new minor milestone

### 3. Release PR

- Double-check if any hard-coded version number is present in the code, it should be not present anywhere:
    - If any, manually correct it then open an issue to automate version number bumping later
    - Versions table in the `README.md` update itself automatically
- Generate the change log https://github.com/leodido/rn2md, or https://fs.fntlnz.wtf/falco/milestones-changelog.txt for the lazy people (it updates every 5 minutes)
    - If you review timeout errors with `rn2md` try to generate an GitHub Oauth access token and use `-t`
- Add the latest changes on top the previous `CHANGELOG.md`
- Submit a PR with the above modifications
- Await PR approval
- Close the completed milestone as soon as the PR is merged

## Release

Now assume `x.y.z` is the new version.

### 1. Create a tag

- Once the release PR has got merged, and the CI has done its job on the master, git tag the new release

    ```
    git pull
    git checkout master
    git tag x.y.z
    git push origin x.y.z
    ```

> **N.B.**: do NOT use an annotated tag

- Wait for the CI to complete

### 2. Update the GitHub release

- [Draft a new release](https://github.com/falcosecurity/falco/releases/new)
- Use `x.y.z` both as tag version and release title
- Use the following template to fill the release description:
    ```
    <!-- Substitute x.y.z with the current release version -->

    | Packages | Download                                                                                                                                               |
    | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
    | rpm      | [![rpm](https://img.shields.io/badge/Falco-x.y.z-%2300aec7?style=flat-square)](https://dl.bintray.com/falcosecurity/rpm/falco-x.y.z-x86_64.rpm)        |
    | deb      | [![deb](https://img.shields.io/badge/Falco-x.y.z-%2300aec7?style=flat-square)](https://dl.bintray.com/falcosecurity/deb/stable/falco-x.y.z-x86_64.deb) |
    | tgz      | [![tgz](https://img.shields.io/badge/Falco-x.y.z-%2300aec7?style=flat-square)](https://dl.bintray.com/falcosecurity/bin/x86_64/falco-x.y.z-x86_64.deb) |

    | Images                                                          |
    | --------------------------------------------------------------- |
    | `docker pull docker.io/falcosecurity/falco:_tag_`               |
    | `docker pull docker.io/falcosecurity/falco-driver-loader:_tag_` |
    | `docker pull docker.io/falcosecurity/falco-no-driver:_tag_`     |

    <!-- Copy the relevant part of the changelog here -->

    ### Statistics

    | Merged PRs      | Number |
    | --------------- | ------ |
    | Not user-facing | x      |
    | Release note    | x      |
    | Total           | x      |

    <!-- Calculate stats and fill the above table -->
    ```

- Finally, publish the release!

### 3. Update the meeting notes

For each release we archive the meeting notes in git for historical purposes.

 - The notes from the Falco meetings can be [found here](https://hackmd.io/6sEAlInlSaGnLz2FnFz21A).
    - Note: There may be other notes from working groups that can optionally be added as well as needed.
 - Add the entire content of the document to a new file in [github.com/falcosecurity/community/tree/master/meeting-notes](https://github.com/falcosecurity/community/tree/master/meeting-notes) as a new file labeled `release-x.y.z.md`
 - Open up a pull request with the new change.


## Post-Release tasks

Announce the new release to the world!

- Send an announcement to cncf-falco-dev@lists.cncf.io (plain text, please)
- Let folks in the slack #falco channel know about a new release came out
