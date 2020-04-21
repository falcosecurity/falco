# Falco Release Process
Our release process is mostly automated, but we still need some manual steps to initiate and complete it.

Changes and new features are grouped in [milestones](https://github.com/falcosecurity/falco/milestones), the milestone with the next version represents what is going to be released. 

Releases happen on a monthly cadence, and we need to assign owners for each (usually we pair a new person with an experienced one). Assignees and the due date are proposed during the [weekly community call](https://github.com/falcosecurity/community). Note that hotfix releases can happen as soon as it is needed.

Finally, on the proposed due date the assignees for the upcoming release proceed with the processes described below.

## Pre-Release Checklist

### 1. Release notes
- Let `YYYY-MM-DD` the day before of the [latest release](https://github.com/falcosecurity/falco/releases)
- Every merged PR matching the `is:pr is:merged closed:>YYY-MM-DD` [filters](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+closed%3A%3EYYYY-MM-DD) to be manually checked for release notes 
    - Release note must follow the [commit convention](https://github.com/falcosecurity/falco/blob/master/CONTRIBUTING.md#commit-convention)
    - If the merged PR has no target milestone, assign it to the current milestone it
- Check issue with no milestone `is:pr is:merged no:milestone closed:>YYYT-MM-DD` and add it
- Double-check that there are no more merged PRs without the target milestone assigned with the `is:pr is:merged no:milestone closed:>YYYT-MM-DD` [filters](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+no%3Amilestone+closed%3A%3EYYYT-MM-DD), if any, fix them

### 2. Milestones
- Move the [tasks not completed](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Aopen) to the new milestone
- Close the completed milestone
    
### 3. Release PR
- Double-check if any hard-coded version number is present in the code, it should be not present anywhere:
    - If any, manually correct it then open an issue to automate version number bumping later
    - Versions table in the `README.md` update itself automatically
    - [leo] This step is no longer necessary when we remove `integrations/` directory
- Generate the change log https://github.com/leodido/rn2md
    - [leo/lore] gotta move this (and merge it with Lorenzo's one) into test-infra
- Add the lastest changes on top the previous `CHANGELOG.md`
- Submit a PR with the above modifications
- Await PR approval

## Release
Let `x.y.z` the new version.

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

<!-- Copy the relevant part of the changelog here -->

### Statistics

| Merged PRs        | Number  |
|-------------------|---------|
| Not user-facing   | x       |
| Release note      | x       |
| Total             | x       |

<!-- Calculate stats and fill the above table -->
```
- Finally, publish the release!

## Post-Release tasks

### 1. Update the web site
- TODO [Netlify](https://app.netlify.com/sites/falcosecurity/deploys)

### 2. Announce the new release to the world!
- Send an announcement to cncf-falco-dev@lists.cncf.io
- Let folks in the slack #falco channel know about a new release came out