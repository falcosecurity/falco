# Change Log

This file documents all notable changes to Falco. The release numbering uses [semantic versioning](http://semver.org).

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
