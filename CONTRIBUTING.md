# Contributing to Falco

* [Code of Conduct](#code-of-conduct)
* [Issues](#issues)
* [Pull Requests](#pull-requests)
* [Developer Certificate Of Origin](#developer-certificate-of-origin)

## Code of Conduct

Falco has a
[Code of Conduct](https://github.com/falcosecurity/falco/blob/dev/CODE_OF_CONDUCT)
to which all contributors must adhere, please read it before interacting with the repository or the community in any way.


## [Issues](./doc/guides/contributing/issues.md)

Issues are the hearthbeat of the Falco project, there are three kinds of issues you can open:

- Bug report: you believe you found a problem in Falco and you want to discuss and get it fixed, 
creating an issue with the bug report template is the best way to do so.
- Enhancement: any kind of new features need to be discussed in this kind of issue, you want a new rule or a new feature? This is the kind of issue you want to open. Be very good at explaining your intent, it's always important that others can understand what you mean in order to discuss, be open and collaborative in letting others help you getting this done!
- Failing tests: you noticed a flaky test or a problem with a build? This is the kind of issue to triage that!

The best way to get **involved** in the project is through issues, you can help in many ways:

- Issues triaging: participating in the discussion and adding details to open issues is always a good thing,
sometimes issues need to be verified, you could be the one writing a test case to fix a bug!
- Helping to resolve the issue: You can help in getting it fixed in many ways, more often by opening a pull request.

Any other discussion, and **support requests** should go through the `#falco` channel in the Sysdig slack, join [here](https://slack.sysdig.com/).

## [Pull Requests](./doc/guides/contributing/pull-requests.md)

Thanks for taking time 
Make a [pull request](https://help.github.com/articles/about-pull-requests/) (hereafter PR).

In the PR body, feel free to add an area label if appropriate by saying `/area <AREA>`, PRs will also
need a kind, make sure to specify the appropriate one.

The list of labels is [here](https://github.com/falcosecurity/falco/labels). 

Also feel free to suggest a reviewer with `/assign @theirname`.

Once your reviewer is happy, they will say `/lgtm` which will apply the 
`lgtm` label, and will apply the `approved` label if they are an 
[owner](/OWNERS).

The `approved` label will also automatically be applied to PRs opened by an 
OWNER. If neither you nor your reviewer is an owner, please `/assign` someone
 who is.

Your PR will be automatically merged once it has the `lgtm` and `approved` 
labels, does not have any `do-not-merge/*` labels, and all tests are passing.


## Developer Certificate Of Origin

The [Developer Certificate of Origin (DCO)](https://developercertificate.org/) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. 

Contributors to the Falco project sign-off that they adhere to these requirements by adding a Signed-off-by line to commit messages.

This is my commit message

Signed-off-by: John Poiana <jpoiana@falco.org>

Git even has a -s command line option to append this automatically to your commit message:

$ git commit -s -m 'This is my commit message'
