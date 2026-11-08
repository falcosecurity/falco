# Rule condition string escaping (RFC, working draft)

Status: **Request for comments.** This document proposes a direction for fixing
string quoting and escaping in rule conditions
([#1859](https://github.com/falcosecurity/falco/issues/1859)). Nothing here is
decided; the open questions at the end need maintainer input before any
implementation starts.

## Summary

String values in rule conditions do not follow one documented escaping model.
Users guessing quotes or backslashes get silently wrong matching instead of an
error (examples in [#1859](https://github.com/falcosecurity/falco/issues/1859)).
As noted by maintainers in that issue, fixing this properly breaks existing
rulesets, so it needs a versioned opt-in plus migration guidelines and tooling.
This proposal sketches that path: canonical escaping rules, a per-rules-file
opt-in, a migration aid, and staged delivery across `falco` and `libs`.

## Goals

* One documented escaping model for condition values, list items, and macro
  bodies, with observable behavior identical everywhere a value is compared.
* Old rules keep working unchanged by default; new semantics apply only to
  rules files that explicitly opt in.
* A migration path: a checker/converter plus guidelines, so ruleset authors can
  move to the new model mechanically.
* Ambiguous quoting fails loudly at load time (error or warning with position)
  instead of silently matching the wrong events.

## Non-Goals

* No change to the filter operator set or to field extraction semantics; this is
  about value tokenizing and unescaping only.
* No change to YAML parsing itself (`yaml_helper` escape handling stays as is).
* Backward-compatible syntax additions stay on the
  [#3255](https://github.com/falcosecurity/falco/issues/3255) track; this
  proposal covers only the incompatible escaping cleanup, as anticipated there
  ("other issues will be opened for backward-incompatible changes").
* This document proposes no implementation; code PRs follow only after the
  design discussion converges.

## Motivation

[#1859](https://github.com/falcosecurity/falco/issues/1859) (open since 2022,
assigned to @leogr and @jasondellaluce): a list item `"runc:[1:CHILD]"` does
not match `proc.name` `runc:[1:CHILD]`, while the hand-escaped form
`runc\:\[1\:CHILD\]` does. Maintainer assessment in that thread: string
escaping is a known Rule Engine issue whose fix would break many existing
rulesets and therefore needs migration guidelines and tooling. The issue is
still open with no agreed design, which this RFC aims to provide.

## Current behavior

Condition handling in this repo (all paths below verified on `master`):

1. `rule_loader::compiler::parse_condition`
   (`userspace/engine/rule_loader_compiler.cpp`) first expands `list` references
   **textually** (`resolve_list`), then hands the resulting string to
   `libsinsp::filter::parser` from `falcosecurity/libs`, and finally compiles
   the AST with `sinsp_filter_compiler`.
2. Quoting and backslash handling therefore live mostly in the libs filter
   parser, while list expansion and YAML decoding live in Falco. The two layers
   have no shared escaping contract, which is why a value can mean different
   things in a list item, a macro, and a bare comparison.
3. Rules files already carry a version gate hook: `required_engine_version`
   (`userspace/engine/rule_loader_reader.cpp`), currently used for engine
   compatibility checks.

## Proposed design

### Canonical escaping model

Define, in one place (libs filter parser), the exact grammar for condition
values:

* Bare values: which characters are literal, which must be escaped, and how a
  backslash escapes the next character.
* Single- and double-quoted values: identical treatment of backslash escapes
  inside both, with the quote character itself escapable.
* List items and macro expansions go through the same unescaping exactly once
  (no double-unescape when a list item is substituted into a condition).

### Versioned opt-in

New semantics apply only to rules files that declare support for them, so
existing rulesets keep byte-identical behavior. Candidate vehicles (decision
needed, see open questions):

* (a) Extend the existing `required_engine_version` gate with the Falco release
  that introduces the new model.
* (b) A new per-file key (for example `rules_dialect` or `escaping`) with
  explicit `legacy` / `canonical` values.

Under either vehicle, files without the declaration keep legacy semantics, and
mixed-version file sets behave per file.

### Loader diagnostics

Falco's rule loader gains detection for values whose meaning differs between
legacy and canonical semantics (unescaped quotes, backslashes before
non-special characters, list items that change meaning after substitution).
Depending on the opt-in state, these produce load warnings pointing at the
migration guide, or load errors for the new dialect, reusing the existing
`rule_loader::context` position reporting.

### Migration aid

A converter that rewrites legacy rules files to the canonical dialect:

* Runs as an offline command (exact surface TBD: `falco --migrate-rules`,
  a `falcoctl` subcommand, or a standalone script).
* Prints a diff-style report of every value it had to reinterpret, and refuses
  to guess on ambiguous inputs, listing them for manual review instead.
* Shipped alongside migration guidelines in the Falco documentation.

### Staged delivery

1. Agree the canonical model and the opt-in vehicle in this RFC.
2. libs: implement canonical unescaping behind a parser option, with unit tests.
3. falco: thread the per-file opt-in from the loader to the parser, add
   diagnostics, ship the migration aid and docs.
4. Migrate the default ruleset and examples, then announce a deprecation window
   for the legacy dialect in a later release.

## Compatibility and rollout

* Default behavior never changes for files without the opt-in declaration.
* The default ruleset migrates only after the converter exists and is tested
  against it.
* No plugin, driver, or event-source API changes are required; the work is
  confined to condition parsing, the rule loader, and tooling.

## Open questions

1. Opt-in vehicle: extend `required_engine_version`, or a new per-file key?
2. Exact canonical grammar: which characters stay bare, and do single and
   double quotes behave identically?
3. Should ambiguous legacy values warn or error when the new dialect is
   selected?
4. Where should the migration aid live (`falco`, `falcoctl`, standalone)?
5. Does any of this interact with planned work in
   [#3255](https://github.com/falcosecurity/falco/issues/3255),
   [#2403](https://github.com/falcosecurity/falco/issues/2403), or
   [libs#1789](https://github.com/falcosecurity/libs/issues/1789)?

## Success metrics

* [#1859](https://github.com/falcosecurity/falco/issues/1859) reproducible cases
  behave per the documented model under the new dialect.
* Zero behavior change for existing rulesets without the opt-in declaration,
  verified by loading the default ruleset and the loader unit tests.
* The migration aid converts the default ruleset with an empty manual-review
  list.
