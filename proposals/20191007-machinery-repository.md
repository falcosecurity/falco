# Falco machinery repository

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
  * [Goals](#goals)
  * [Non-Goals](#non-goals)
  * [Use cases](#use-cases)
  * [Project structure](#project-structure)

<!-- tocstop -->

## Summary

We want to have a new repository under the `falcosecurity` organization named `falcosecurity/falco-machinery`.
This repository will contain all the tools **written in Go** that are not big enough to have their own repo but that are also not
eligible to go to the main Falco repository.

## Motivation

Right now, we have two pull requests trying to introduce small Go command line tools to the Falco repository directly

- [PSP rules support: to add a tool to convert K8s PSPs to Falco rules](https://github.com/falcosecurity/falco/pull/826)
- [Build slim images: to add a tool to download kernel modules from https](https://github.com/falcosecurity/falco/pull/776)

By just looking at the main Falco project structure, one can immediatelly understand that the way its structured
doesn't fit having multiple tools written in Go within it. Moreover, having Go code in the Falco repo means introducing Go modules to the Falco
project itself, which in turn means adding a duality between Go and CMake that we don't want to deal with that.

In the end, we don't want to be forced to build non-mandatory Go tools when building Falco. 
We also don't want CMake to deal with Go stuff as Go has its own ecosystem and tooling
that would be best exploited by having a separate repo.


### Goals

- Having a place where to put Go command-line tools and common libraries
- Keep the Falco repository clean and maintaineble with only standard CPP tools
- Create more contribution opportunities
  - Code and issues are easier to discover for contributors in another repo
  - Go programmers can recognize the structure of a typical Go project and contribute straight away

### Non-Goals

- Make this for every language, Go is the language we choose for tooling right now


### Use cases

Here are some tools we could have in there.

- PSP Converter
- Falco probes HTTPS downloader
- Tool to generate the changelog from release notes

### Project structure

Here's the project structure with examples where the `cmd` folder contains all the binary entrypoints
and the `pkg` folder the respective libraries with their tests.


```
.
├── cmd
│   ├── probe-downloader
│   │   └── main.go
│   └── psp-converter
│       └── main.go
├── go.mod
├── go.sum
└── pkg
    ├── probe-downloader
    │   ├── downloader.go
    │   └── downloader_test.go
    └── psp-converter
        ├── converter.go
        └── converter_test.go
```
