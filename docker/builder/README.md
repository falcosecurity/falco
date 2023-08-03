# Builder folder

* We use `modern-falco-builder.Dockerfile` to build Falco with the modern probe and return it as a Dockerfile output. This Dockerfile doesn't generate a Docker image but returns as output (through the `--output` command):
  * Falco `tar.gz`.
  * Falco `deb` package.
  * Falco `rpm` package.
