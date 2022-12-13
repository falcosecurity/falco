# Builder folder

* We use `Dockerfile` to build the `centos7` Falco builder image.
* We use `modern-falco-builder.Dockerfile` to build Falco with the modern probe and return it as a Dockerfile output. This Dockerfile doesn't generate a Docker image but returns as output (through the `--output` command):
  * Falco `tar.gz`.
  * Falco `deb` package.
  * Falco `rpm` package.
  * Falco build directory, used by other CI jobs.
