# Falco development image

This docker image can be easily generated starting from a clean Falco build.

## 1. Clone the Falco repo ⬇️

```bash
git clone https://github.com/falcosecurity/falco.git
```

## 2. Prepare the build directory 🏗️

### `falco-runner-image` tag

The CMake command that we will see in the next section builds Falco locally on your machine, and push it into a docker image, so as you may imagine the final image that will run Falco must have a similar `GLIBC` version to your local one. For this reason, you have to use docker tags.

The `nodriver.Dockerfile` will use the `falco-runner-image` tag to build the final image as you can see here:

```dockerfile
FROM falco-runner-image AS runner

...
```

For example, if I build Falco locally on a un `ubuntu:22-04` machine I will instruct docker to use `ubuntu:22-04` as a final running image.

```bash
docker tag ubuntu:22.04 falco-runner-image
```

In this way the `nodriver.Dockerfile` will use `ubuntu:22-04` during the building phase.

### Cmake command

Now that we set the `falco-runner-image` tag, we are ready to build our Falco image. Starting from the project root:

```bash
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DCPACK_GENERATOR=TGZ -DFALCO_ETC_DIR=/etc/falco ..
make dev-docker
```
> __Please note__: These cmake options `-DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DCPACK_GENERATOR=TGZ -DFALCO_ETC_DIR=/etc/falco` are the required ones but you can provide additional options to build the image according to your needs (for example you can pass `-DMINIMAL_BUILD=On` if you want a minimal build image or `-DBUILD_FALCO_MODERN_BPF=ON` if you want to include the modern bpf probe inside the image)

## 3. Run the docker image locally 🏎️

```bash
docker run --rm -i -t \
           --privileged \
           -v /var/run/docker.sock:/host/var/run/docker.sock \
           -v /dev:/host/dev \
           -v /proc:/host/proc:ro \
           falco-nodriver-dev
```

If you change something in the Falco source code you can simply rebuild the image with:

```bash
make dev-docker
```
