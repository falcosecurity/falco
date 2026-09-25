# Limit CMake parallel builds. Runner don't have such memory
%undefine _smp_mflags
%global _parallel_builds --parallel 6

Summary: Falco is a runtime security tool for Linux operating systems
Name: falco
Version: 0.44.1
%define _rules_ver 5.1.0
%define _libs_ver 0.25.4
%define _driver_ver 10.2.0
%define _ctl_ver 0.13.0
%define _p_container_ver 0.7.1
Release: 5%{?dist}
License: Apache2.0
ExclusiveArch: x86_64 aarch64
BuildRequires: golang >= 1.25.7 git systemd-rpm-macros bpftool cmake gcc-c++
BuildRequires: cmake-filesystem%{?_isa} clang cppcheck cppcheck-htmlreport
BuildRequires: zlib-devel openssl-devel libcurl-devel libbpf-devel
BuildRequires: gperftools-devel uthash-devel >= 1.9.8 jemalloc-devel
BuildRequires: cmake(cxxopts) >= 3.3.1 cmake(jsoncpp) >= 1.9.5
BuildRequires: cmake(GTest) >= 1.16.0 cmake(tbb) >= 2022.1.0
BuildRequires: cmake(httplib) >= 0.23.1 cmake(nlohmann_json) >= 3.11.3
BuildRequires: cmake(valijson) >= 1.0.2 cmake(yaml-cpp) >= 0.9.0 cmake(re2)
Url: https://%{name}.org/
%define _uri github.com/%{name}security
Source0: https://codeload.%{_uri}/%{name}/tar.gz/refs/tags/%{version}#/%{name}-%{version}.tar.gz
Source1: https://codeload.%{_uri}/rules/tar.gz/refs/tags/%{name}-rules-%{_rules_ver}#/%{name}-rules-%{_rules_ver}.tar.gz
Source2: https://codeload.%{_uri}/libs/tar.gz/refs/tags/%{_libs_ver}#/%{name}-libs-%{_libs_ver}.tar.gz
Source3: https://codeload.%{_uri}/libs/tar.gz/refs/tags/%{_driver_ver}+driver#/%{name}-libs-%{_driver_ver}-driver.tar.gz
Source4: https://codeload.%{_uri}/%{name}ctl/tar.gz/refs/tags/v%{_ctl_ver}#/%{name}ctl-%{_ctl_ver}.tar.gz
Source5: https://codeload.%{_uri}/plugins/tar.gz/refs/tags/plugins/container/v%{_p_container_ver}#/plugins-plugins-container-v%{_p_container_ver}.tar.gz
Source6: %{name}.service
Source7: %{name}.sysusers
Source8: %{name}.tmpfiles

%description
Falco is a cloud native runtime security tool for Linux operating systems. It
is designed to detect and alert on abnormal behavior and potential security
threats in real-time. At its core, Falco is a kernel monitoring and detection
agent that observes events, such as syscalls, based on custom rules. Falco
can enhance these events by integrating metadata from the container runtime
and Kubernetes. The collected events can be analyzed off-host in SIEM or data
lake systems

%prep
%setup -c -q
%setup -a 1 -qcTD
%setup -a 2 -qcTD
%setup -a 3 -qcTD
%setup -a 4 -qcTD
%setup -a 5 -qcTD

export GOPATH="%{_builddir}/gopath"
export GOBIN="${GOPATH}/bin"
mkdir -p "${GOPATH}/src/%{_uri}"
ln -snf "%{_builddir}/%{name}-%{version}/%{name}ctl-%{_ctl_ver}" \
  "${GOPATH}/src/%{_uri}/%{name}ctl"

# Use distro FORTIFY_SOURCE
%{__sed} --in-place \
  --expression 's|-D_FORTIFY_SOURCE=2||g' \
  "%{name}-%{version}/cmake/modules/CompilerFlags.cmake"

# Do not listen 0.0.0.0/0 by default!
%{__sed} --in-place \
  --expression 's|listen_address: 0.0.0.0|listen_address: 127.0.0.1|g' \
  "%{name}-%{version}/%{name}.yaml"

# plugin/container golang code - set flags for cache
%{__sed} --in-place \
  --expression 's|CGO_ENABLED=1||g' \
  --expression 's|ldflags="-s -w"|ldflags "-linkmode external -extldflags '\''${LDFLAGS}'\''"|g' \
  --expression 's|go build|go build -trimpath -mod=readonly -modcacherw|g' \
  "plugins-plugins-container-v%{_p_container_ver}/plugins/container/go-worker/Makefile"

# plugin/container CXX - remove 'fix for legacy compatibility'
%{__sed} --in-place \
  --expression 's|-static-libgcc -static-libstdc++||g' \
  "plugins-plugins-container-v%{_p_container_ver}/plugins/container/CMakeLists.txt"

# plugin/container CXX - do not strip, save debug symbols
%{__sed} --in-place \
  --expression 's| -s||g' \
  "plugins-plugins-container-v%{_p_container_ver}/plugins/container/cmake/modules/compiler.cmake"

%build
# Don't know why, but some libs in EL9 is not linked with error like this:
# error adding symbols: DSO missing from command line
%define _cmake_linker_flags -lre2 -ltbb

%define _vpath_srcdir plugins-plugins-container-v%{_p_container_ver}/plugins/container
# This is CMake prepare for plugin/container - very req plugin due hardcode in falco_rules.yaml file
%define __cmake_builddir plugin-container-build
%cmake -Wno-dev \
  -D CMAKE_EXE_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D CMAKE_SHARED_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D CMAKE_BUILD_TYPE="RelWithDebInfo" \
  -D LIBS_DIR="%{_builddir}/%{name}-%{version}/libs-%{_libs_ver}" \
  -D USE_BUNDLED_DEPS=Off \
  -D USE_BUNDLED_DRIVER=Off \
  -D USE_BUNDLED_JSONCPP=Off \
  -D USE_BUNDLED_CXXOPTS=Off \
  -D USE_BUNDLED_RE2=Off \
  -D USE_BUNDLED_TBB=Off \
  -D USE_BUNDLED_UTHASH=Off \
  -D USE_BUNDLED_VALIJSON=Off \
  -D USE_BUNDLED_ZLIB=Off
%cmake_build --target "container" --config "Release" %{?_parallel_builds}

%define _vpath_srcdir %{name}-%{version}
# This is CMake prepare for eBPF files that req for actual falco build
%define __cmake_builddir skeleton-build
%cmake -Wno-dev \
  -D CMAKE_EXE_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D CMAKE_SHARED_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D DRIVER_SOURCE_DIR="%{_builddir}/%{name}-%{version}/libs-%{_driver_ver}-driver/driver" \
  -D FALCOSECURITY_LIBS_SOURCE_DIR="%{_builddir}/%{name}-%{version}/libs-%{_libs_ver}" \
  -D FALCOSECURITY_RULES_FALCO_PATH="%{_builddir}/%{name}-%{version}/rules-%{name}-rules-%{_rules_ver}/rules/%{name}_rules.yaml" \
  -D USE_BUNDLED_DEPS=Off \
  -D USE_BUNDLED_CPPHTTPLIB=Off \
  -D USE_BUNDLED_DRIVER=Off \
  -D USE_BUNDLED_JSONCPP=Off \
  -D USE_BUNDLED_LIBBPF=Off \
  -D USE_BUNDLED_LIBELF=Off \
  -D USE_BUNDLED_MODERN_BPF=Off \
  -D USE_BUNDLED_NLOHMANN_JSON=Off \
  -D USE_BUNDLED_OPENSSL=Off \
  -D USE_BUNDLED_RE2=Off \
  -D USE_BUNDLED_TBB=Off \
  -D USE_BUNDLED_UTHASH=Off \
  -D USE_BUNDLED_VALIJSON=Off \
  -D USE_BUNDLED_YAMLCPP=Off \
  -D USE_BUNDLED_ZLIB=Off \
  -D BUILD_FALCO_UNIT_TESTS=Off \
  -D BUILD_DRIVER=Off \
  -D USE_JEMALLOC=On \
  -D BUILD_FALCO_MODERN_BPF=On \
  -D FALCO_VERSION="%{version}"
%cmake_build --target "ProbeSkeleton" --config "Release" %{?_parallel_builds}

# This is CMake prepare for falco
%define __cmake_builddir build
%cmake -Wno-dev \
  -D CMAKE_EXE_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D CMAKE_SHARED_LINKER_FLAGS="%{?_cmake_linker_flags}" \
  -D DRIVER_SOURCE_DIR="%{_builddir}/%{name}-%{version}/libs-%{_driver_ver}-driver/driver" \
  -D FALCOSECURITY_LIBS_SOURCE_DIR="%{_builddir}/%{name}-%{version}/libs-%{_libs_ver}" \
  -D FALCOSECURITY_RULES_FALCO_PATH="%{_builddir}/%{name}-%{version}/rules-%{name}-rules-%{_rules_ver}/rules/%{name}_rules.yaml" \
  -D USE_BUNDLED_DEPS=Off \
  -D USE_BUNDLED_CPPHTTPLIB=Off \
  -D USE_BUNDLED_DRIVER=Off \
  -D USE_BUNDLED_JSONCPP=Off \
  -D USE_BUNDLED_LIBBPF=Off \
  -D USE_BUNDLED_LIBELF=Off \
  -D USE_BUNDLED_MODERN_BPF=Off \
  -D USE_BUNDLED_NLOHMANN_JSON=Off \
  -D USE_BUNDLED_OPENSSL=Off \
  -D USE_BUNDLED_RE2=Off \
  -D USE_BUNDLED_TBB=Off \
  -D USE_BUNDLED_UTHASH=Off \
  -D USE_BUNDLED_VALIJSON=Off \
  -D USE_BUNDLED_YAMLCPP=Off \
  -D USE_BUNDLED_GPERFTOOLS=Off \
  -D USE_BUNDLED_ZLIB=Off \
  -D USE_BUNDLED_GTEST=Off \
  -D USE_BUNDLED_JEMALLOC=Off \
  -D CMAKE_BUILD_TYPE="RelWithDebInfo" \
  -D BUILD_FALCO_UNIT_TESTS=Off \
  -D ENABLE_BENCHMARKS=Off \
  -D BUILD_FALCO_MODERN_BPF=On \
  -D ADD_FALCOCTL_DEPENDENCY=Off \
  -D BUILD_DRIVER=Off \
  -D USE_GPERFTOOLS=On \
  -D USE_JEMALLOC=On \
  -D MODERN_BPF_SKEL_DIR="%{_builddir}/%{name}-%{version}/skeleton-build/skel_dir" \
  -D FALCO_VERSION="%{version}"
%cmake_build --target "%{name}" --config "Release" %{?_parallel_builds}

# This is falcoctl build (golang)
export GOCACHE="${HOME}/pkgcache/go-cache"
export GOMODCACHE="${HOME}/pkgcache/go"
export GOPATH="%{_builddir}/gopath"
export GOBIN="${GOPATH}/bin"
export GOTMPDIR="${GOPATH}/tmp"
mkdir -p "${GOTMPDIR}"
cd "${GOPATH}/src/%{_uri}/%{name}ctl"

eval "$(go env | grep -e "GOHOSTOS" -e "GOHOSTARCH")"
GOOS="${GOHOSTOS}" GOARCH="${GOHOSTARCH}" \
  go build -x \
  -buildmode="pie" \
  -trimpath \
  -mod="readonly" \
  -modcacherw \
  -ldflags "-linkmode external \
  -X %{_uri}/%{name}ctl/cmd/version.semVersion=%{_ctl_ver} \
  -X %{_uri}/%{name}ctl/cmd/version.gitCommit=tarball \
  -X %{_uri}/%{name}ctl/cmd/version.buildDate=$(date -u -d@$SOURCE_DATE_EPOCH +%%Y%%m%%d)"

%check
%define __cmake_builddir build
%cmake_build --target "cppcheck" %{?_parallel_builds}

export GOPATH="%{_builddir}/gopath"
export GOTMPDIR="${GOPATH}/tmp"
mkdir -p "${GOTMPDIR}"
eval "$(go env | grep -e "GOHOSTOS" -e "GOHOSTARCH")"
cd "${GOPATH}/src/%{_uri}/%{name}ctl"
GOOS="${GOHOSTOS}" GOARCH="${GOHOSTARCH}" TMPDIR="${GOTMPDIR}" \
  go test -modcacherw -cover ./...

%install
%cmake_install
# Delete libtool archives
find %{buildroot}%{_libdir} -type f -name "*.*a" -delete -print
install -Dm0755 "%{name}ctl-%{_ctl_ver}/%{name}ctl" -t "%{buildroot}%{_bindir}"
install -Dm0644 "%{SOURCE6}" "%{buildroot}%{_unitdir}/%{name}.service"
install -Dm0644 "%{SOURCE7}" "%{buildroot}%{_sysusersdir}/%{name}.conf"
install -Dm0644 "%{SOURCE8}" "%{buildroot}%{_tmpfilesdir}/%{name}.conf"
# Some compiled stuff from Internet
rm --verbose --force "%{buildroot}%{_datadir}/%{name}/plugins/libcontainer.so"
install -Dm0755 "plugin-container-build/libcontainer.so" -t \
"%{buildroot}%{_datadir}/%{name}/plugins"

%files
%license %{name}-%{version}/LICENSE
%attr(0755,root,root) %{_bindir}/{%{name},%{name}ctl}
%{_libdir}/{libsinsp,libpman,libscap}*
%{_libdir}/pkgconfig/{libsinsp,libpman,libscap}.pc
%{_datadir}/%{name}/plugins/libcontainer.so
%defattr(0644,root,root,0755)
%dir %{_sysconfdir}/%{name}/{config.d,rules.d}
%config %{_sysconfdir}/%{name}/%{name}_rules.yaml
%config(noreplace) %{_sysconfdir}/%{name}/{%{name}.yaml,%{name}_rules.local.yaml}
%config(noreplace) %{_sysconfdir}/%{name}ctl/%{name}ctl.yaml
%config %{_sysconfdir}/%{name}/config.d/%{name}.container_plugin.yaml
%{_includedir}/%{name}security/{driver,libscap,libsinsp,plugin}/*
%{_includedir}/libpman.h
%{_usrsrc}/%{name}*
%{_sysusersdir}/%{name}.conf
%{_unitdir}/%{name}.service
%{_tmpfilesdir}/%{name}.conf

%pre
%sysusers_create_package %{name} "%{SOURCE7}"
%tmpfiles_create_package %{name} "%{SOURCE8}"

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%changelog
* Fri Aug 21 2026 Konstantin Shalygin <k0ste@k0ste.ru> - 0.44.1-5
- Added build for plugin/container (libcontainer.so)

* Thu Aug 20 2026 Konstantin Shalygin <k0ste@k0ste.ru> - 0.44.1-4
- Added tmpfiles support

* Wed Aug 19 2026 Konstantin Shalygin <k0ste@k0ste.ru> - 0.44.1-3
- Added systemd support

* Fri Aug 14 2026 Konstantin Shalygin <k0ste@k0ste.ru> - 0.44.1-2
- Added libs and headers: libscap, libsinsp to files

* Mon Aug 10 2026 Konstantin Shalygin <k0ste@k0ste.ru> - 0.44.1-1
- RPM Packaging added
