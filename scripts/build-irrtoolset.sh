#!/bin/sh
# build-irrtoolset.sh builds IRRToolSet 5.1.3's rtconfig and peval for the
# differential tests (resolve/rtconfig_irrtoolset_test.go,
# resolve/peval_irrtoolset_test.go) and installs them in PREFIX/bin:
#
#   scripts/build-irrtoolset.sh [PREFIX]     # default $HOME/.cache/irrtoolset-5.1.3
#   export PATH="$HOME/.cache/irrtoolset-5.1.3/bin:$PATH"
#
# It builds at -O0: GCC's -O2 build crashes printing any prefix set. On Linux
# it builds natively (CI does; it needs build-essential autoconf automake
# libtool bison flex pkgconf libreadline-dev). Anywhere else it builds in
# Docker (debian:trixie) and installs wrappers that run the Linux binaries in
# a container, reaching a server on this host's loopback through
# host.docker.internal. The tests name their server in IRR_HOST/IRR_PORT/
# IRR_SOURCES, which every build reads. Homebrew's bottle (brew install
# irrtoolset) also works, for cisco only: it ignores its command line.
set -eu
tag=release-5.1.3
commit=6b385e9e5d96670451f76b8204e8ec90b85e1cf0
repo=https://github.com/irrtoolset/irrtoolset.git
prefix=${1:-$HOME/.cache/irrtoolset-5.1.3}

if [ "$(uname -s)" = Linux ]; then
	src=$(mktemp -d)
	trap 'rm -rf "$src"' EXIT
	git clone --quiet --depth 1 --branch "$tag" "$repo" "$src"
	test "$(git -C "$src" rev-parse HEAD)" = "$commit"
	cd "$src"
	autoreconf --force --install >/dev/null 2>&1
	CFLAGS=-O0 CXXFLAGS=-O0 ./configure --quiet --prefix="$prefix"
	make --quiet -j"$(nproc)" >/dev/null
	make --quiet install >/dev/null
else
	image=rpsl-irrtoolset:5.1.3
	docker build --quiet -t "$image" - >/dev/null <<EOF
FROM debian:trixie
RUN apt-get update -qq && apt-get install -y -qq build-essential autoconf automake libtool bison flex pkgconf libreadline-dev git >/dev/null
RUN git clone --quiet --depth 1 --branch $tag $repo /src && test "\$(git -C /src rev-parse HEAD)" = $commit
RUN cd /src && autoreconf --force --install >/dev/null 2>&1 && CFLAGS=-O0 CXXFLAGS=-O0 ./configure --quiet && make --quiet -j8 >/dev/null && make --quiet install >/dev/null
EOF
	mkdir -p "$prefix/bin"
	for tool in rtconfig peval; do
		cat >"$prefix/bin/$tool" <<EOF
#!/bin/sh
# IRRToolSet 5.1.3's $tool, built by scripts/build-irrtoolset.sh, run in Docker.
host=\${IRR_HOST:-}
case \$host in 127.0.0.1|localhost|::1) host=host.docker.internal ;; esac
exec docker run --rm -i --add-host=host.docker.internal:host-gateway \\
	-e IRR_HOST="\$host" -e IRR_PORT="\${IRR_PORT:-}" -e IRR_SOURCES="\${IRR_SOURCES:-}" $image $tool "\$@"
EOF
		chmod +x "$prefix/bin/$tool"
	done
fi
test -x "$prefix/bin/rtconfig" && test -x "$prefix/bin/peval"
echo "IRRToolSet 5.1.3 is in $prefix/bin; put it on PATH for the differential tests"
