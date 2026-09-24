# EntropyLab development container — the entire contributing environment.
#
# Nothing needs to be installed on the host except Docker itself: this image
# carries Node.js (pinned), the Rust toolchain pinned by
# entropylab-wasm/rust-toolchain.toml (1.95.0 + wasm32 target), clang for the
# C sources vendored into the WASM crate, and the two browser engines the
# headless integration suite (test/browser.test.mjs) runs: Firefox and
# Chrome/Chromium. (Microsoft Edge is a Chromium fork sharing Chrome's
# engine and code path; the harness runs it too when it is installed.)
#
#   docker compose up --build              # build the image, interactive shell
#   docker compose run --rm dev bash
#   docker compose run --rm dev npm test   # full suite incl. both browsers
#
# Environment variables baked into the image (overridable at run time):
#   BROWSER_TEST_NO_SANDBOX=1  headless Chrome/Edge run unsandboxed (the
#                              container does not grant the setuid sandbox
#                              privileges; the app under test is what is
#                              audited, not the browser)
#   RUSTUP_HOME / CARGO_HOME   shared, pre-fetched Rust toolchain + crates
#   NPM_CONFIG_CACHE           pre-fetched npm cache (npm ci needs no network)
# Optional per-browser overrides honoured by test/browser.test.mjs:
#   FIREFOX_BINARY, CHROME_BINARY (or CHROMIUM_BINARY), EDGE_BINARY
#   (EDGE_BINARY selects a local Edge install; the image ships none)

# linux/amd64 manifest of the previous index pin (sha256:69cecf4b…). An index
# digest would select a different clang on another architecture. Ubuntu's
# archive is frozen to one snapshot so the clang packages cannot move between
# image builds (Google's Chrome repository below is not snapshotted).
# Bump the digest, the snapshot, and the clang versions together.
FROM --platform=linux/amd64 ubuntu:24.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4

ARG NODE_VERSION=v22.23.2
ARG FIREFOX_VERSION=140.14.0esr
ARG UBUNTU_SNAPSHOT=20260916T000000Z
ARG CLANG_VERSION=1:18.0-59~exp2
ARG CLANG18_VERSION=1:18.1.3-1ubuntu1

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    NPM_CONFIG_CACHE=/usr/local/npm-cache \
    BROWSER_TEST_NO_SANDBOX=1 \
    PATH=/usr/local/cargo/bin:/home/dev/.local/bin:$PATH

# System packages: git, compilers (the pinned clang builds libsecp256k1's
# vendored C for wasm32), tarball tooling, fonts so the headless layout
# checks measure real text metrics. clang-18 pins libllvm18, libclang1-18,
# libclang-common-18-dev and llvm-18-linker-tools to its own version but only
# lower-bounds libclang-cpp18, which the clang binary links, so that one is
# pinned here as well.
#
# snapshot.ubuntu.com is served over https and the base image has no CA
# bundle, so the first index fetch and the ca-certificates install run with
# TLS peer checks off. apt still checks the signed InRelease against the base
# image's ubuntu-keyring, and every index and package hash under it — the
# same guarantee the stock http:// archive relies on. Every apt call after
# that verifies TLS. `--error-on=any` fails the build on a failed index fetch;
# without it apt only warns and the build dies later on a missing package.
RUN set -eu; \
    sources=/etc/apt/sources.list.d/ubuntu.sources; \
    snapshot="https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}"; \
    sed -i \
      -e "s|http://archive.ubuntu.com/ubuntu|${snapshot}|g" \
      -e "s|http://security.ubuntu.com/ubuntu|${snapshot}|g" \
      "$sources"; \
    uris=$(grep -c '^URIs:' "$sources" || true); \
    pinned=$(grep -c "^URIs: ${snapshot}/*$" "$sources" || true); \
    if [ "$uris" -eq 0 ] || [ "$pinned" -ne "$uris" ]; then \
      echo "ubuntu.sources names a mirror other than ${snapshot}" >&2; \
      exit 1; \
    fi; \
    apt-get -o Acquire::https::Verify-Peer=false update --error-on=any; \
    apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends \
      ca-certificates; \
    apt-get update --error-on=any; \
    apt-get install -y --no-install-recommends \
      curl git gnupg xz-utils bzip2 sqlite3 python3 \
      build-essential \
      "clang=${CLANG_VERSION}" \
      "clang-18=${CLANG18_VERSION}" \
      "libclang-cpp18=${CLANG18_VERSION}" \
      fontconfig fonts-liberation; \
    rm -rf /var/lib/apt/lists/*

# Pinned Node.js (engines: >= 20.19; CI runs 22).
RUN curl -fsSLO "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
    && tar -xJf "node-${NODE_VERSION}-linux-x64.tar.xz" -C /usr/local --strip-components=1 \
    && rm "node-${NODE_VERSION}-linux-x64.tar.xz" \
    && node --version && npm --version

# Firefox runtime libraries (the tarball is not linked against any distro
# packages, so its GTK/XPCOM shared libraries must be installed explicitly).
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libatk-bridge2.0-0t64 \
      libx11-xcb1 libxcb-dri3-0 libxkbcommon0 libxkbcommon-x11-0 libxt6t64 \
      libnspr4 libnss3 libcups2t64 libxcomposite1 libxdamage1 libxrandr2 \
      libxtst6 libpangocairo-1.0-0 libcairo-gobject2 libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Pinned Firefox ESR tarball (Ubuntu's apt firefox is a snap shim and cannot
# run in a container; the harness already handles the unconfined tarball).
RUN curl -fsSLO "https://archive.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/linux-x86_64/en-US/firefox-${FIREFOX_VERSION}.tar.xz" \
    && mkdir -p /opt/firefox \
    && tar -xJf "firefox-${FIREFOX_VERSION}.tar.xz" -C /opt/firefox --strip-components=1 \
    && ln -s /opt/firefox/firefox /usr/local/bin/firefox \
    && rm "firefox-${FIREFOX_VERSION}.tar.xz" \
    && firefox --version

# Chrome from Google's official apt repository (amd64). Chrome covers the
# whole Chromium family: Microsoft Edge is a Chromium fork that shares its
# engine and headless code path.
RUN curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
        | gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb stable main" \
        > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/* \
    && google-chrome --version

# Non-root user. The base image's `ubuntu` account already owns uid 1000
# (which matches typical host users, keeping the bind-mounted workspace
# writable), so it is renamed `dev` with a matching home directory.
RUN groupmod -n dev ubuntu && usermod -l dev ubuntu && usermod -d /home/dev -m dev

# Rust: `default-toolchain none` keeps the base image lean; the exact
# 1.95.0 toolchain + wasm32 target activate from each crate's
# rust-toolchain.toml. The dependency graphs of all three crates are
# fetched into the shared CARGO_HOME so the first `npm run build:wasm`
# needs no network.
RUN curl -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none

COPY entropylab-wasm/ /warm/crate/
COPY vanity-wasm/ /warm/vanity-crate/
COPY psbt-wasm/ /warm/psbt-crate/
RUN cd /warm/crate \
    && rustup target add wasm32-unknown-unknown --toolchain 1.95.0 \
    && cargo fetch \
    && cd /warm/vanity-crate \
    && cargo fetch \
    && cd /warm/psbt-crate \
    && cargo fetch

# Warm the shared npm cache (locked dependencies only — the app has no
# lifecycle scripts; --ignore-scripts matches CI).
COPY package.json package-lock.json /warm/npm/
RUN cd /warm/npm && npm ci --ignore-scripts
RUN chown -R dev:dev /usr/local/npm-cache /usr/local/cargo && rm -rf /warm

WORKDIR /workspace
USER dev
# USER/HOME are set only here so build-time package postinsts (which write
# into $HOME) do not pre-create /home/dev before the rename above.
ENV USER=dev HOME=/home/dev
CMD ["bash"]
