FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        cargo \
        ccache \
        clang \
        cmake \
        curl \
        file \
        gdb \
        git \
        golang-go \
        jq \
        libffi-dev \
        libglib2.0-dev \
        libgtk-3-dev \
        liblzma-dev \
        libpixman-1-dev \
        libssl-dev \
        lldb \
        meson \
        ninja-build \
        nodejs \
        npm \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        rustc \
        strace \
        unzip \
        wget \
        xz-utils \
        zip \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /workspace

# CodeAuditor passes the invoking host UID/GID explicitly so bind-mounted
# scratch files stay owned by the caller.  Keep a non-root fallback for direct
# or diagnostic runs that do not use the wrapper.
USER 65534:65534
