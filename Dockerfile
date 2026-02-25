FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# Base tools and enable 'universe' (needed for clang-18, libbpf-dev, etc.)
RUN rm -rf /var/lib/apt/lists/* && \
    apt-get clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        software-properties-common && \
    # Add GCC 9 PPA (Ubuntu 18.04 defaults to GCC 7, we need GCC 9 to match Ubuntu 20.04)
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    # Add LLVM's official apt repository for clang-18
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bionic/ llvm-toolchain-bionic-18 main" > /etc/apt/sources.list.d/llvm.list && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc-9 \
        g++-9 \
        libstdc++-10-dev \
        git \
        pkg-config \
        xxd \
        # Clang / LLVM 18
        clang-18 \
        clang-tools-18 \
        llvm-18 \
        llvm-18-dev \
        lld-18 \
        # libbpf-dev (for libbpf)
        libelf-dev \
        libdw-dev \
        # zlib (shared + static)
        zlib1g-dev \
        # zstd (shared + static)
        libzstd-dev \
        # libssl-dev (for OpenSSL build)
        libssl-dev \
        # sqlite3 (for SQLite build)
        libsqlite3-dev \
        # libbz2 (transitive dep of libdw; link directly so RUNPATH finds it)
        libbz2-dev \
        # libs for tests
        libgtest-dev \
        googletest \
        cmake \
        # misc
        make && \
    # Set GCC 9 as the default gcc/g++
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 100 && \
    rm -rf /var/lib/apt/lists/*

# Build & install Google Test (Ubuntu 18.04's libgtest-dev ships source only)
RUN cd /usr/src/googletest && \
    cmake -DCMAKE_CXX_COMPILER=g++-9 . && \
    make -j"$(nproc)" && \
    find . -name '*.a' -exec cp {} /usr/lib/ \; && \
    ldconfig

# Make clang-18 and LLVM tools the default (without version suffix)
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 && \
    ln -sf /usr/bin/llvm-strip-18 /usr/bin/llvm-strip && \
    ln -sf /usr/bin/llvm-objcopy-18 /usr/bin/llvm-objcopy && \
    ln -sf /usr/bin/llvm-objdump-18 /usr/bin/llvm-objdump && \
    ln -sf /usr/bin/llvm-ar-18 /usr/bin/llvm-ar && \
    ln -sf /usr/bin/llvm-nm-18 /usr/bin/llvm-nm && \
    ln -sf /usr/bin/llvm-readelf-18 /usr/bin/llvm-readelf

ENV CC=clang \
    CXX=clang++ \
    CLANG=clang

WORKDIR /tmp

# Build & install libbpf v1.5.0 (Ubuntu 20.04's libbpf 0.5 is too old)
RUN git clone --depth=1 --branch v1.5.0 https://github.com/libbpf/libbpf.git && \
    make -C libbpf/src -j"$(nproc)" && \
    make -C libbpf/src install && \
    make -C libbpf/src install_uapi_headers && \
    ldconfig && \
    rm -rf libbpf

# Build & install bpftool v7.5.0
RUN git clone --depth=1 --branch v7.5.0 --recurse-submodules https://github.com/libbpf/bpftool.git && \
    make -C bpftool/src -j"$(nproc)" && \
    install -m 0755 bpftool/src/bpftool /usr/local/bin/bpftool && \
    rm -rf bpftool

# Install uv globally (to /usr/local/bin) so any user can access it
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    /usr/local/bin/uv python install 3.10 && \
    ln -sf $(/usr/local/bin/uv python find 3.10) /usr/local/bin/python3 && \
    ln -sf $(/usr/local/bin/uv python find 3.10) /usr/local/bin/python

ENV PATH="/usr/local/bin:$PATH"