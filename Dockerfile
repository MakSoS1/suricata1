# Multi-stage build for Suricata with Rust-based STUN parser
FROM ubuntu:22.04 AS build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    bison \
    build-essential \
    cargo \
    cmake \
    flex \
    git \
    libcap-ng-dev \
    libgeoip-dev \
    libjansson-dev \
    libjemalloc-dev \
    liblz4-dev \
    liblzma-dev \
    libmagic-dev \
    libmaxminddb-dev \
    libnet1-dev \
    libnetfilter-queue-dev \
    libnspr4-dev \
    libnss3-dev \
    libpcap-dev \
    libpcre2-dev \
    libpcre3-dev \
    libtool-bin \
    libunwind-dev \
    libyaml-dev \
    pkg-config \
    python3 \
    python3-pip \
    rustc \
    zlib1g-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN ./autogen.sh && \
    CFLAGS="-O0 -g3" ./configure \
      --enable-debug \
      --enable-unittests \
      --enable-rust \
      --prefix=/usr/local \
      --sysconfdir=/etc/suricata && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig

# Runtime image
FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libcap-ng0 \
    libgeoip1 \
    libjansson4 \
    libjemalloc2 \
    liblz4-1 \
    liblzma5 \
    libmagic1 \
    libmaxminddb0 \
    libnet1 \
    libnetfilter-queue1 \
    libnspr4 \
    libnss3 \
    libpcap0.8 \
    libpcre2-8-0 \
    libpcre3 \
    libunwind8 \
    libyaml-0-2 \
    zlib1g \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local /usr/local
COPY --from=build /etc/suricata /etc/suricata

# Ensure runtime directories exist
RUN mkdir -p /var/run/suricata /var/log/suricata && \
    ldconfig

WORKDIR /var/run/suricata
ENTRYPOINT ["/usr/local/bin/suricata"]
CMD ["-V"]
