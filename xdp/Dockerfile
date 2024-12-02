ARG UBUNTU_VERSION=22.04
FROM ubuntu:$UBUNTU_VERSION

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

# Update and install build requirements.
RUN apt update && apt upgrade -y && \
    # Basic build requirements from documentation
    apt-get install -y \
            clang \
            libbpf-dev \
            linux-headers-generic \
            gcc-multilib \
            make \
            perl \
            python3-dev \
            iproute2 \
            python3-bpfcc

# Link asm/byteorder.h into eBPF
RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm
COPY xdp_drop.c xdp_drop.c
COPY apply_xdp_filter.sh apply_xdp_filter.sh
RUN clang -O2 -target bpf -c xdp_drop.c -o xdp_drop.o

ENV VTAP_HOST_INTERFACE=vhost1
ENTRYPOINT [ "./apply_xdp_filter.sh" ]