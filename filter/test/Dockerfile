FROM debian:bookworm
RUN apt-get update -qq && apt-get install -y -qq clang llvm libbpf-dev bpftool linux-libc-dev python3-scapy >/dev/null \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
