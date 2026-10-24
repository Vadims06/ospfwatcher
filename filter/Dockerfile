FROM alpine:3.20
RUN apk add --no-cache clang libbpf-dev linux-headers iproute2-tc
COPY announcement_filter.c attach_filter.sh ./
ENV FILTER_INTERFACE=gre1
ENTRYPOINT ["./attach_filter.sh"]
