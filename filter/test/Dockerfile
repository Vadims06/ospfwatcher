FROM vadims06/ospf-filter:latest
RUN apk add --no-cache bpftool python3 py3-pip && pip install --no-cache-dir --break-system-packages scapy
COPY test/run_tests.py /test/run_tests.py
ENTRYPOINT ["python3", "-W", "ignore", "/test/run_tests.py"]
