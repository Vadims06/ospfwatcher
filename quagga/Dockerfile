FROM frrouting/frr:v8.1.0

COPY ./config/ospfd.conf /etc/frr/ospfd.conf
COPY ./config/vtysh.conf /etc/frr/vtysh.conf

RUN sed -i 's/ospfd=no/ospfd=yes/g' /etc/frr/daemons && \
    chown frr:frr /etc/frr/ospfd.conf && \
    chmod 600 /etc/frr/vtysh.conf && \
    chown frr:frr /etc/frr/ospfd.conf && \
    chmod 600 /etc/frr/vtysh.conf && \
    mkdir -p /var/log/quagga && \
    chown frr:frr /var/log/quagga && \
    touch /var/log/quagga/ospfd.log && \
    chown frr:frr /var/log/quagga/ospfd.log