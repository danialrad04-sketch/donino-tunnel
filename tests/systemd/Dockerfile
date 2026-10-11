ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}
ENV container=docker
COPY donino_link/resources/platform.sh /tmp/donino-platform.sh
RUN /bin/bash -Eeuo pipefail -c 'source /tmp/donino-platform.sh; donino_platform; donino_apt update -q; donino_apt install -y -q systemd systemd-sysv dbus openssh-server python3 python3-venv python3-pip openssl iproute2 iputils-ping iptables ufw ca-certificates; rm -rf /var/lib/apt/lists/*'
RUN mkdir -p /run/sshd && ssh-keygen -A && systemctl enable ssh.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
