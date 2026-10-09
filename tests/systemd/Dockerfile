FROM debian:12
ENV container=docker
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q systemd systemd-sysv dbus openssh-server python3 python3-venv python3-pip openssl iproute2 iputils-ping iptables ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd && ssh-keygen -A && systemctl enable ssh.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
