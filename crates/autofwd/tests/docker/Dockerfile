FROM alpine:3.20

# Install OpenSSH server, netcat, and socat for testing
RUN apk add --no-cache openssh-server netcat-openbsd procps socat

# Generate host keys
RUN ssh-keygen -A

# Create test user and unlock the account (Alpine locks accounts with no password)
RUN adduser -D -s /bin/sh testuser && \
    passwd -u testuser

# Configure sshd for testing
RUN mkdir -p /run/sshd && \
    sed -i 's/^AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config && \
    sed -i 's/^GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config && \
    sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "AuthorizedKeysFile .ssh/authorized_keys" >> /etc/ssh/sshd_config && \
    echo "StrictModes no" >> /etc/ssh/sshd_config

# Create .ssh directory for testuser
RUN mkdir -p /home/testuser/.ssh && \
    chmod 700 /home/testuser/.ssh && \
    chown -R testuser:testuser /home/testuser/.ssh

# The authorized_keys file will be mounted at runtime
# This allows each test to use its own ephemeral key

EXPOSE 22

# Run sshd in foreground with debug logging
CMD ["/usr/sbin/sshd", "-D", "-e"]
