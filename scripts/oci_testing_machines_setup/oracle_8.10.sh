#!/bin/bash

# Oracle Linux 8.10 Complete Setup Script
# Run as root

set -e  # Exit on error

echo "=========================================="
echo "Starting Oracle Linux 8.10 System Setup"
echo "=========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (uid 0)."
    exit 1
fi

# Update system
echo "[1/8] Updating system packages..."
dnf update -y

# Install EPEL repository and base utilities
echo "[2/8] Installing EPEL repository and base utilities..."
dnf install -y oracle-epel-release-el8 2>/dev/null || dnf install -y epel-release
dnf config-manager --enable ol8_developer_EPEL
dnf install -y sudo iptables iptables-services grep

# Configure users
echo "[3/8] Configuring users..."
# Set root password
echo "root:Password1" | chpasswd

# Create admin user if doesn't exist
if ! id -u admin >/dev/null 2>&1; then
    # Check if group 'admin' already exists
    if getent group admin >/dev/null 2>&1; then
        echo "Group 'admin' exists. Creating user 'admin' assigned to existing group."
        useradd -m -s /bin/bash -g admin admin
    else
        echo "Creating user 'admin' and group 'admin'."
        useradd -m -s /bin/bash admin
    fi
else
    echo "User 'admin' already exists."
fi

# Set admin password
echo "admin:Password1" | chpasswd

# Add admin to wheel group (sudo equivalent in RHEL/Oracle Linux)
usermod -aG wheel admin

# Ensure wheel group has sudo access
if ! grep -q "^%wheel" /etc/sudoers 2>/dev/null; then
    echo "%wheel  ALL=(ALL)       ALL" >> /etc/sudoers
fi

# Configure SSH
echo "[4/8] Configuring SSH..."
# Enable root login with password
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

rm -fRd /etc/ssh/sshd_config.d/*

# Restart SSH service
systemctl restart sshd 2>/dev/null || true

# Configure firewall (disable firewalld, clear iptables)
echo "[5/8] Configuring firewall services..."
# Disable and stop firewalld
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true

# Flush all iptables rules (handles cloud provider pre-configured rules)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Set default policies to ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Flush ip6tables as well
ip6tables -F
ip6tables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

# Save the clean rules
service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables 2>/dev/null || true

# Disable SELinux
echo "Disabling SELinux..."
setenforce 0 2>/dev/null || true
sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true
sed -i 's/^SELINUX=disabled/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true

# Install required packages
echo "[6/8] Installing required packages..."
dnf install -y \
    ncdu \
    nmap-ncat \
    git \
    wget \
    jq \
    bind-utils \
    htop \
    tcpdump \
    tree \
    zip \
    unzip \
    strace \
    nmap \
    lsof \
    curl \
    gnupg2 \
    ca-certificates \
    bash \
    zsh \
    fish \
    dash

curl -LsSf https://astral.sh/uv/install.sh | sh

# nmap-ncat only provides 'ncat'/'nc', but tests expect 'netcat' on PATH
if ! command -v netcat &>/dev/null; then
    ln -sf "$(readlink -f "$(command -v ncat)")" /bin/netcat
fi

# Install Python 3.12
echo "[7/8] Installing Python 3.12..."
# OL 8 system Python is 3.6 (platform-python used by dnf).
# Try repo install first, fall back to building from source.
if dnf list available python3.12 2>/dev/null | grep -q python3.12; then
    dnf install -y python3.12 python3.12-pip python3.12-devel
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
    alternatives --set python3 /usr/bin/python3.12
    # On OL 8 the 'python' alternative uses /usr/bin/unversioned-python as
    # primary link, so a plain symlink is simpler and avoids conflicts.
    ln -sf /usr/bin/python3.12 /usr/bin/python
else
    echo "Python 3.12 not available in repos, building from source..."
    exit 1
    # Install build dependencies
    # dnf install -y gcc gcc-c++ make openssl-devel bzip2-devel libffi-devel \
    #     zlib-devel readline-devel sqlite-devel xz-devel tk-devel \
    #     gdbm-devel ncurses-devel

    # # Download and compile Python 3.12
    # cd /tmp
    # wget https://www.python.org/ftp/python/3.12.0/Python-3.12.0.tgz
    # tar xzf Python-3.12.0.tgz
    # cd Python-3.12.0
    # ./configure --enable-optimizations --with-ensurepip=install
    # make -j$(nproc)
    # make altinstall

    # # Create alternatives
    # alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.12 1
    # alternatives --set python3 /usr/local/bin/python3.12
    # ln -sf /usr/local/bin/python3.12 /usr/bin/python

    # cd /
    # rm -rf /tmp/Python-3.12.0*
fi

# Install pip 24.0
echo "Installing pip 24.0..."
python3.12 -m pip install --upgrade pip==24.0 --break-system-packages 2>/dev/null || \
python3.12 -m pip install --upgrade pip==24.0

# Install Docker
echo "[8/8] Installing Docker..."
# Remove old versions if present
dnf remove -y docker docker-client docker-client-latest docker-common docker-latest \
    docker-latest-logrotate docker-logrotate docker-engine podman runc 2>/dev/null || true

# Add Docker repository
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker packages
dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Add admin user to docker group
usermod -aG docker admin

# Test Docker
echo "Testing Docker installation..."
if docker run hello-world; then
    echo "Docker test successful"
else
    echo "Docker test failed"
fi

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
