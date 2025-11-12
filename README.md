# Packet Monitor

eBPF-based packet monitoring tool with web dashboard

Setup Instructions

# Environment
This project runs inside a virtualized Linux environment (tested on Ubuntu via VirtualBox).
Download and install Oracle VirtualBox or VMware.
Download the Ubuntu Desktop or Server ISO. 
Create a new VM, allocate RAM and disk space, mount the ISO and complete the OS installation. 
Install VS Code inside the VM.

# Install dependencies
sudo apt install git

# Create Python virtual environment
sudo apt install python3-venv

python3 -m venv cnenv

source cnenv/bin/activate

# Install Python packages
pip install flask==3.0.0

pip install flask-socketio==5.3.5

pip install python-socketio==5.10.0

pip install numba pytest

pip install bcc

# Install eBPF / BCC dependencies

# For Ubuntu
sudo apt update

sudo apt install python3-bcc bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r)

sudo apt install clang llvm libelf-dev

# For Arch Linux
sudo pacman -Syu python-bcc
# Running the CLI
sudo python3 packet_monitoring_cli.py

# Running the dashboard
sudo python3 app.py

python3 analyze_drops.py
