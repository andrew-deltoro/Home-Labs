# Wazuh Home Lab — Build Session Summary (Part 1)
**May 28, 2026**

---

## Goal

Build a Wazuh home security lab from scratch using two VirtualBox VMs — an Ubuntu Server running the Wazuh stack, and a Windows 10 endpoint running the Wazuh agent.

---

## VM Configuration

### Ubuntu Server (Wazuh Server)

| Setting | Value |
|---|---|
| RAM | 4096 MB (4GB) |
| CPUs | 2 |
| Disk | 50 GB (expanded from 25 GB) |
| OS | Ubuntu Server 22.04 LTS |
| Adapter 1 | NAT (internet access) |
| Adapter 2 | Host-Only (VM-to-VM communication) |

<img width="781" height="618" alt="ram and cpu" src="https://github.com/user-attachments/assets/a1a699d3-d0bb-4cbe-8cf0-098fb6322c4c" />
<img width="781" height="618" alt="ram and cpu 2" src="https://github.com/user-attachments/assets/772399b6-6360-493f-a92b-db7a7356e205" />

### Windows 10 VM (Endpoint)

| Setting | Value |
|---|---|
| RAM | 4096 MB (4GB) |
| CPUs | 2 |
| Disk | 50 GB |
| Adapter 1 | NAT (internet access) |
| Adapter 2 | Host-Only (VM-to-VM communication) |

---

## Network Setup

Both VMs use a dual-adapter setup:
- **Adapter 1 → NAT:** gives each VM internet access
- **Adapter 2 → Host-Only:** allows VM-to-VM communication on the `192.168.56.x` subnet
You need both because:

Without NAT → can't download Wazuh agent, Sysmon, updates
Without Host-Only → Windows VM can't send logs to the Wazuh server

It's a standard two-adapter lab setup. The NAT adapter handles the outside world, the Host-Only adapter handles your internal lab network.

Windows 10 IP on Host-Only network: `192.168.56.102`

Ubuntu `enp0s8` was initially not auto-assigned an IP on boot. Checked interfaces with:

```bash
ip a
```

Fixed by editing Netplan:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Config added:

```yaml
network:
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: true
  version: 2
```

```bash
sudo chmod 600 /etc/netplan/00-installer-config.yaml
sudo netplan apply
```

Windows 10 VM network confirmed with:

```cmd
ipconfig
```
<img width="1026" height="854" alt="windows 10 cmd ipconfig" src="https://github.com/user-attachments/assets/97ed6076-ac0d-4fd8-a3d1-c1f90721f6dd" />

---

## Wazuh Installation

Wazuh was installed using the official all-in-one installer script:

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash wazuh-install.sh -a -i
```

Flags used:
- `-a` — all-in-one install (manager + indexer + dashboard)
- `-i` — ignore hardware requirement warnings

After install, credentials were printed to the terminal:
- **Username:** admin
- **Password:** (auto-generated — saved separately)

To retrieve credentials from the log at any time:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

---

## Problems Encountered & Fixes

### 1. Wazuh Hardware Warning During Install

Installer flagged that the system did not meet minimum hardware requirements. The `-i` flag was placed in the wrong position initially.

Fixed by placing `-i` at the end of the command:

```bash
sudo bash wazuh-install.sh -a -i
```

---

### 2. Disk Full (100%) — /dev/sda2

Wazuh's vulnerability detection updater filled the 25GB disk completely. Diagnosed with:

```bash
sudo du -h / --max-depth=2 2>/dev/null | sort -rh | head -20
sudo du -h /var/ossec --max-depth=2 2>/dev/null | sort -rh | head -20
```

```bash
df -h
```

Found `/var/ossec/queue/vd_updater` was consuming 13GB. Cleared with:

```bash
sudo rm -rf /var/ossec/queue/vd_updater/*
sudo rm -rf /var/ossec/queue/vd/*
```

---

### 3. Disk Expansion Not Reflecting

Expanding the VDI in VirtualBox only grows the virtual disk file — the Linux partition and filesystem still need to be resized manually inside the VM. Wazuh services were stopped first, then:

```bash
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
sudo systemctl stop wazuh-dashboard
sudo growpart /dev/sda 2
sudo resize2fs /dev/sda2
```

Result: disk expanded from 25GB to 50GB with 23GB free (53% usage).

---

### 4. enp0s8 Not Persisting on Reboot

The Host-Only adapter (`enp0s8`) had no IP after every reboot, requiring manual `dhclient` runs. Fixed permanently by adding the interface to the Netplan configuration (see Network Setup section above).

---

### 5. Password Reset — No Space on Device

Attempted to reset the admin password using the Wazuh password tool but failed due to full disk.

Resolved after disk expansion. Correct command:

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p NewPassword123
```

---

## Current Status

| Item | Status |
|---|---|
| Ubuntu VM running | ✅ Complete |
| Wazuh installed (v4.9.2) | ✅ Complete |
| Disk expanded to 50GB | ✅ Complete |
| Host-Only networking configured | ✅ Complete |
| enp0s8 auto-assigns IP on boot | ✅ Complete |
| Wazuh services running | ✅ Complete |
| Access Wazuh dashboard | ⏳ Next Step |
| Install Wazuh agent on Windows 10 VM | ⏳ Pending |

---

## Next Steps

- Access the Wazuh dashboard via browser at `https://<ubuntu-host-only-ip>`
- Install the Wazuh agent on the Windows 10 VM
- Point the agent at the Ubuntu VM's Host-Only IP
- Verify the Windows endpoint appears as Active in the dashboard
- Optionally install Sysmon on Windows 10 for enhanced endpoint telemetry
