# Wazuh Home Lab — Command Reference Guide

**May 2026** | Sorted by system and phase


I wanted to keep a directory of commands used to setup and troublshoot the labs. Perhaps in the future I'll reference them again. 


## Linux Commands (Ubuntu Server)

### System & Disk Management

| Command | Purpose |
|---|---|
| `sudo apt update && sudo apt upgrade -y` | Update all system packages to latest versions |
| `sudo apt clean` | Clear cached package files to free disk space |
| `sudo rm -rf /var/cache/apt/archives/*` | Delete downloaded package archives to recover space |
| `sudo rm -rf /tmp/*` | Clear temporary files to free disk space |
| `df -h` | Show disk usage in human-readable format (GB/MB) |
| `sudo du -h / --max-depth=2 2>/dev/null \| sort -rh \| head -20` | Find the 20 largest directories on the system |
| `sudo du -h /var/ossec --max-depth=2 2>/dev/null \| sort -rh \| head -20` | Find largest directories inside Wazuh's data folder |
| `sudo journalctl --vacuum-size=100M` | Trim system logs down to 100MB to free space |
| `sudo growpart /dev/sda 2` | Expand partition 2 to use newly allocated disk space |
| `sudo resize2fs /dev/sda2` | Resize the filesystem to fill the expanded partition |
| `lsblk` | Show disk and partition layout |
| `sync` | Force OS to flush pending disk writes and update usage |

### Network

| Command | Purpose |
|---|---|
| `ip a` | Show all network interfaces and their IP addresses |
| `sudo dhclient enp0s8` | Request an IP address for the enp0s8 interface |
| `sudo ip link set enp0s8 up` | Bring the enp0s8 network interface online |
| `sudo nano /etc/netplan/00-installer-config.yaml` | Edit the Netplan config to persist network settings on boot |
| `sudo chmod 600 /etc/netplan/00-installer-config.yaml` | Fix file permissions so Netplan stops throwing warnings |
| `sudo netplan apply` | Apply Netplan network configuration changes |
| `sudo tcpdump -i enp0s8` | Capture and display live network traffic on enp0s8 |
| `sudo ufw status` | Check if the Ubuntu firewall is enabled and show rules |
| `sudo ufw allow 1514/tcp` | Allow Wazuh agent communication on TCP port 1514 |
| `sudo ufw allow 1515/tcp` | Allow Wazuh agent enrollment on TCP port 1515 |
| `sudo ufw allow 1514/udp` | Allow Wazuh agent communication on UDP port 1514 |

### SSH

| Command | Purpose |
|---|---|
| `sudo apt install openssh-server -y` | Install the SSH server on Ubuntu |
| `sudo systemctl enable ssh` | Set SSH to start automatically on every boot |
| `sudo systemctl start ssh` | Start the SSH service immediately |

### Wazuh Server Management

| Command | Purpose |
|---|---|
| `curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash wazuh-install.sh -a` | Download and run the Wazuh all-in-one installer |
| `sudo bash wazuh-install.sh -a -i` | Install Wazuh ignoring hardware requirement warnings |
| `sudo systemctl start wazuh-manager` | Start the Wazuh manager service |
| `sudo systemctl stop wazuh-manager` | Stop the Wazuh manager service |
| `sudo systemctl restart wazuh-manager` | Restart the Wazuh manager service |
| `sudo systemctl status wazuh-manager` | Check if the Wazuh manager is running |
| `sudo systemctl start wazuh-indexer` | Start the Wazuh indexer (data storage) service |
| `sudo systemctl stop wazuh-indexer` | Stop the Wazuh indexer service |
| `sudo systemctl start wazuh-dashboard` | Start the Wazuh web dashboard service |
| `sudo systemctl stop wazuh-dashboard` | Stop the Wazuh web dashboard service |
| `sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt` | Print the auto-generated Wazuh admin password |
| `sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p NewPassword` | Reset the Wazuh dashboard admin password |

### Wazuh Agent Management

| Command | Purpose |
|---|---|
| `sudo /var/ossec/bin/manage_agents` | Open interactive agent manager (add/remove/extract keys) |
| `sudo /var/ossec/bin/manage_agents -e 001` | Extract the registration key for agent ID 001 |
| `sudo /var/ossec/bin/agent_control -l` | List all registered agents and their connection status |
| `sudo tail -f /var/ossec/logs/ossec.log` | Watch Wazuh manager logs in real time |
| `sudo rm -rf /var/ossec/queue/vd_updater/*` | Delete vulnerability detection updater cache files |
| `sudo rm -rf /var/ossec/queue/vd/*` | Delete vulnerability detection queue files |
| `sudo lsof / \| grep deleted` | Find processes holding onto deleted files (preventing space recovery) |

### File & Process Utilities

| Command | Purpose |
|---|---|
| `sudo nano <filepath>` | Open a file in the nano text editor |
| `cat <filepath>` | Print file contents to the terminal |
| `sudo find / -name "wazuh-passwords-tool.sh" 2>/dev/null` | Search entire system for a specific file |
| `sudo find /var/ossec/logs/archives -type f -delete` | Delete all files inside the archives log folder |
| `sudo poweroff` | Shut down the Ubuntu VM |
| `sudo reboot` | Restart the Ubuntu VM |
| `watch -n 2 <command>` | Repeat a command every 2 seconds (live refresh) |

---

## Windows Commands (PowerShell & CMD)

### Wazuh Agent Installation

| Command | Purpose |
|---|---|
| `Invoke-WebRequest -Uri <url> -OutFile wazuh-agent.msi` | Download the Wazuh agent installer from the web (PowerShell) |
| `.\wazuh-agent.msi /q WAZUH_MANAGER="192.168.56.103"` | Silent install of Wazuh agent with manager IP set |
| `msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.56.103"` | Alternative silent install using msiexec |
| `msiexec /x wazuh-agent.msi /q` | Silently uninstall the Wazuh agent |

### Wazuh Agent Service

| Command | Purpose |
|---|---|
| `NET START WazuhSvc` | Start the Wazuh agent Windows service |
| `NET STOP WazuhSvc` | Stop the Wazuh agent Windows service |
| `Get-Service WazuhSvc` | Check the current status of the Wazuh service |
| `Get-Service \| Where-Object {$_.DisplayName -like "*wazuh*"}` | Search for any installed Wazuh-related services |
| `Set-Service -Name WazuhSvc -StartupType Automatic` | Set Wazuh service to start automatically on boot |
| `NET START WazuhSvc; Start-Sleep -Seconds 3; Get-Service WazuhSvc` | Start service, wait 3 seconds, then check its status |

### Wazuh Agent Configuration & Logs

| Command | Purpose |
|---|---|
| `notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"` | Open the Wazuh agent config file in Notepad |
| `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" \| Select-String "address"` | Check what manager IP is set in the agent config |
| `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" \| Select-String -Pattern "address\|port\|protocol"` | View key connection settings in the agent config |
| `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20` | View the last 20 lines of the Wazuh agent log |
| `& "C:\Program Files (x86)\ossec-agent\manage_agents.exe" -i <key>` | Import a registration key into the Windows agent |

### Network & Connectivity

| Command | Purpose |
|---|---|
| `ipconfig` | Show all network adapter IPs on Windows |
| `ssh vboxuser@192.168.56.103` | SSH into the Ubuntu VM from Windows PowerShell |
| `Test-NetConnection -ComputerName 192.168.56.103 -Port 1514` | Test if port 1514 is reachable on the Wazuh server |
| `Test-NetConnection -ComputerName 192.168.56.103 -Port 1515` | Test if port 1515 is reachable on the Wazuh server |
| `netsh advfirewall set allprofiles state off` | Temporarily disable Windows Firewall for testing |
| `ping 192.168.56.103` | Basic connectivity test to the Ubuntu VM |

---

## Terminal Tips

| Command | Purpose |
|---|---|
| `Ctrl + C` (Linux) | Kill a running process |
| `Ctrl + Shift + C` (Linux) | Copy selected text in Linux terminal |
| `Ctrl + Shift + V` (Linux) | Paste text into Linux terminal |
| `Shift + Page Up` (Linux) | Scroll up through terminal output |
| `\| less` | Pipe command output to a scrollable viewer (q to quit) |
| `command \| tee output.log` | Show command output on screen AND save to a file |
| `2>/dev/null` | Suppress error messages from a command's output |
| `sudo !!` | Re-run the previous command with sudo |

---

## VirtualBox Lab Setup Commands

*Commands used to configure the virtual machine environment before installing Wazuh.*

### Linux — Network Configuration

| Command | Purpose |
|---|---|
| `ip a` | Confirm Host-Only adapter got an IP after VM boot |
| `sudo nano /etc/netplan/00-installer-config.yaml` | Assign a static IP to the Host-Only adapter (enp0s8) |
| `sudo netplan apply` | Apply the network config change without rebooting |
| `ping 192.168.56.102` | Test connectivity from Ubuntu to the Windows 10 VM |

### Linux — Disk & System Prep

| Command | Purpose |
|---|---|
| `df -h` | Confirm available disk space before installing Wazuh |
| `sudo apt update && sudo apt upgrade -y` | Update all packages to latest versions before install |
| `sudo apt clean` | Free up cached apt package files |
| `sudo rm -rf /var/cache/apt/archives/*` | Delete downloaded package archives to recover space |

### Windows — VM Connectivity Check (PowerShell)

| Command | Purpose |
|---|---|
| `ipconfig` | Confirm the Host-Only adapter has a 192.168.56.x IP assigned |
| `ping 192.168.56.103` | Verify Windows VM can reach the Ubuntu Wazuh server |
| `ssh vboxuser@192.168.56.103` | SSH into the Ubuntu VM from Windows to run server-side commands |

---

## Wazuh & Sysmon Setup Commands

*Commands used to install and configure the Wazuh agent on the Windows endpoint, deploy Sysmon, and connect the agent to the Wazuh server.*

### Windows — Wazuh Agent Setup (PowerShell as Admin)

| Command | Purpose |
|---|---|
| `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent.msi -OutFile wazuh-agent.msi` | Download the Wazuh agent installer |
| `msiexec /i wazuh-agent.msi /q WAZUH_MANAGER='192.168.56.103'` | Silently install the agent and point it at the Wazuh server IP |
| `Get-Service -Name WazuhSvc` | Check if the Wazuh agent service is installed and running |
| `Restart-Service -Name WazuhSvc` | Restart the agent — required after any ossec.conf changes |
| `notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"` | Open the agent config in Notepad to add or edit localfile blocks |
| `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" \| Select-String "Sysmon"` | Verify the Sysmon localfile block is present in the config |
| `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20` | View the last 20 lines of the agent log for diagnostics |

### Windows — Sysmon Setup (PowerShell as Admin)

| Command | Purpose |
|---|---|
| `Get-Service -Name Sysmon64` | Check if Sysmon is installed and running |
| `Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip` | Download Sysmon from Microsoft Sysinternals |
| `Expand-Archive Sysmon.zip` | Extract the Sysmon zip file |
| `.\Sysmon64.exe -accepteula -i sysmonconfig.xml` | Install Sysmon with a config file — SwiftOnSecurity config recommended |

### ossec.conf — Sysmon Localfile Block

Add this block to `C:\Program Files (x86)\ossec-agent\ossec.conf` before the closing `</ossec_config>` tag, then restart the WazuhSvc service:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## Detection Testing Commands

*Commands run on the Windows 10 VM to generate test events and validate each Wazuh dashboard detection.*

### Dashboard 1 — Failed Logon Attempts (PowerShell)

| Command | Purpose |
|---|---|
| `1..7 \| ForEach-Object { net use \\localhost\IPC$ /user:fakeuser wrongpassword }` | Loop 7 failed logon attempts — triggers Wazuh rule 60122 (Event ID 4625) |
| `net use * /delete /yes` | Clean up any lingering net use sessions after testing |

### Dashboard 2 — Account Creation (PowerShell as Admin)

| Command | Purpose |
|---|---|
| `net user labtest Password123! /add` | Create a new local user account — triggers Event ID 4720 |
| `net localgroup administrators labtest /add` | Add the account to Administrators group — triggers Event ID 4732 |
| `net user labtest2 Password123! /add` | Create a second test account to generate more events |
| `net user labtest /delete` | Remove the test account after lab is complete |
| `net user labtest2 /delete` | Remove the second test account after lab is complete |

### Dashboard 3 — Suspicious Process Activity (PowerShell)

| Command | Purpose |
|---|---|
| `Start-Process cmd.exe` | Launch cmd.exe from PowerShell — triggers Sysmon Event ID 1 |
| `Start-Process powershell.exe` | Launch a child PowerShell process — triggers Sysmon Event ID 1 |
| `Start-Process cmd.exe; Start-Process cmd.exe; Start-Process cmd.exe` | Run cmd.exe three times in sequence to generate multiple events |
| `Get-Service -Name Sysmon64` | Verify Sysmon is running before generating test events |

### Wazuh Discover — Validation Queries (DQL Search Bar)

| Query | Purpose |
|---|---|
| `sysmon` | Confirm Sysmon data is flowing to Wazuh after ossec.conf fix |
| `cmd.exe` | Search for any events referencing cmd.exe |
| `labtest` | Find events related to the test accounts created during Dashboard 2 testing |
| `data.win.eventdata.image:*cmd.exe* OR data.win.eventdata.image:*powershell*` | Filter process creation events — used as the DQL query for Dashboard 3 panels |
