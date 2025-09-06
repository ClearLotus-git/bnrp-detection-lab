# BNRP Detection Lab
Broadcast Name Resolution Poisoning (LLMNR/NBT-NS) Detection with PowerShell + SIEM Integration.

## Overview
This project demonstrates how to detect **LLMNR/NBT-NS spoofing attacks** using a PowerShell trap script. 
It simulates false host requests and logs any spoofed responses (indicative of an attacker using Responder/Inveigh).

-  Detects spoofed LLMNR/NBT-NS responses
-  Logs attacker IP + requested hostname
-  Exports to CSV for ingestion into SIEMs (Splunk/ELK/etc.)
-  Includes **sample logs** and **screenshots**

---

##  Repository Structure
- `scripts/`  PowerShell detection script
- `scripts/template.ps1`  Example script
-  `scripts/bnrp-detection.ps1` Lab ready
- `sample-logs/` Example poisoning logs (CSV + console output)
- `images/`  Screenshots + diagrams
- `README.md`  Documentation

---

##  Example Usage
```powershell
PS C:\> .\bnrp-detection.ps1
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with DC01 request
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with FILSRV01 request
