# BNRP Detection Lab
Broadcast Name Resolution Poisoning (LLMNR/NBT-NS) Detection with PowerShell + SIEM Integration.

## Overview
This demonstrates how to detect **LLMNR/NBT-NS spoofing attacks** using a PowerShell trap script. 
It simulates false host requests and logs any spoofed responses (indicative of an attacker using Responder/Inveigh).

-  Detects spoofed LLMNR/NBT-NS responses
-  Logs attacker IP + requested hostname
-  Exports to CSV for ingestion into SIEMs (Splunk/ELK/etc.)
-  Includes **sample logs** and **screenshots**

---

##  Example Usage
```powershell
PS C:\> .\bnrp-detection.ps1
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with DC01 request
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with FILSRV01 request
