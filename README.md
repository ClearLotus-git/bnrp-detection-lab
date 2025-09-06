# BNRP Detection Lab
Broadcast Name Resolution Poisoning (LLMNR/NBT-NS) Detection with PowerShell + SIEM Integration.

## Overview
This demonstrates how to detect **LLMNR/NBT-NS spoofing attacks** using a PowerShell trap script. 
It simulates false host requests and logs any spoofed responses (indicative of an attacker using Responder/Inveigh).

-  Detects spoofed LLMNR/NBT-NS responses
-  Logs attacker IP + requested hostname
-  Exports to CSV for ingestion into SIEMs (Splunk/ELK/etc.)

---

I added a `-TestMode` parameter to the script.  

When enabled, this generates **synthetic detections** by producing random `192.168.1.x` IP addresses 
to simulate spoofing responses. This allowed me to validate that the script. Please check the script
template for proper use and edit it accordingly. The example shown in the images has a loopback for the 
test script when using `bnrp-detection-safe-test.ps1` Please edit accordingly. There is an updated one 
with an added filter to skip loopback called `bnrp-detection-noloop-test.ps1` .

##  Example Usage
```powershell
PS C:\> .\bnrp-detection.ps1
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with DC01 request
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with FILSRV01 request
