# BNRP Detection Lab
Broadcast Name Resolution Poisoning (LLMNR/NBT-NS) Detection with PowerShell + SIEM Integration.

## Overview
This demonstrates how to detect **LLMNR/NBT-NS spoofing attacks** using a PowerShell trap script. 
It simulates false host requests and logs any spoofed responses (indicative of an attacker using Responder/Inveigh).

-  Detects spoofed LLMNR/NBT-NS responses
-  Logs attacker IP + requested hostname
-  Exports to CSV for ingestion into SIEMs (Splunk/ELK/etc.)

## What is Broadcast Name Resolution Poisoning?

Broadcast Name Resolution Poisoning (BNRP) is a **man-in-the-middle technique** where an attacker abuses legacy Windows name resolution protocols — **LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)**.  

When a host on the local network broadcasts a request like *“Who has FILESERVER?”*, the attacker quickly responds with *“I do”*. This tricks the victim into sending authentication attempts (such as NTLM hashes) to the attacker’s machine.  

These captured credentials can then be:
- **Cracked offline** to reveal plaintext passwords  
- **Relayed** to other systems for lateral movement or privilege escalation  

### Why this matters
LLMNR and NBT-NS are still enabled by default in many Windows environments, which makes this attack straightforward and effective. Detecting and disabling these protocols is an important defensive step for securing enterprise networks.  


---
## Testing Purpose

I added a `-TestMode` parameter to the the test script:  

When enabled, this generates **synthetic detections** by producing random `192.168.1.x` IP addresses 
to simulate spoofing responses. This allowed me to validate that the script. Please check the script
template for proper use and edit it accordingly. The example shown in the images has a loopback for the 
test script when using `bnrp-detection-safe-test.ps1` Please edit accordingly. There is an updated test 
with an added filter to skip loopback called `bnrp-detection-noloop-test.ps1` . The final script is 
`bnrp-detection.ps1`

##  Example Usage
```powershell
PS C:\> .\bnrp-detection.ps1
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with DC01 request
LLMNR/NBT-NS spoofing by 192.168.38.105 detected with FILSRV01 request
