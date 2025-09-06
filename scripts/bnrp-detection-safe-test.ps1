# BNRP Detection Script (Final + Demo Friendly)
# Detects spoofed LLMNR/NBT-NS responses and logs to CSV
# -TestMode prints synthetic detections (useful on home machine)
# -Once runs a single iteration (good for screenshots)

[CmdletBinding()]
param(
  [string]$LogFile = "C:\logs\bnrp-detection.csv",
  [string[]]$RequestHosts = @("CORP-TX-FILE-01","COPY-NY-DC-02"),
  [int]$Interval = 30,
  [int]$Jitter = 30,
  [switch]$TestMode,
  [switch]$Once
)

# ensure log directory exists
$dir = Split-Path -Parent $LogFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

Write-Host "[*] BNRP Detection Script started..." -ForegroundColor Cyan
Write-Host "[*] LogFile: $LogFile" -ForegroundColor DarkCyan
Write-Host "[*] TestMode: $($TestMode.IsPresent)" -ForegroundColor DarkCyan

function New-FakeIp { "192.168.1.$(Get-Random -Min 10 -Max 240)" }

do {
  Start-Sleep -Seconds ($Interval + (Get-Random ($Jitter + 1)))
  try {
    $ErrorActionPreference = "stop"
    $request = Get-Random $RequestHosts

    if ($TestMode) {
      $ipAddr = New-FakeIp
    } else {
      $ipAddr = (Resolve-DnsName -LlmnrNetbiosOnly -Name $request).IPAddress.ToString()
    }

    $event = [pscustomobject]@{
      date        = Get-Date -Format o
      host        = $env:COMPUTERNAME
      request     = $request
      attacker_ip = $ipAddr
      message     = "LLMNR/NBT-NS spoofing by $ipAddr detected with $request request"
    }

    Write-Output $event.message
    $event | Export-Csv -Path $LogFile -Append -NoTypeInformation -Encoding UTF8
  }
  catch {
    # silent in non-test environments; uncomment next line to debug:
    # Write-Warning $_
  }
  finally { $ErrorActionPreference = "continue" }
} while (-not $Once)
