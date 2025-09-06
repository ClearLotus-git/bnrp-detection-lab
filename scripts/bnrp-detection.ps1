# BNRP Detection Script 
# Detects spoofed LLMNR/NBT-NS responses and logs to CSV

[CmdletBinding()]
param(
  [string]  $LogFile      = "C:\logs\bnrp-detection.csv",
  [string[]]$RequestHosts = @("CORP-TX-FILE-01","COPY-NY-DC-02"),
  [int]     $Interval     = 30,
  [int]     $Jitter       = 30,
  [switch]  $Once
)

# Ensure log directory exists
$dir = Split-Path -Parent $LogFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

Write-Host "[*] BNRP Detection Script started..." -ForegroundColor Cyan
Write-Host "[*] LogFile: $LogFile" -ForegroundColor DarkCyan

function Is-ValidIp {
  param([string]$Ip)
  if ($Ip -eq "127.0.0.1" -or $Ip -eq "::1") { return $false }  # ignore loopback
  return $true
}

function Invoke-BnrpIteration {
  try {
    $ErrorActionPreference = 'stop'
    $request = Get-Random $RequestHosts

    $resolved = Resolve-DnsName -LlmnrNetbiosOnly -Name $request -ErrorAction SilentlyContinue
    if ($resolved) {
      $ipAddr = $resolved.IPAddress.ToString()
      if (Is-ValidIp $ipAddr) {
        $line = "LLMNR/NBT-NS spoofing by $ipAddr detected with $request request"
        Write-Output $line
        [pscustomobject]@{
          date        = Get-Date -Format o
          host        = $env:COMPUTERNAME
          request     = $request
          attacker_ip = $ipAddr
          message     = $line
        } | Export-Csv -Path $LogFile -Append -NoTypeInformation -Encoding UTF8
      }
    }
  } catch {
    # keep quiet in production; uncomment to troubleshoot:
    # Write-Warning $_
  } finally {
    $ErrorActionPreference = 'continue'
  }
}

# One-shot or loop
if ($Once) { Invoke-BnrpIteration; return }

while ($true) {
  Start-Sleep -Seconds ($Interval + (Get-Random ($Jitter + 1)))
  Invoke-BnrpIteration
}
