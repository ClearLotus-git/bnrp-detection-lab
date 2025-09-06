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

function Is-ValidIp {
    param([string]$Ip)
    # filter out loopback and local addresses
    if ($Ip -eq "127.0.0.1" -or $Ip -eq "::1") { return $false }
    if ($Ip -like "192.168.*" -or $Ip -like "10.*" -or $Ip -like "172.16.*") { return $true }
    return $false
}

do {
  Start-Sleep -Seconds ($Interval + (Get-Random ($Jitter + 1)))
  try {
    $ErrorActionPreference = "stop"
    $request = Get-Random $RequestHosts

    if ($TestMode) {
      $ipAddr = New-FakeIp
    } else {
      $resolved = Resolve-DnsName -LlmnrNetbiosOnly -Name $request -ErrorAction SilentlyContinue
      if ($resolved) {
        $ipAddr = $resolved.IPAddress.ToString()
      }
    }

    if ($ipAddr -and (Is-ValidIp $ipAddr)) {
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

  }
  catch {
    # silent in non-test environments; uncomment next line to debug:
    # Write-Warning $_
  }
  finally { $ErrorActionPreference = "continue" }
} while (-not $Once)
