# BNRP Detection Script (Final Version)
# Detects spoofed LLMNR/NBT-NS responses and logs to CSV

$logfile = "C:\logs\bnrp-detection.csv"
$requestHosts = @("CORP-TX-FILE-01","COPY-NY-DC-02")
$interval = 30
$jitter = 30

while ($true) {
    Start-Sleep ($interval + (Get-Random ($jitter + 1)))
    try {
        $ErrorActionPreference = "stop"
        $request = Get-Random $requestHosts
        $ipAddr = (Resolve-DnsName -LlmnrNetbiosOnly -Name $request).IPAddress.ToString()
        $event = [pscustomobject]@{
            date        = Get-Date -Format o
            host        = $env:COMPUTERNAME
            request     = $request
            attacker_ip = $ipAddr
            message     = "Spoofing detected: $ipAddr responded to $request"
        }
        Write-Output $event.message
        $event | Export-Csv -Path $logfile -Append -NoTypeInformation
    }
    catch { } 
    finally { $ErrorActionPreference = "continue" }
}
