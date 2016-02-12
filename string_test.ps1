$CurrentIPs = @(); 
 
get-wmiobject win32_networkadapterconfiguration | ? { $_.IPAddress -ne $null } | Sort-Object IPAddress -Unique | % { 
   $CurrentIPs+=$_.IPAddress 
} 
 
$CurrentIPs