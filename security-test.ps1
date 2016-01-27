#   Windows testing script. version is based mostly around CIS benchmarks
#   Developed initially for Windows 2k8 Server and Powershell v2
#   Initially we're only farming reg key values
#   ian.tibble@education.gsi.gov.uk
#   January 2016

#$ErrorActionPreference= 'silentlycontinue'

"computer name" 
$env:computername
 
"Windows OS Version"
(Get-CimInstance Win32_OperatingSystem).version

"<h2>IP addresses</h2>"
Get-NetIPAddress 
 
"<h2>Powershell Version</h2>"
$PSVersionTable

"<h2>Shares</h2>"
Get-WmiObject Win32_Share 

# Services Check

function Test-RegistryValue($regkey, $name) {
    $exists = Get-ItemProperty -Path "$regkey" -Name "$name" -ErrorAction SilentlyContinue
    If (($exists -ne $null) -and ($exists.Length -ne 0)) {
        Return $true
    }
    Return $false
}

function services_check
{
    $a = Get-Content services.txt 
    $lines = Get-Content -Path services.txt  | Measure-Object

    $prefilter_lines = $lines.Count

    $service_start_key_value_exists = $true

    ""
    ""
    "AUTO-LOADED SERVICES (start key value = 2):"
    ""
<#    foreach ($service in $a){
        if ( Test-Path $service ){

            if ((Get-ItemProperty -Path $service -Name Start).Start -Match 2)
            {
                $filtered_lines++
                $service 
                ""
            }
            #Get-ItemProperty $service -Name Start
        }
    }#>

    function Test-RegistryValue($regkey, $name) {
        $exists = Get-ItemProperty -Path "$regkey" -Name "$name" -ErrorAction SilentlyContinue
        If (($exists -ne $null) -and ($exists.Length -ne 0)) {
            Return $true
        }
        Return $false
    }



    foreach ($service in $a){

        if ( Test-Path $service ){

            try {
                $exists = Get-ItemProperty -Path $service 'start' -ErrorAction Stop
            }
            catch {
                " *** $service registry key exists but no 'start' value is configured"
                $service_start_key_value_exists = $false
            }

            $startvalue = Get-ItemProperty -Path $service | Select-Object -ExpandProperty 'Start'

            if ($service_start_key_value_exists -and $startvalue.Length -eq 0){
                "$service registry key exists, 'start' value configured, but is zero length"
            }

            if ($startvalue -eq 2){
                $filtered_lines++
                $service 
            }
        }
        $service_start_key_value_exists = $true
        
    }
    "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    "$filtered_lines of $prefilter_lines services were found Auto-loaded"
}

function security_options_check
{
    $b = Get-Content security-options-regkeys.txt
    $lines = Get-Content -Path security-options-regkeys.txt | Measure-Object

    <#$b | foreach {
    $Address,$Strings = $_.split('#').trim()
    Foreach ($String in $Strings.split(';'))
     {"$Address,$String" }
    }#>
    ""

    $key_not_found = @()
    $unset_keys = @()

    foreach ($line in $b){
        $value,$key = $line.split(':').trim()
        "Registry key: $value"
        "key: $key"


        if (Test-Path "hklm:$value"){
            $keyvalue = (Get-ItemProperty "hklm:$value" | Select-Object $key).$key
            "Detected key value: $keyvalue"
            if ($keyvalue -eq $null){
                $unset_keys += "${value}: $key"
                }
        }
        else
        {
            "Registry item not found"
            $key_not_found += $value
            ""
        }
        ""
    }

    "<h3>Keys not found<h3>"

    $total_sec_options_keys = $lines.Count
    $total_keys_not_found = $key_not_found.Count
    $total_unset_keys = $unset_keys.Count

    "Out of a total of $total_sec_options_keys security-options registry keys, $total_keys_not_found were not found"

    foreach ($item in $key_not_found){

        $item

    }
    ""
    "Out of a total of $total_sec_options_keys security-options registry keys, $total_unset_keys were found unset"

    foreach ($item in $unset_keys){
        $item
    }
}

"<h2>Services</h2>"
if ( Test-Path services.txt )
{
    services_check
}
else 
{ 
    "Skipping services check; services.txt file not found"
}

"<h2>Security Options</h2>"
if ( Test-Path security-options-regkeys.txt )
{
    security_options_check
}
else
{
    "Skipping security-options check; security-options-regkeys.txt not found"
}