#   Windows testing script. version is based mostly around CIS benchmarks
#   Developed initially for Windows 2k8 Server and Powershell v2
#   Initially we're only farming reg key values
#   ian.tibble@education.gsi.gov.uk
#   January 2016

#$ErrorActionPreference= 'silentlycontinue'

"<h3>Computer Name</h3>" 
"<p>$env:computername</p>"


"<h3>Windows OS Version</h3>"
$os_ver = (Get-CimInstance Win32_OperatingSystem).version
"<p>$os_ver</p>"

"<h3>IP addresses</h3>"
$netipaddress = Get-NetIPAddress
"<p>$netipaddress</p>"
 
"<h3>Powershell Version</h3>"
$psver = $PSVersionTable
"<p>$psver</p>"

"<h3>Shares</h3>"
$shares = Get-WmiObject Win32_Share
"<p>$shares</p>" 

function Get-Information 
{
    function registry_values($regkey, $regvalue,$child) 
    { 
        if ($child -eq "no"){$key = get-item $regkey} 
        else{$key = get-childitem $regkey} 
        $key | 
        ForEach-Object { 
        $values = Get-ItemProperty $_.PSPath 
        ForEach ($value in $_.Property) 
        { 
        if ($regvalue -eq "all") {$values.$value} 
        elseif ($regvalue -eq "allname"){$value} 
        else {$values.$regvalue;break} 
        }}} 
    $output = "Logged in users:`n" + ((registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") -join "`r`n") 
    $output = $output + "`n`n Powershell environment:`n" + ((registry_values "hklm:\software\microsoft\powershell" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty trusted hosts:`n" + ((registry_values "hkcu:\software\simontatham\putty" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty saved sessions:`n" + ((registry_values "hkcu:\software\simontatham\putty\sessions" "all")  -join "`r`n") 
    $output = $output + "`n`n Recently used commands:`n" + ((registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Shares on the machine:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Environment variables:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n More details for current user:`n" + ((registry_values "hkcu:\Volatile Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings for current user:`n" + ((registry_values "hkcu:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications for current user:`n" + ((registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Domain Name:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Contents of /etc/hosts:`n" + ((get-content -path "C:\windows\System32\drivers\etc\hosts")  -join "`r`n") 
    $output = $output + "`n`n Running Services:`n" + ((net start) -join "`r`n") 
    $output = $output + "`n`n Account Policy:`n" + ((net accounts)  -join "`r`n") 
    $output = $output + "`n`n Local users:`n" + ((net user)  -join "`r`n") 
    $output = $output + "`n`n Local Groups:`n" + ((net localgroup)  -join "`r`n") 
    $output = $output + "`n`n WLAN Info:`n" + ((netsh wlan show all)  -join "`r`n") 
    $output


}



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

    "<p>AUTO-LOADED SERVICES (start key value = 2):</p>"
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
                " *** $service registry key exists but no 'start' value is configured<br>"
                $service_start_key_value_exists = $false
            }

            $startvalue = Get-ItemProperty -Path $service | Select-Object -ExpandProperty 'Start'

            if ($service_start_key_value_exists -and $startvalue.Length -eq 0){
                "$service registry key exists, 'start' value configured, but is zero length<br>"
            }

            if ($startvalue -eq 2){
                $filtered_lines++
                $service + "<br>"
            }
        }
        $service_start_key_value_exists = $true
        
    }
    "<p>$filtered_lines of $prefilter_lines services were found Auto-loaded</p>"
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
            "Detected key value: $keyvalue <br>"
            if ($keyvalue -eq $null){
                $unset_keys += "${value}: $key"
                }
        }
        else
        {
            "Registry item not found <br>"
            $key_not_found += $value
            ""
        }
        ""
    }

    "<h4>Keys not found</h4>"

    $total_sec_options_keys = $lines.Count
    $total_keys_not_found = $key_not_found.Count
    $total_unset_keys = $unset_keys.Count

    "<p>Out of a total of $total_sec_options_keys security-options registry keys, $total_keys_not_found were not found</p>"

    foreach ($item in $key_not_found){

        $item + "<br>"

    }
    ""
    "<p>Out of a total of $total_sec_options_keys security-options registry keys, $total_unset_keys were found unset</p>"

    foreach ($item in $unset_keys){
        $item + "<br>"
    }
}

function event_logging_config_check
{
    $b = Get-Content event-logging.txt
    $lines = Get-Content -Path event-logging.txt | Measure-Object

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
            "Detected key value: $keyvalue<br>"
            if ($keyvalue -eq $null){
                $unset_keys += "${value}: $key"
                }
        }
        else
        {
            "Registry item not found<br>"
            $key_not_found += $value
            ""
        }
        ""
    }

    "<h4>Keys not found</h4>"

    $total_keys = $lines.Count
    $total_keys_not_found = $key_not_found.Count
    $total_unset_keys = $unset_keys.Count

    "<p>Out of a total of $total_keys event logging configuration registry keys, $total_keys_not_found were not found</p>"

    foreach ($item in $key_not_found){

        $item = "<br>"

    }
    ""
    "<p>Out of a total of $total_keys event logging registry keys, $total_unset_keys were found unset</p>"

    foreach ($item in $unset_keys){
        $item + "<br>"
    }
}

function miscellaneous_options_check
{
    $b = Get-Content miscellaneous.txt
    $lines = Get-Content -Path miscellaneous.txt | Measure-Object

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
            "Detected key value: $keyvalue <br>"
            if ($keyvalue -eq $null){
                $unset_keys += "${value}: $key"
                }
        }
        else
        {
            "Registry item not found <br>"
            $key_not_found += $value
            ""
        }
        ""
    }

    "<h4>Keys not found</h4>"

    $total_miscellaneous_keys = $lines.Count
    $total_keys_not_found = $key_not_found.Count
    $total_unset_keys = $unset_keys.Count

    "<p>Out of a total of $total_miscellaneous_keys miscellaneous-options registry keys, $total_keys_not_found were not found</p>"

    foreach ($item in $key_not_found){

        $item + "<br>"

    }
    ""
    "<p>Out of a total of $total_miscellaneous_keys miscellaneous-options registry keys, $total_unset_keys were found unset</p>"

    foreach ($item in $unset_keys){
        $item + "<br>"
    }
}


""
"<h2>General Information Gathering</h2>"
Get-Information


""
"<h2>Services</h2>"

if ( Test-Path services.txt )
{
    services_check
}
else 
{ 
    "<p>Skipping services check; services.txt file not found</p>"
}

""
"<h2>Security Options</h2>"

if ( Test-Path security-options-regkeys.txt )
{
    security_options_check
}
else
{
    "<p>Skipping security-options check; security-options-regkeys.txt not found</p>"
}

""
"<h2>Event Logging Configuration</h2>"

if ( Test-Path event-logging.txt )
{
    event_logging_config_check
}
else
{
    "<p>Skipping event-logging check; event-logging.txt not found</p>"
}

"<h2>Miscellaneous Registry Settings</h2>"

if ( Test-Path miscellaneous.txt )
{
    miscellaneous_options_check
}
else
{
    "<p>Skipping miscellaneous settings check; miscellaneous.txt not found</p>"
}