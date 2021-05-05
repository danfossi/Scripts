Write-Host "   Centralized Client Update"
Write-Host "================================"
#Global Counter
$GlobalStartTime=Get-Date

#Function(s)
Function WOL{
	Param ($Mac)
	$MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_"}
	[Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray  * 16)
	$UdpClient = New-Object System.Net.Sockets.UdpClient
	$UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
	$UdpClient.Send($MagicPacket,$MagicPacket.Length)
	$UdpClient.Close()
}

Function Send-PopupMessage {
#originally from http://poshcode.org/5085
[cmdletbinding(DefaultParameterSetName="Time")]    

Param (
[Parameter(
Position=0,
Mandatory,
HelpMessage="Enter the text of your message",
ValueFromPipeline,
ValueFromPipelineByPropertyName
)]
[ValidateNotNullorEmpty()]
[string]$Message,

[Parameter(ValueFromPipelineByPropertyName)]
[ValidateNotNullorEmpty()]
[string]$Username = "*",

[Parameter( ValueFromPipelineByPropertyName )]
[ValidateNotNullorEmpty()]
[Alias("CN")]
[string[]]$Computername = $env:computername,

[Parameter(ParameterSetName="Time")]
[int32]$TimeOut,
[Parameter(ParameterSetName="Wait")]
[switch]$Wait

)

Begin {
    Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"
} #Begin

Process {

    #Don't send a message to * on a remote computer with -Wait.
    if ($Wait -AND ($Username -eq "*") -AND ($Computername -notmatch "$($env:computername)|localhost|127.0.0.1")) {
        Write-Warning "You should specify a username when using -Wait on a remote computer."
        #Bail out
        Return
    }
    #display PSBoundparameters formatted nicely for Verbose output  
    [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
    Write-Verbose "[PROCESS] PSBoundparameters: `n$($pb.split("`n").Foreach({"$("`t"*4)$_"}) | Out-String) `n" 

    if ($Message.Length -gt 262) {
        Write-Verbose "[PROCESS] The message is too long ($($message.length)). Truncating."
        $Message = $Message.Substring(0,262)
    }        

    foreach ($Computer in $Computername) {
        #create the MSG.exe command
        Write-Verbose "[PROCESS] Creating a message for $Username on $Computer"
        $cmd = "msg.exe $Username /SERVER:$Computer "

        if ($Timeout -gt 0) {
            $cmd+="/time:$timeout "
        }
        elseif ($Wait) {
            $cmd+="/W "
        }

        #add the message
        $cmd+=$Message

        #redirect errors
        $errFile = "$($env:temp)\msg.err"
        $cmd+=" 2>$errFile"
        Write-Verbose "[PROCESS] Command: $cmd"

        #turn the command into a scriptblock
        $sb = [scriptblock]::Create($cmd)

        #execute it
        Invoke-Command -ScriptBlock $sb

        #test if there is an error file that has something in it
        if ( (Test-Path $errFile) -AND ((Get-Item -Path $errFile).Length -gt 0)) {
            Write-Warning "[$Computer] $($error[0].Exception.Message)"
        }

        #remove err file which may only be a 0 byte file
        Write-Verbose "[PROCESS] Removing $errFile"
        Remove-Item -Path $errFile
    } #foreach
} #Process

End {
    Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
} 

}
#Define an optional alias
Set-Alias -Name spm -Value Send-PopUpMessage

## Script Start ##
#Import Active Directory Modules
ipmo ActiveDirectory

##Select OUs
$OUs="OU=Workstations,DC=contoso,DC=com", "OU=Notebooks,DC=contoso,DC=com"

$computers = $Ous | foreach { Get-ADComputer -Filter {enabled -eq $true} -SearchBase $_} | Select Name

$Script = {
	#Machine Counter
	$MachineStartTime=Get-Date
	#Requires -RunAsAdministrator

	#Check architecture
	if ([Environment]::Is64BitOperatingSystem -ne "True") {
		Write-Host "Sorry the RuckZuck package provider for OneGet is only available for 64-bit OS!"
		Write-Host ""
	exit 1
	}

	#Managed software (Software List: https://ruckzuck.tools/Home/Repository)
	$ManagedSW = @("7-Zip", "Adobe Acrobat Reader DC", "AIMP", "Filezilla", "InfraRecorder", "Firefox ESR", 
				   "Notepad++", "PuTTY", "TeamViewer", "TightVNC", "VLC", "WinSCP", "Open-Shell")
	

	#Installed packages
	$InstalledSW = Get-Package | select name

	#Check packages provider and install them (if required)
	## OneGet
	if(!('NuGet' -in (get-packageprovider).Name)){
		write-host "* Setup package provider NuGet"
		try{
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue;
			}
		catch{
			Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
			Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue;
			}
	}
	## RuckZuck
	if(!('RuckZuck' -in (get-packageprovider).Name)){
		write-host "* Installazione package provider RuckZuck"
		#Temp dir
		if (!(Test-Path -LiteralPath "C:\temp")) {
			mkdir "C:\temp"
		}
			#Download RuckZuck
			try{
				Invoke-WebRequest -Uri "https://github.com/rzander/ruckzuck/releases/download/1.7.2.1/RuckZuck.provider.for.OneGet_x64.msi" -outfile "C:\temp\RuckZuck.msi"
			}
			catch {
				Write-Error -Message  " $_" -ErrorAction Stop
			}

		#Download RuckZuck form a network share
		#Copy-Item -Path "\\path\to\ruckzuck\RuckZuck.provider.for.OneGet_x64.msi" -Destination "C:\temp\RuckZuck.msi"
		
		#Setup
		if (Test-Path -path "C:\temp\RuckZuck.msi"){
			try{
				& msiexec /i "C:\temp\RuckZuck.msi" /log "C:\ruckzuck-log.txt" /quiet
				#Restart script and load RuckZuck
				sleep -s 5			
				$powershell = [System.Diagnostics.Process]::GetCurrentProcess()
				$psi = New-Object System.Diagnostics.ProcessStartInfo $powerShell.Path
				$psi.Arguments = '-file ' + $script:MyInvocation.MyCommand.Path
				$psi.Verb = "runas"
				[System.Diagnostics.Process]::Start($psi) | Out-Null
				[Environment]::Exit(0)
			}
			catch{
				Write-Error -Message  " $_" -ErrorAction Stop
			}
		}
	}

	#Find updates
	$updates = Find-Package -ProviderName RuckZuck -Updates | Select-Object PackageFilename

	#Install missing software
	$ManagedSW | ForEach-Object {
		if (!($InstalledSW -like "*$_*")) {
			Write-Host "* Installing package: $_"
			Install-Package -ProviderName RuckZuck "$($_)"
		}
	}

	#Update managed software
	$ManagedSW | ForEach-Object { 
		if ($updates.PackageFilename -contains $_) { 
		Write-Host "* Updating package: $_"
		Install-Package -ProviderName RuckZuck "$($_)"
		}
	}

	#Pulizia
	if (Test-Path "C:\temp") {
		Remove-Item -Recurse -Force "C:\temp"
	}
	
	#Set reboot (5min)
	shutdown -f -r -t 300
	
	# Stats
	$MachineEndTime=Get-Date
	$MachineExecution=New-TimeSpan -Start $MachineStartTime -End $MachineEndTime
	Write-Host "* Machine Execution Time: $MachineExecution"
	Write-Host ""
}


# Massive WOL
$macs=gc -Path "\\192.168.1.100\Public\Mac_Addr.txt"
foreach ($mac in $macs){
	WOL $mac
}

# RuckZuck Update
foreach ($computer in $computers) {
	if ((Test-Connection $computer.name -Quiet) -eq "True") {
		Write-Host "Running update on:" $computer.name
		Invoke-Command -ComputerName $computer.name -Script $Script -Verbose
		Send-PopupMessage "Your workstation has just been updated, you need to restart it before continuing with your work." -username "*" -computername $computer.name -timeout 300
		}
	else{
		Write-Host $computer.name "is down!"
		Write-Host ""
	}
}
Write-Host "======================================"
# Stats
$GlobalEndTime=Get-Date
$GlobalExecution=New-TimeSpan -Start $GlobalStartTime -End $GlobalEndTime
Write-Host "Global Execution Time: $GlobalExecution"
Write-Host ""
pause
