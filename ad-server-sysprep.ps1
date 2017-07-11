#
# Copyright 2016 Schlumberger, unpublished work. All rights reserved. 
#

$ErrorActionPreference = "Stop"

Function Decrypt($project, $encryptedString)
{
	$keyRing = 'vm-service'
	$keyName = 'admin'
	$headers = @{"Authorization"="Bearer $(gcloud auth application-default print-access-token)"}
	$body = "{`"ciphertext`": `"$encryptedString`"}"
	$response = Invoke-RestMethod -Method Post -Headers $headers -Uri "https://cloudkms.googleapis.com/v1/projects/$project/locations/global/keyRings/$keyRing/cryptoKeys/${keyName}:decrypt" -Body $body -ContentType 'application/json'
	return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($response.plaintext))
}

Function CheckTimestamp($timestamp) {
  $d = Get-Date $timestamp
  $now = (Get-Date).AddMinutes(-3)
  if ($now -gt $d) { throw "Command timestamp has expired" }
}

#  TODO: remove once commercial
Function Set-RuntimeConfig($project, $config, $variable, $value) {
   $headers = @{"Authorization"="Bearer $(gcloud auth application-default print-access-token)"}
   $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($value))
   $body = "{`"name`": `"projects/$project/configs/$config/variables/$variable`", `"value`": `"$base64`"}"
   Invoke-RestMethod -Method Post -Headers $headers -Uri "https://runtimeconfig.googleapis.com/v1beta1/projects/$project/configs/$config/variables?alt=json" -Body $body -ContentType 'application/json'
}

Function Set-ACLDomainJoinAccessRule($user) {
    $IdentityReference = [System.Security.Principal.NTAccount] $user
    $DistinguishedName = 'CN=$user,CN=Users,DC=sis-ad,DC=sis,DC=com'

    $SD = Get-Acl "AD:\$DistinguishedName"

    # Validated write to DNS host name
    $SD.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $IdentityReference,
        'Self',  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
        'Allow', # ACE type ([System.Security.AccessControl.AccessControlType])
        '72e39547-7b18-11d1-adef-00c04fd8d5cd',  # GUID for 'Validated write to DNS host name'
        'Descendents',  # ACE will only apply to child objects ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
        'bf967a86-0de6-11d0-a285-00aa003049e2'  # Inherited object type (in this case in can apply to computers)
    )))

    # Validated write to service principal name
    $SD.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $IdentityReference,
        'Self',  # Access mask
        'Allow',
        'f3a64788-5306-11d1-a9c5-0000f80367c1',  # GUID for 'Validated write to service principal name'
        'Descendents',
        'bf967a86-0de6-11d0-a285-00aa003049e2'
    )))

    # Write Account Restrictions
    $SD.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $IdentityReference,
        'ReadProperty, WriteProperty',  # Access mask
        'Allow',
        '4c164200-20c0-11d0-a768-00aa006e0529',  # GUID for 'Account Restrictions' PropertySet
        'Descendents',
        'bf967a86-0de6-11d0-a285-00aa003049e2'
    )))

    # Reset password
    $SD.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $IdentityReference,
        'ExtendedRight',  # Access mask
        'Allow', 
        '00299570-246d-11d0-a768-00aa006e0529',  # GUID for 'Reset Password' extended right
        'Descendents',
        'bf967a86-0de6-11d0-a285-00aa003049e2'
    )))

    # Create and Delete computer objects
    $SD.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $IdentityReference,
        'CreateChild, DeleteChild',  # Access mask
        'Allow', 
        'bf967a86-0de6-11d0-a285-00aa003049e2',  # GUID for 'Computer' object
        'All',         # Object and ChildObjects
        [guid]::Empty  # Don't restrict objects this can apply to (You could restrict it to OUs)
    )))

    $SD | Set-Acl
}

Function Get-StorageFiles([string] $path) {
  try {
     return gsutil ls $path 2>$null
  }
  catch { }
}

Function Install-Package([Parameter(Mandatory=$true)][string]$name, [Parameter(Mandatory=$true)][string]$version, [switch]$WhatIf) {
    Write-Host "Resolving '${name}': '$version'"
    $folders = $Global:packagePath | ForEach-Object { Get-StorageFiles "$_/$name/$version/install.ps1" } | Split-Path -Parent 
    $version = $folders | Split-Path -Leaf | Sort -Descending | Select-Object -First 1
    if (!$version) {
        throw "Can't resolve $name"
    }
    $packageSource = ($folders | Where-Object { $_.EndsWith("\$version") } | Select-Object -First 1) -Replace "\\", "/"
    $packageDir = "$global:downloadDir\$name\$version"
    if (Test-Path $packageDir) {
        Remove-Item -Path $packageDir -Recurse -Force
    }

    Write-Host "Downloading $packageSource/*"
    MkDir -Force $packageDir | Out-Null
    gsutil -q cp -r "$packageSource/*" $packageDir 
    
    if (!$WhatIf) {
        cd $packageDir | Out-Null
        Write-Host "Installing '${name}': '$version'"
        & .\install.ps1
        cd \
        Remove-Item -Path $packageDir -Recurse -Force
    }
}

Function ADServer($project) {

    (Get-Process -Id $pid).priorityclass = "Realtime"

    # open port 3001
    New-NetFirewallRule -DisplayName "ADService" `
        -Direction Inbound `
        -Enabled True `
        -Action Allow `
        -Protocol TCP -LocalPort 3001

    $key = Decrypt -project $project -encryptedString $projectMeta.PowershellKey | ForEach-Object { $_ -split "(?<=\G\w{2})(?=\w{2})" } | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://*:3001/a5025bfb-0e58-47da-b779-e41ecf9f1f94/")
    $listener.Start()
    Write-Host "Listening..."
	  [char[]]$buffer = new-object char[] 4096
    try {
       $calls = 0
       while ($listener.IsListening) {
          $statusCode = 200
		      $command = "debug"
          try {
            $context = $listener.GetContext()
            $reader = New-Object System.IO.StreamReader -ArgumentList $context.Request.InputStream
            $command = $reader.ReadToEnd() | ConvertTo-SecureString -Key $key
            #$count = $reader.Read($buffer, 0, $buffer.Length)
            #$command = New-Object System.String($buffer,0,$count) | ConvertTo-SecureString -Key $key
            $helperCredential = New-Object System.Management.Automation.PsCredential("user", $command)
            $command = $helperCredential.GetNetworkCredential().Password

            #Write-Host "Command:`r`n $command"
            $script = $ExecutionContext.InvokeCommand.NewScriptBlock($command)                        
            $commandOutput = & $script
			      #Write-Host "Result Raw:`r`n $commandOutput"
			      $commandOutput = $commandOutput | ConvertTo-Json
			      #Write-Host "Result Json:`r`n $commandOutput"
            if ($calls++ % 100 -eq 0) {
               Write-Host "Processed $calls commands"
               Write-Host "VM READY"
            }
          } catch {
            $commandOutput = $_.ToString()
            $statusCode = 500
          }
          try {
            if (!$commandOutput) {
               $encryptedResult  = [string]::Empty
            }
            else {
               $encryptedResult = $commandOutput | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString -Key $key
            }
            $response = $context.Response
            $response.StatusCode = $statusCode
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($encryptedResult)

            $response.ContentLength64 = $buffer.Length
            $output = $response.OutputStream
            $output.Write($buffer,0,$buffer.Length)
            $output.Close()
            #Write-Host "Finished request $(get-date)" 
          } catch {
            Write-Host $_
            Start-Sleep -m 10
          }
       }
    }
    finally {
      Write-Host "Listening stopped"
      $listener.Stop()
    }
}


try {
    Write-Host "Starting AD controller ..."
    $meta = Invoke-RestMethod -Uri http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true -Headers @{'Metadata-Flavor' = 'Google' }
    $projectMeta = Invoke-RestMethod -Uri http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true -Headers @{'Metadata-Flavor' = 'Google' }
    $project = Invoke-RestMethod -Uri http://metadata.google.internal/computeMetadata/v1/project/project-id -Headers @{'Metadata-Flavor' = 'Google' }
    $Global:packagePath = $projectMeta.PackagePath.Split(";")
    $Global:downloadDir = "$env:Temp\Downloads"
    $domain = $projectMeta.Domain
    $domainAdmin = $projectMeta.DomainAdmin
    $domainAdminPassword = Decrypt -project $project -encryptedString $projectMeta.DomainAdminPassword | ConvertTo-SecureString -AsPlainText -Force 
    $adminForestPassword = $domainAdminPassword
    $serviceAdminCredential = New-Object System.Management.Automation.PsCredential("$domain\$domainAdmin", $domainAdminPassword)

    if ((Get-CimInstance Win32_ComputerSystem).Domain -ne $domain) {
    
	      Write-Host "Installing AD services for $env:COMPUTERNAME"
	      
        # need to make password meeting AD server requirements
        net user Administrator (New-Guid).Guid 

	      Import-Module ServerManager
		
	      Add-WindowsFeature RSAT-AD-PowerShell, DNS, AD-Domain-Services -IncludeManagementTools

	      Import-Module ADDSDeployment
	
        $domain -match "([^.]+)"
        $netBiosName = $Matches[1]

	      Install-ADDSForest `
              -CreateDnsDelegation:$false `
              -DatabasePath "C:\Windows\NTDS" `
              -DomainMode "Win2012R2" `
              -ForestMode "Win2012R2" `
              -InstallDns:$true `
              -SysvolPath "C:\Windows\SYSVOL" `
		          -DomainName $domain `
		          -SafeModeAdministratorPassword $adminForestPassword `
              -DomainNetbiosName $netBiosName `
		          -Force

        # Enable time synchronization for the domain controller.
        # Compute Engine metadata server as source
        w32tm /config /manualpeerlist:"metadata.google.internal" /syncfromflags:manual /reliable:yes /update
    } 
    else {
        # wait for AD service to be ready
        ForEach ($number in 1..1000) {
            try {
                Start-Sleep -s 10
                Get-ADUser -Filter { SamAccountName -eq $domainAdmin }
                break;
            }
            catch { 
                Write-Host $_
                Write-Host "Waiting for AD service"
            }
        }
    
        if (!(Get-ADUser -Filter { SamAccountName -eq $domainAdmin })) {

	          $gpoTempDir = "$env:TEMP\GPOs"
	          Write-Host "Importing GPOs $gpoTempDir"

	          New-Item $gpoTempDir -ItemType directory -Force
	          $bucket = $meta."windows-startup-script-url" | Split-Path -parent
              $bucket = $bucket -Replace "\\","/"
	          gsutil cp -r "$bucket/ad-server-group-policies.zip" $env:TEMP

            Add-Type -assembly "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory("$env:TEMP\ad-server-group-policies.zip", $gpoTempDir)
            $targetDomain = (($domain.Split('.') | ForEach-Object { "DC=$_," }) -join "").Trim(',')
            $cloudDcGpo = "SIS Cloud DC GPO"
            $workstationGpo = "SIS Cloud Workstation GPO"
            $cloudSecurityGpo = "SIS Cloud Security GPO"
            $vmserviceGpo = "VM Service GPO"
            $sisExtended3hGpo = "SIS Extended Timeout Users 3h GPO"
            $sisExtended2dGpo = "SIS Extended Timeout Users 2d GPO"
            $sisExtended3hGroup = "VM Extended Timeout Users 3h"
            $sisExtended2dGroup = "VM Extended Timeout Users 2d"
	    
            Import-GPO -BackupGpoName $cloudDcGpo -TargetName $cloudDcGpo -CreateIfNeeded -Path $gpoTempDir
            Import-GPO -BackupGpoName $workstationGpo -TargetName $workstationGpo -CreateIfNeeded -Path $gpoTempDir
            Import-GPO -BackupGpoName $cloudSecurityGpo -TargetName $cloudSecurityGpo -CreateIfNeeded -Path $gpoTempDir
            Import-GPO -BackupGpoName $vmserviceGpo -TargetName $vmserviceGpo -CreateIfNeeded -Path $gpoTempDir
            Import-GPO -BackupGpoName $sisExtended3hGpo -TargetName $sisExtended3hGpo -CreateIfNeeded -Path $gpoTempDir
            Import-GPO -BackupGpoName $sisExtended2dGpo -TargetName $sisExtended2dGpo -CreateIfNeeded -Path $gpoTempDir
	
            New-GPLink -Name $cloudDcGpo -Domain $domain -Target $targetDomain
            New-GPLink -Name $workstationGpo -Domain $domain -Target $targetDomain
            New-GPLink -Name $cloudSecurityGpo -Domain $domain -Target $targetDomain
            New-GPLink -Name $vmserviceGpo -Domain $domain -Target $targetDomain
            New-GPLink -Name $sisExtended3hGpo -Domain $domain -Target $targetDomain
            New-GPLink -Name $sisExtended2dGpo -Domain $domain -Target $targetDomain
            
            New-ADGroup -Name $sisExtended3hGroup -GroupScope DomainLocal
            New-ADGroup -Name $sisExtended2dGroup -GroupScope DomainLocal

            Set-GPPermission -Name $workstationGpo -TargetType Group -PermissionLevel GpoRead -TargetName "Domain Computers"
            Set-GPPermission -Name $cloudSecurityGpo -TargetType Group -PermissionLevel GpoRead -TargetName "Authenticated Users" -Replace
            Set-GPPermission -Name $vmserviceGpo -TargetType Group -PermissionLevel GpoRead -TargetName "Domain Computers"
            Set-GPPermission -Name $sisExtended3hGpo -TargetType Group -PermissionLevel GpoApply -TargetName $sisExtended3hGroup
            Set-GPPermission -Name $sisExtended3hGpo -TargetType Group -PermissionLevel GpoRead -TargetName "Authenticated Users" -Replace
            Set-GPPermission -Name $sisExtended2dGpo -TargetType Group -PermissionLevel GpoApply -TargetName $sisExtended2dGroup 
            Set-GPPermission -Name $sisExtended2dGpo -TargetType Group -PermissionLevel GpoRead -TargetName "Authenticated Users" -Replace
	
            &cmd.exe /c rd /s /q $gpoTempDir 

            Write-Host "Adding admin user"
	
            New-ADUser 	-Name $domainAdmin `
                        -DisplayName $domainAdmin `
				                -GivenName "" `
				                -SamAccountName $domainAdmin `
				                -UserPrincipalName "$domainAdmin@$domain" `
                        -PasswordNeverExpires $true `
				                -AccountPassword $domainAdminPassword `
				                -Enabled $true
				
	          Add-ADGroupMember "Domain Admins" $domainAdmin
            $studioAdminPassword = Decrypt -project $project -encryptedString $projectMeta.StudioAdminPassword | ConvertTo-SecureString -AsPlainText -Force 

            New-ADUser 	-Name StudioAdmin `
                        -DisplayName StudioAdmin `
				                -GivenName "" `
				                -SamAccountName StudioAdmin `
				                -UserPrincipalName "StudioAdmin@$domain" `
                        -PasswordNeverExpires $true `
				                -AccountPassword $studioAdminPassword `
				                -Enabled $true

            New-ADGroup -Name "VM Users" -GroupScope DomainLocal
            New-ADGroup -Name "VM Admins" -GroupScope DomainLocal
            New-ADGroup -Name "DB Admins" -GroupScope DomainLocal

            New-ADOrganizationalUnit Cirrus –Path "$targetDomain"
            New-ADOrganizationalUnit Desktops –Path "OU=Cirrus,$targetDomain"
            New-ADOrganizationalUnit Groups –Path "OU=Cirrus,$targetDomain"
            New-ADOrganizationalUnit Servers –Path "OU=Cirrus,$targetDomain"
            New-ADOrganizationalUnit Users –Path "OU=Cirrus,$targetDomain"

            # disable Administrator account
            net user Administrator /active:no
            
            Write-Host "Installing Stack Driver"
            # Install Stack Driver
            Install-Package -name 'stackdriver-agent' -version '4.1'
            Install-Package -name 'stackdriver-logging' -version '1.7'
            #Install Office 2016 KMS
            Install-Package -name microsoft-office-kms -version 2016.1.0

            Set-RuntimeConfig $project ad-server-startup-config success/ad-server success
            #gcloud runtime-config configs variables set success/ad-server success --config-name ad-server-startup-config
                     
         }

         Write-Host "VM READY"
         ADServer($project)
    }
} catch {
    Write-Host $_.Exception
    Set-RuntimeConfig $project ad-server-startup-config failure/ad-server failure
    #gcloud runtime-config configs variables set failure/ad-server failure --config-name ad-server-startup-config
}

