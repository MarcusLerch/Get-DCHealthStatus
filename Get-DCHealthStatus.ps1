<#
=============================================================================
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

This sample is not supported under any Microsoft standard support program or
service. The code sample is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without
limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of
the sample and documentation remains with you. In no event shall Microsoft, 
its authors, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss
of business information, or other pecuniary loss) arising out of  the use of
or inability to use the sample or documentation, even if Microsoft has been 
advised of the possibility of such damages.
=============================================================================
#>
#Requires –Version 3

#region Parameter
[cmdletBinding(SupportsShouldProcess=$true)]
param(
    [String]$ConfigFile="config.xml",
    [String]$LogDir
)

#endregion

[String]$ScriptVersion = "2.4.5"

#region Functions
function Log2File{
	param(
			[string]$log,
			[string]$text
	)
	"$(Get-Date -Format "yyyyMMdd-HH:mm:ss"):`t$text" | Out-File -FilePath $log -Append
}

function Check-DNSEntries {
    [CmdletBinding(DefaultParametersetName="LocalCheck")] 
	param(
		[Parameter(ParametersetName="ProvidedList", Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]
		$DNSRecordList,
		[Parameter(ParametersetName="LocalCheck")]
		[Parameter(ParametersetName="RemoteCheck")]
		[Parameter(ParametersetName="ProvidedList")]
        [System.String]
        $DNSServerAdress,
        [Parameter(ParametersetName="ProvidedList", Mandatory=$true)]
        [Parameter(ParametersetName="RemoteCheck", Mandatory=$true)]
        [System.String]
        $SourceServer
	)
    switch ($PSCmdlet.ParameterSetName){
        "LocalCheck" {
            $DNSRecordList = Get-Content $env:SystemRoot\System32\config\netlogon.dns
            $SourceServer=$env:COMPUTERNAME
        }
        "RemoteCheck" {
            $DNSRecordList = Get-Content "\\$SourceServer\admin$\System32\config\netlogon.dns"
        }
    }
    if($DNSServerAdress -eq ""){
        $DNSServerAdress = ((Get-DnsClientServerAddress -AddressFamily IPv4) | Where-Object {$_.ServerAddresses})[0].ServerAddresses[0]
    }
    $ServiceRecordList = @()
	foreach ($DNSEntry in $DNSRecordList){
		$Entry = $DNSEntry -split " "
		$DNSName = $Entry[0]
        $DNSTTL = $Entry[1]
		$DNSType = $Entry[3]
        if ($DNSType -eq "SRV"){
            $SRVPriority = $Entry[4]
            $SRVWeight = $Entry[5]
            $SRVPort = $Entry[6]
        }
        $ServerInQuestion = ($Entry[-1]).TrimEnd(".")
        $ServiceRecord = New-Object System.Object | Select-Object SourceServer,DNSRecord,DNSRecordType,IsRegistered,IsCorrect,DNSServer
        $ServiceRecord.SourceServer = $SourceServer
        $ServiceRecord.DNSRecord = $DNSName
        $ServiceRecord.DNSRecordType = $DNSType
        $ServiceRecord.IsRegistered = $false
        $ServiceRecord.IsCorrect = $false
        $ServiceRecord.DNSServer = $DNSServerAdress
        $nslResults = Resolve-DnsName -Name $DNSName -Type $DNSType -DnsOnly -Server $DNSServerAdress -ErrorAction SilentlyContinue
		switch ($DNSType) {
			
            "SRV" {
                foreach ($nslResult in $nslResults){
                    if ($nslResult.NameTarget -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL -and 
                            $nslResult.Priority -eq $SRVPriority -and 
                            $nslResult.Weight -eq $SRVWeight -and 
                            $nslResult.Port -eq $SRVPort){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
				
			}

			"A" {
				foreach ($nslResult in $nslResults){
                    if ($nslResult.IP4Address -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
			}

			"CNAME" {
				foreach ($nslResult in $nslResults){
                    if ($nslResult.NameHost -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
			}

			Default {
				break
			}
		}
        $ServiceRecordList += $ServiceRecord
	}
    $ServiceRecordList | Sort-Object DNSRecordType, DNSRecord
}

#endregion

#region Initialize
$rundatestring = ("{0:yyyyMMdd}" -f (get-date))
$ScriptPath = $MyInvocation.MyCommand.Path | Split-Path
if($LogDir){
    if(-not (Test-Path $LogDir -PathType Container)){
        $LogDir = $ScriptPath
    }
}
else{
    $LogDir = $ScriptPath
}
$LogFilePath = "$LogDir\$rundatestring"

if (-not (Test-Path $LogFilePath -PathType Container)){ $null = mkdir $LogFilePath -Force }
$LogFile = "$LogFilePath\$rundatestring-RuntimeLog.log"
[String]$Spacer = "=" * 80
[Int]$DCDiagErrSum = 0
$DCDiagErrList = ""
$RepAdminErrList = ""
$SysVolReplErrorList = ""
[Int]$RepAdminErrSum = 0
[Int]$SysVolReplErrorSum = 0
[Int64]$DSASize = 0
[String[]]$UnreachbleDCs = @()
[String]$RepAdminErrHTML = ""
[String]$SysVolReplErrorHTML = ""
[String]$DCDiagErrHTML = ""
Import-Module ActiveDirectory
$RunResult = New-Object System.Object | Select-Object -Property DSASize,RIDsIssued,RunDate
$RunResult.RunDate = Get-Date
if (Test-Path -Path "$LogDir\LastRun.xml"){
    $LastRunResult = Import-Clixml -Path "$LogDir\LastRun.xml"
}
else{
    $LastRunResult = New-Object System.Object | Select-Object -Property DSASize,RIDsIssued,RunDate
}

$HTMLRed = "bgcolor=#FF4000"
$HTMLGreen = "bgcolor=#13D813"
$HTMLYellow = "bgcolor=#F7FE2E"

Log2File -log $LogFile -text $Spacer
Log2File -log $LogFile -text "Starting"
#endregion

#region Read config
if(Test-Path $ConfigFile -PathType Leaf){
    $config = $ConfigFile
}
elseif(Test-Path "$ScriptPath\$ConfigFile" -PathType Leaf){
    $config = "$ScriptPath\$ConfigFile"
}
else{
    Write-Host ("Configuration file {0} not found and config not in script path.`nExiting script" -f $ConfigFile)
    break
}

Log2File -log $LogFile -text "Reading configuration from file $config"
[xml]$configuration = Get-Content $config

$Domain2Check = $configuration.ScriptConfiguration.Domain2Check
Log2File -log $LogFile -text "Domain for reporting"
Log2File -log $LogFile -text "`t - $Domain2Check"

[int]$EventlogCheckDays = $configuration.ScriptConfiguration.EventlogCheckDays
Log2File -log $LogFile -text "Number of days for Eventlog reporting"
Log2File -log $LogFile -text "`t - $EventlogCheckDays"
[String]$EventlogCheckDays = $EventlogCheckDays * -1

$recipients = @()
Log2File -log $LogFile -text "Reading recipients"
foreach ($recipient in $configuration.ScriptConfiguration.MailSettings.recipientlist){
	Log2File -log $LogFile -text "`t - $($recipient.recipient)"
	$recipients += $recipient.recipient
}

[bool][int]$sendMail = $configuration.ScriptConfiguration.MailSettings.SendMail
Log2File -log $LogFile -text "SendMail:"
Log2File -log $LogFile -text "`t - $sendMail"

$smtpserver = $configuration.ScriptConfiguration.MailSettings.'SMTP-Server'
Log2File -log $LogFile -text "SMTP Server to use"
Log2File -log $LogFile -text "`t - $smtpserver"

$Sender = $configuration.ScriptConfiguration.MailSettings.Sender
Log2File -log $LogFile -text "Mail sender"
Log2File -log $LogFile -text "`t - $Sender"

$Subject = $configuration.ScriptConfiguration.MailSettings.Subject
Log2File -log $LogFile -text "Mail subject"
Log2File -log $LogFile -text "`t - $Subject"

$CheckFiles = @()
Log2File -log $LogFile -text "Reading files to check"
foreach ($CheckFile in $configuration.ScriptConfiguration.CheckFile){
	Log2File -log $LogFile -text "`t - $($CheckFile.FullName)"
	$CheckFiles += $CheckFile.FullName
}

[bool][int]$CheckSimpleBindEvents = $configuration.ScriptConfiguration.CheckSimpleBindEvents
Log2File -log $LogFile -text "Read CheckSimpleBindEvents Flag"
Log2File -log $LogFile -text "`t - $CheckSimpleBindEvents"

$CheckServices = @()
Log2File -log $LogFile -text "Reading services to check"
foreach ($ReadService in $configuration.ScriptConfiguration.CheckService.Service){
	Log2File -log $LogFile -text "`t - $($ReadService.ServiceName)"
    $htService = @{'ServiceName'=$ReadService.ServiceName;'StartMode'=$ReadService.StartMode;'State'=$ReadService.State}
	$CheckServices += New-Object PSObject -Property $htService
}

#endregion

#region Check AD and DCs
Log2File -log $LogFile -text "Starting checks"

#region get forest and domain infos
Log2File -log $LogFile -text "Reading Forest and Domain Information"
$ADForest = Get-ADForest -Server $Domain2Check
$ADForestDomains = $ADForest.Domains
$ADInfo = Get-ADDomain -Server $Domain2Check
$ADDomainDNSRoot = $ADInfo.DNSRoot
$ADDomainReadOnlyReplicaDirectoryServers = $ADInfo.ReadOnlyReplicaDirectoryServers
$ADDomainReplicaDirectoryServers = $ADInfo.ReplicaDirectoryServers
#endregion

#region get fsmo role owners
Log2File -log $LogFile -text "Reading FSMO Role Owners"
$ADForestDomainNamingMaster = $ADForest.DomainNamingMaster
$ADForestSchemaMaster = $ADForest.SchemaMaster
$ADDomainPDCEmulator = $ADInfo.PDCEmulator
$ADDomainRIDMaster = $ADInfo.RIDMaster
$ADDomainInfrastructureMaster = $ADInfo.InfrastructureMaster
#endregion

#region Get Rid Object
Log2File -log $LogFile -text "Reading RID Information"
$domainDN = $ADInfo.DistinguishedName
$RIDManager = [ADSI]"LDAP://CN=RID Manager$,CN=System,$domainDN"
$ADSearcher = new-object system.DirectoryServices.DirectorySearcher
$ADSearcher.SearchRoot = $RIDManager
[Void]$ADSearcher.PropertiesToLoad.Add("ridavailablepool")
$RIDAvailablePool= ($ADSearcher.FindOne()).properties.ridavailablepool
[int32]$totalSIDS = $($RIDAvailablePool) / ([math]::Pow(2,32))
[int64]$totalSIDS64val = $totalSIDS * ([math]::Pow(2,32))
[int32]$currentRIDPoolCount = $($RIDAvailablePool) - $totalSIDS64val
$ridsremaining = $totalSIDS - $currentRIDPoolCount
$ridObject = New-Object PSObject -Property @{"RIDsIssued"=$currentRIDPoolCount;"RIDsRemaining"=$ridsremaining;"TotalSIDs"=$totalSIDS}
$RunResult.RIDsIssued = $ridObject.RIDsIssued
#endregion

#region DFSR-HealthCheck
Log2File -log $LogFile -text "Starting DFSRAdmin Healthcheck"
$dfsrAdminHealth = @()
$referenceMember = ("{0}\{1}" -f $ADInfo.NetBIOSName,$ADDomainPDCEmulator.split('.')[0])
$ReportName = "$LogFilePath\$rundatestring-DFSRHealthReport"
$domain = $ADInfo.DNSRoot

$null = DfsrAdmin.exe Health New /RgName:`"Domain System Volume`" /RefMemName:$referenceMember /RepName:$ReportName /FsCount:true /domain:$domain

$reportXML = [XML](Get-Content "$ReportName.xml")
foreach ($DFSRServer in $reportxml.dfsReplicationReport.members.server){
    foreach($node in $DFSRServer.serverErrors.ChildNodes){
            $dfsrAdminError = New-Object System.Object | Select-Object -Property Server,ErrorID,ErrorType
            $dfsrAdminError.Server = $DFSRServer.name
            $dfsrAdminError.ErrorID = $node.id
            $dfsrAdminError.ErrorType = $node.type
            Log2File -log $LogFile -text  ("`t{0} : {1} - {2}" -f $DFSRServer.name, $node.id, $node.type)
            $dfsrAdminHealth += $dfsrAdminError
    }
}

#<serverErrors><error id="11001" type="warning"><timestamp timezone="60"><fileTime>130842754526030000</fileTime><systemTime>Monday, August 17, 2015 10:57:32</systemTime></timestamp><affectedContentSets/><errorReferences><ref refId="11001.1">1EB54844-CF94-11DE-9E1F-806E6F6E6963</ref><ref refId="11001.2">C:</ref></errorReferences></error></serverErrors>
#endregion

#region Create ScriptBlock to run on DCs
Log2File -log $LogFile -text "Creating script block for DC checks"

$TimeToCheck = 86400000
$filterXML = @"
<QueryList>
  <Query Id="0" Path="Directory Service">
    <Select Path="Directory Service">*[System[(EventID=2889) and TimeCreated[timediff(@SystemTime) &lt;= $TimeToCheck]]]</Select>
  </Query>
</QueryList>
"@

$SBText = @'
$DC_HealthInfo = [ordered]@{}
$NTDS_Parameters = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters *
$DC_HealthInfo.Computername = $env:COMPUTERNAME
$DC_HealthInfo.OSDirFreeSpace = (Get-WmiObject -Query "SELECT FreeSpace FROM win32_logicaldisk WHERE DeviceID = 'C:'").FreeSpace
$DC_HealthInfo.DSAWorkingDir = $NTDS_Parameters.'DSA Working Directory'
$DSADrive = ($DC_HealthInfo.DSAWorkingDir -split "\\")[0]
$DC_HealthInfo.DSADirFreeSpace = (Get-WmiObject -Query "SELECT FreeSpace FROM win32_logicaldisk WHERE DeviceID = '$DSADrive'").FreeSpace
$DC_HealthInfo.DSAPath = $NTDS_Parameters.'DSA Database file'
$DC_HealthInfo.DSASize = (Get-Item $NTDS_Parameters.'DSA Database file').Length
$DC_HealthInfo.StrictReplication = [bool][int]$NTDS_Parameters.'Strict Replication Consistency'
$DC_HealthInfo.GCPromoComplete = [bool][int]$NTDS_Parameters.'Global Catalog Promotion Complete'
$DC_HealthInfo.DCDiag = dcdiag /skip:systemlog /skip:DFSREvent
$DC_HealthInfo.DCDiagFailedTests = ($DC_HealthInfo.DCDiag | select-string -Pattern "failed test") | % { $_.ToString().Split(" ")[-1] }
$DC_HealthInfo.RepAdmin = @(repadmin /showrepl /csv | ConvertFrom-Csv | Where-Object {$_.'Number of Failures' -gt 0})
$DC_HealthInfo.DCDiagErr = @($DC_HealthInfo.DCDiag | Select-String -Pattern "failed test").count
$DC_HealthInfo.RepAdminErr = $DC_HealthInfo.RepAdmin.count
$DC_HealthInfo.SysVolReplError = @(Get-Eventlog 'DFS Replication' -After (get-date).AddDays($using:EventlogCheckDays) -EntryType Error -ErrorAction SilentlyContinue | Where-Object {$_.EventID -ne 5002})
$DC_HealthInfo.SysVolReplErrorCount = $DC_HealthInfo.SysVolReplError.Count
$DC_HealthInfo.UnexpectedShutdown = @(Get-Eventlog 'System' -After (get-date).AddDays($using:EventlogCheckDays) -EntryType Error -ErrorAction SilentlyContinue | Where-Object {$_.EventID -eq 6008})
$DC_HealthInfo.UnexpectedShutdownCount = $DC_HealthInfo.UnexpectedShutdown.Count
if($using:CheckSimpleBindEvents){
    $DC_HealthInfo.SimpleBinds = @(Get-WinEvent -FilterXml $using:filterXML | ForEach-Object { $client = $_.properties[0].value; $user = $_.properties[1].value ; New-Object psobject -Property @{Client=$client;User=$user} })
    $DC_HealthInfo.SimpleBindsCount = $DC_HealthInfo.SimpleBinds.Count
}
$FileVersions = @{}
foreach ($FileName in $using:CheckFiles){
    $Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FileName)
    $Version = ("{0}.{1}.{2}.{3}" -f $Version.FileMajorPart,$Version.FileMinorPart,$Version.FileBuildPart,$Version.FilePrivatePart)
    $FileVersions.Add($FileName,$Version)
}
$DC_HealthInfo.CheckedFiles = $FileVersions
$ServicesChecked = @()
foreach ($Service2Check in $using:CheckServices){
    $Service = Get-WmiObject -Query "SELECT Name,State,StartMode FROM win32_service WHERE Name='$($Service2Check.ServiceName)'" | Select-Object -Property Name,State,StartMode
    if (($Service.State -eq $Service2Check.State) -and ($Service.StartMode -eq $Service2Check.StartMode)){
        $ServiceResult = [ordered]@{'Computername'=$env:COMPUTERNAME;'ServiceName'=$Service2Check.ServiceName;'CheckResult'='OK';'StartMode'=$Service.StartMode;'State'=$Service.State}
    }
    else {
        $ServiceResult = [ordered]@{'Computername'=$env:COMPUTERNAME;'ServiceName'=$Service2Check.ServiceName;'CheckResult'='ERROR';'StartMode'=$Service.StartMode;'State'=$Service.State}
    }
    $ServicesChecked += New-Object PSObject -Property $ServiceResult
}
$DC_HealthInfo.CheckedServices = $ServicesChecked
New-Object PSObject -Property $DC_HealthInfo
'@

$SB = [ScriptBlock]::Create($SBText)
#endregion

#region Find reachable DCs
Log2File -log $LogFile -text "Reading DCs and executing script block"
$ALDCList = New-Object System.Collections.ArrayList
$DCList = @(Get-ADDomainController -Filter * -server $Domain2Check| Select-Object -ExpandProperty HostName)
$ALDCList.AddRange($DCList)
Log2File -log $LogFile -text "Found the following Domain Controllers:"
foreach ($DC in $DCList){
    $reachable = Test-Connection -ComputerName $DC -Count 2 -Quiet
    if(!$reachable){
        $UnreachbleDCs += $DC
        $ALDCList.Remove($DC)
    }
	Log2File -log $LogFile -text ("{1,-8}{0}" -f $DC,$reachable)
}
#endregion

#region Run checks on reachable DCs
Log2File -log $LogFile -text "Collecting information from the reachable servers"
$results = @(Invoke-Command -ComputerName $DCList -ScriptBlock $SB)
#endregion

#region DNS Registration Check
Log2File -log $LogFile -text "Starting DNS Registrations Check"
$DNSRegistrationErrors = @()
foreach ($DC in $DCList){
    $DNSRegistrationErrors += Check-DNSEntries -SourceServer $DC -DNSServerAdress '172.30.0.151' | Where-Object {!($_.IsRegistered -and $_.IsCorrect)}
}

#endregion

#region Get time source of PDC
Log2File -log $LogFile -text "Checking time configuration"
$TimeSource = (w32tm /monitor /domain:$Domain2Check | Select-String -Pattern " PDC " -Context 2).Context.PostContext[1].Split(":")[2].Trim()
#endregion

#region Get replication summary

Log2File -log $LogFile -text "Generating replication summary"

repadmin /showrepl * /csv | ConvertFrom-Csv | Export-Csv -Path "$LogFilePath\$rundatestring-ReplicationSummary.csv" -NoTypeInformation -Delimiter ';' -Force

#endregion

Log2File -log $LogFile -text "Finished collecting information"

#region Generate reports from collected information
Log2File -log $LogFile -text "Generating reports"
$CheckedFiles = @()
$CheckedServices = @()
$FailedServices = 0
foreach ($result in $results){
    $DCDiagErrSum += $result.DCDiagErr
    $SysVolReplErrorSum += $result.SysVolReplErrorCount
    $UnexpectedShutdownSum += $result.UnexpectedShutdownCount
    $SimpleBindCount += $result.SimpleBindsCount
    $RepAdminErrSum += $result.RepAdminErr
	if ($result.RepAdminErr){
		$result.RepAdmin | Out-File -FilePath "$LogFilePath\$rundatestring-$($result.Computername)-repadmin.txt" -Force
        $RepAdminErrList += "<li>$($result.Computername)</li>"
	}
	if ($result.DCDiagErr){
		$result.DCDiag | Out-File -FilePath "$LogFilePath\$rundatestring-$($result.Computername)-dcdiag.txt" -Force
        if($result.DCDiagErr){
            $DCDiagErrList += "<li>$($result.Computername)</li>"
               $DCDiagErrList += "<ul>"
               foreach($FailedTest in $result.DCDiagFailedTests){
                    $DCDiagErrList += "<li>$FailedTest</li>"
               }
               $DCDiagErrList += "</ul>"
        }
	}
    if ($result.SysVolReplErrorCount){
        $result.SysVolReplError | Select-Object -Property Index,TimeGenerated,EntryType,Source,Message | Out-File -FilePath "$LogFilePath\$rundatestring-$($result.Computername)-SysVolReplError.txt" -Force
        $SysVolReplErrorList += "<li>$($result.Computername)</li>"
    }
    if ($result.UnexpectedShutdownCount){
        $result.UnexpectedShutdown | Select-Object -Property Index,TimeGenerated,EntryType,Source,Message | Out-File -FilePath "$LogFilePath\$rundatestring-$($result.Computername)-UnexpectedShutdown.txt" -Force
        $UnexpectedShutdownList += "<li>$($result.Computername)</li>"
    }
    if ($result.SimpleBindsCount){
        $result.SimpleBinds |  Export-Csv -Path "$LogFilePath\$rundatestring-$($result.Computername)-SimpleBinds.csv" -NoTypeInformation -Delimiter ';' -Force
    }
    $DSASize += $result.DSASize
    foreach($FileName in $result.CheckedFiles.Keys){
        $FileInfo = New-Object System.Object | Select-Object -Property Computername,FileName,FileVersion
        $FileInfo.Computername = $result.Computername
        $FileInfo.FileName = $FileName
        $FileInfo.FileVersion = $result.CheckedFiles.Item($FileName)
        $CheckedFiles += $FileInfo
    }
    foreach($Service in $result.CheckedServices){
        $ServiceCheckStatus = New-Object System.Object | Select-Object -Property Computername,ServiceName,CheckResult,StartMode,State
        $ServiceCheckStatus.Computername = $Service.Computername
        $ServiceCheckStatus.ServiceName  = $Service.ServiceName 
        $ServiceCheckStatus.CheckResult  = $Service.CheckResult 
        $ServiceCheckStatus.StartMode    = $Service.StartMode   
        $ServiceCheckStatus.State        = $Service.State       
        $CheckedServices += $ServiceCheckStatus
        if ($Service.CheckResult -eq "Error"){$FailedServices++} 
    }
}
[int64]$DSASizeAverage = $DSASize / $results.count
$RunResult.DSASize = $DSASizeAverage

Log2File -log $LogFile -text "Exporting reports"
$results | Select-Object -Property * -ExcludeProperty DCDiag,RepAdmin,PSComputerName,RunspaceId,PSShowComputerName,CheckedFiles | Export-Csv -Path "$LogFilePath\$rundatestring-DCHealth.csv" -NoTypeInformation -Delimiter ";" -Force
$CheckedFiles | Export-Csv -Path "$LogFilePath\$rundatestring-FileVersionCheck.csv" -NoTypeInformation -Delimiter ';' -Force
$dfsrAdminHealth | Export-Csv -Path "$LogFilePath\$rundatestring-DFSRAdminHealthCheckErrors.csv" -NoTypeInformation -Delimiter ';' -Force
$CheckedServices | Export-Csv -Path "$LogFilePath\$rundatestring-ServiceCheck.csv" -NoTypeInformation -Delimiter ';' -Force
$DNSRegistrationErrors | Export-Csv -Path "$LogFilePath\$rundatestring-DNSRegistrationErrors.csv" -NoTypeInformation -Delimiter ';' -Force
#endregion
#endregion

#region Creating and sending mail
$UnreachableList = ""
if ($UnreachbleDCs){
    $UnreachableList = "<p>Nicht erreichbare DomainController:<br><ul>"
    foreach ($OfflineDC in $UnreachbleDCs){
        $UnreachableList += ("<li>{0}</li>" -f $OfflineDC)
    }
}
$UnreachableList += "</ul></p>"

$DFSRErrorList = ''
if ($dfsrAdminHealth){
    $DFSRErrorList = "<p>DSFRAdmin Health Check Errors:<br><ul>"
    foreach ($DFSRError in $dfsrAdminHealth){
        $DFSRErrorList += ("<li>{0} : {1} - {2} </li>" -f $DFSRError.Server,$DFSRError.ErrorID,$DFSRError.ErrorType)
    }
}
$DFSRErrorList += "</ul></p>"

if ($RepAdminErrSum){
    $RepAdminErrHTML = ("<p>Liste der Server mit RepAdmin Fehlern:<br><ul>{0}</ul></p>" -f $RepAdminErrList)
}

if ($SysVolReplErrorSum){
    $SysVolReplErrorHTML = ("<p>Liste der Server mit SysVol Replikationsfehlern:<br><ul>{0}</ul></p>" -f $SysVolReplErrorList)
}

if ($UnexpectedShutdownSum){
    $UnexpectedShutdownHTML = ("<p>Liste der Server mit SysVol Replikationsfehlern:<br><ul>{0}</ul></p>" -f $UnexpectedShutdownList)
}

if ($DCDiagErrSum){
    $DCDiagErrHTML = ("<p>Liste der Server mit DCDiag Fehlern:<br><ul>{0}</ul></p>" -f $DCDiagErrList)
}

$DCDNSErrHTML = ''
if ($DNSRegistrationErrors){
    $DCDNSErrHTML = ("<p>Es wurden {0} fehlerhafte DNS Registrierungen gefunden</p>" -f $DNSRegistrationErrors.Count)
}

Log2File -log $LogFile -text "Creating mail"
[string]$MailBody = Get-Content -Path "$Scriptpath\MailBody.html"

$MailBody = $MailBody.Replace("___ADDOMAIN___",$domainDN)
$MailBody = $MailBody.Replace("___DSASIZE___",$DSASizeAverage)
$MailBody = $MailBody.Replace("___DSAGROWTH___",($RunResult.DSASize - $LastRunResult.DSASize))
$MailBody = $MailBody.Replace("___PDCE___",$ADInfo.PDCEmulator)
$MailBody = $MailBody.Replace("___RID___",$ADInfo.RIDMaster)
$MailBody = $MailBody.Replace("___INFRA___",$ADInfo.InfrastructureMaster)
$MailBody = $MailBody.Replace("___SCHEMA___",$ADForestSchemaMaster)
$MailBody = $MailBody.Replace("___DOMAINNAMING___",$ADForestDomainNamingMaster)
$MailBody = $MailBody.Replace("___TIMESOURCE___",$TimeSource)
$MailBody = $MailBody.Replace("___RIDSISSUED___",$ridObject.RIDsIssued)
$MailBody = $MailBody.Replace("___RIDSISSUEDDIFF___",($RunResult.RIDsIssued - $LastRunResult.RIDsIssued))
$MailBody = $MailBody.Replace("___RIDSREMAINING___",$ridObject.RIDsRemaining)
$MailBody = $MailBody.Replace("___DCDIAGERR___",$DCDiagErrSum)
$MailBody = $MailBody.Replace("___SYSVOLREPLERR___",$SysVolReplErrorSum)
$MailBody = $MailBody.Replace("___UXSCOUNT___",$UnexpectedShutdownSum)
$MailBody = $MailBody.Replace("___REPADMINERR___",$RepAdminErrSum)
$MailBody = $MailBody.Replace("___REPADMINLIST___",$RepAdminErrHTML)
$MailBody = $MailBody.Replace("___DCDIAGLIST___",$DCDiagErrHTML)
$MailBody = $MailBody.Replace("___UNREACHABLEDC___",$UnreachbleDCs.count)
$MailBody = $MailBody.Replace("___UNREACHABLELIST___",$UnreachableList)
$MailBody = $MailBody.Replace("___SCRIPTNAME___",$MyInvocation.MyCommand.Path)
$MailBody = $MailBody.Replace("___SCRIPTVERSION___",$ScriptVersion)
$MailBody = $MailBody.Replace("___SERVERNAME___",$env:COMPUTERNAME)
$MailBody = $MailBody.Replace("___SYSVOLREPLERRLIST___",$SysVolReplErrorHTML)
$MailBody = $MailBody.Replace("___UNEXPECTEDSHUTDOWNLIST___",$UnexpectedShutdownHTML)
$MailBody = $MailBody.Replace("___DFSRERR___",$dfsrAdminHealth.Count)
$MailBody = $MailBody.Replace("___DFSRERRLIST___",$DFSRErrorList)
$MailBody = $MailBody.Replace("___ADDSERR___",$FailedServices)
$MailBody = $MailBody.Replace("___DNSERR___",$DCDNSErrHTML)
if($CheckSimpleBindEvents){
$MailBody = $MailBody.Replace("___LSBCOUNT___",$SimpleBindCount)
switch ($SimpleBindCount){
    {$_ -gt 100} {$MailBody = $MailBody.Replace("___LSBCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___LSBCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___LSBCOLOR___",$HTMLGreen)}
}
}
else{
$MailBody = $MailBody.Replace("___LSBCOUNT___","Not checked")
$MailBody = $MailBody.Replace("___LSBCOLOR___",$HTMLGreen)
}
switch ($UnreachbleDCs.count){
    {$_ -gt 4} {$MailBody = $MailBody.Replace("___URCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___URCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___URCOLOR___",$HTMLGreen)}
}
switch ($SysVolReplErrorSum){
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___SVCOLOR___",$HTMLRed); break}
    default {$MailBody = $MailBody.Replace("___SVCOLOR___",$HTMLGreen)}
}
switch ($UnexpectedShutdownSum){
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___UXSCOLOR___",$HTMLRed); break}
    default {$MailBody = $MailBody.Replace("___UXSCOLOR___",$HTMLGreen)}
}
switch ($RepAdminErrSum){
    {$_ -gt 4} {$MailBody = $MailBody.Replace("___RACOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___RACOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___RACOLOR___",$HTMLGreen)}
}
switch ($DCDiagErrSum){
    {$_ -gt 4} {$MailBody = $MailBody.Replace("___DDCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___DDCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___DDCOLOR___",$HTMLGreen)}
}
switch ($RunResult.DSASize - $LastRunResult.DSASize){
    {$_ -gt ($LastRunResult.DSASize * 0.1)} {$MailBody = $MailBody.Replace("___DSACOLOR___",$HTMLRed); break}
    {$_ -gt ($LastRunResult.DSASize * 0.05)} {$MailBody = $MailBody.Replace("___DSACOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___DSACOLOR___",$HTMLGreen)}
}
switch ($RunResult.RIDsIssued - $LastRunResult.RIDsIssued){
    {$_ -gt ($LastRunResult.RIDsIssued * 0.1)} {$MailBody = $MailBody.Replace("___RIDCOLOR___",$HTMLRed); break}
    {$_ -gt ($LastRunResult.RIDsIssued * 0.05)} {$MailBody = $MailBody.Replace("___RIDCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___RIDCOLOR___",$HTMLGreen)}
}
switch ($dfsrAdminHealth.Count){
    {$_ -gt 4} {$MailBody = $MailBody.Replace("___DFSRCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___DFSRCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___DFSRCOLOR___",$HTMLGreen)}
}
switch ($FailedServices){
    {$_ -gt 4} {$MailBody = $MailBody.Replace("___ADDSCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___ADDSCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___ADDSCOLOR___",$HTMLGreen)}
}

$Attachements = Get-ChildItem -Path $LogFilePath | ForEach-Object {$_.FullName}
if($sendMail){
Log2File -log $LogFile -text "Sending mail"
Send-MailMessage -BodyAsHtml -Body $MailBody `
            -Attachments $Attachements `
            -To $recipients `
            -From $Sender `
            -SmtpServer $smtpserver `
            -Subject $Subject 
}
$MailBody | Out-File -FilePath "$LogFilePath\SentMail.html" 
#endregion

#region Store run results and finish
Log2File -log $LogFile -text "Exporting LastRunObject"

$RunResult | Export-Clixml -Path "$LogDir\LastRun.xml" -Force

Log2File -log $LogFile -text "Ended"
Log2File -log $LogFile -text $Spacer
#endregion