function Write-Log {
    param (
        [Parameter(Mandatory=$false)]$Sev,
        [Parameter(Mandatory=$false)]$Line,
        [Parameter(Mandatory=$true)][array]$Msg
    )
    if ($null -eq $Line) {
        Write-Host ' ' 
        Write-Host  $Msg -ForegroundColor White
        Write-Host '------------------------------------------------------------------' -ForegroundColor White
        ' ' >> $filePath
        $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - ' + $Msg >> $filePath
        '------------------------------------------------------------------' >> $filePath
    }
    else {
        if ($Sev -eq 1) { 
            Write-Host 'INFO : [' $Line ']' $Msg -ForegroundColor White
            $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - INFO [' + $Line + '] ' + $Msg >> $filePath
        }
        if ($Sev -eq 2) { 
            Write-Host 'WARN : [' $Line ']' $Msg -ForegroundColor Yellow
            $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - WARN [' + $Line + '] ' + $Msg >> $filePath
        }
        if ($Sev -eq 3) { 
            Write-Host 'ERROR: [' $Line ']' $Msg -ForegroundColor Red
            $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - ERROR [' + $Line + '] ' + $Msg >> $filePath
        }
    }
}

############################################################################################################
# Log message formattng function
############################################################################################################
function Get-ScriptLineNumber { return $MyInvocation.ScriptLineNumber }
new-item alias:__LINE__ -value Get-ScriptLineNumber

Clear-Host
Write-Log -Msg "Start processing PowerShell script"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Sample informational message"
Write-Log -Sev 2 -Line $(__LINE__) -Msg "Sample warning message"
Write-Log -Sev 3 -Line $(__LINE__) -Msg "Sample error message"

$filePath = './difenda-mdrProvisioning-' + $company + "-" + $(Get-Date -Format "dddd-MM-dd-yyyy") + '.log'
$paramsFilePath = './mdrProvisioningParams.json'

try {
    $parametersFile = Get-Content -Raw -Path $paramsFilePath -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    if ($ErrorMessage -like '*because it does not exist*') {
        Write-Host
        Write-Log -Sev 1 -Line (__LINE__) -Msg "This is the first time executing the script."
        Write-Log -Msg 'Please provide the following information.'
    }
    else {}
}

If ($parametersFile) {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The script has been previously executed and the values provided will be used."
    $paramsObject = ConvertFrom-Json -InputObject $parametersFile
    $parameterCount = $paramsObject.PSObject.Properties.value.Count
}
else {
    $paramsObject = New-Object -TypeName PSObject
}


############################################################################################################
# Obtaining Company name
############################################################################################################
$confirmationCompany = $null
$company = $null
While ($company -eq $null) {
    if ($parameterCount -gt 0) {
        try { $company = $( $paramsObject | Select-Object -ExpandProperty "CustomerName" -ErrorAction Stop ) }
        catch {
            $ErrorMessage = $_.Exception.Message
        }
    }
    Write-Host
    while($confirmationCompany -ne "y") {
        if ($company) { 
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Provided company name : $company" 
            while ($confirmationCompany -ne 'y' -and $confirmationCompany -ne 'n') {
                $confirmationCompany = Read-Host "Are you sure you want to use $company as the Company name [Y/N] "
            }
            if ($confirmationCompany -eq 'n') { 
                $company = $null
                $confirmationCompany = $null
            }
        }
        else {
            while($confirmationCompany -ne "y") {
                while ($company.length -lt 3) {
                    $company = Read-Host 'Enter the Customer name used in Difenda Services (3 or more alphanumeric characters) '
                }
                while ($confirmationCompany -ne 'y' -and $confirmationCompany -ne 'n') {
                    $confirmationCompany = Read-Host "Are you sure you want to use $company as the Company name [Y/N] "
                }
                if ($confirmationCompany -eq 'y') {
                    Write-Log -Sev 1 -Line (__LINE__) -Msg "Provided company name : $company"
                }
                else {
                    $confirmationCompany = $null
                    $company = $null
                }
            }
        }
    }
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{CustomerName = $company}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining Azure subscription information
############################################################################################################
$subscriptionId = $null
$confirmationSubs = $null
$compareValue = 0
while ($confirmationSubs -ne 'y') {
    while ($subscriptionId -eq $null) {
        if ($parameterCount -gt $compareValue) {
            try { $subscriptionId = $( $paramsObject | Select-Object -ExpandProperty "SubscriptionId" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($subscriptionId.length -ne 36) {
                $subscriptionId = Read-Host 'Enter the Subscription ID where the Sentinel resources are deployed '
                if ($subscriptionId -match '^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$') {}
                else {
                    Write-Log -Sev 2 -Line $(__LINE__) -Msg "Invalid Subscription ID format."
                    $subscriptionId = $null
                }
            }
        }
        while ($confirmationSubs -ne 'y' -and $confirmationSubs -ne 'n') {
            $confirmationSubs = Read-Host "Please confirm $subscriptionId is the correct Subscription ID [Y/N] "
        }
        if ($confirmationSubs -eq 'y') {
            try { $subscriptionInfo = Get-AzSubscription -SubscriptionId $subscriptionId -ErrorAction Stop }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Sev 2 -Line (__LINE__) -Msg "There was a problem obtaining Subscription information."
                Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
                $confirmationSubs = $null
                $subscriptionId = $null
            }
            if ($subscriptionInfo) {
                Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:", $subscriptionInfo.Name, "(ID:", $subscriptionInfo.Id, ") - Status:", $subscriptionInfo.State
            }
        }
        else {
            $confirmationSubs = $null
            $subscriptionId = $null
            $compareValue = 100
        }
    }
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{SubscriptionId = $subscriptionInfo.Id}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining and validating Sentinel Resource group information
#
# Resource group names only allow up to 90 characters and 
# can only include alphanumeric, underscore, parentheses, hyphen, period (except at end), 
# and Unicode characters that match the allowed characters
# 
############################################################################################################
$rgSentinel = $null
$confirmationrgSentinel = $null
$compareValue = 0
while($confirmationrgSentinel -ne "y") {
    while ($rgSentinel -eq $null) {
        if ($parameterCount -gt $compareValue) {
            try { $rgSentinel = $( $paramsObject | Select-Object -ExpandProperty "SentinelRgName" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($rgSentinel.length -lt 4 -or $rgSentinel.length -gt 89) {
                $rgSentinel = Read-Host 'Enter the name of the Resource group where Microsoft Sentinel is installed '
            }
        }
        while ($rgSentinel -and $confirmationrgSentinel -ne 'y' -and $confirmationrgSentinel -ne 'n') {
            $confirmationrgSentinel = Read-Host "Please confirm $rgSentinel is the correct Sentinel Resource group name [Y/N] "
        }
        if ($confirmationrgSentinel -eq 'y') {
            try { $rgSentinelInfo = Get-AzResourceGroup -Name $rgSentinel -ErrorAction Stop }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem obtaining Sentinel Resource group information."
                Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
                $confirmationrgSentinel = $null
                $rgSentinel = $null
                $compareValue = 100
            }
        }
        if ($rgSentinelInfo) {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Resource group $rgSentinel found in the", $rgSentinelInfo.Location, "region."
            $rgSentinelState = '(Resource group exists: True)'
        }
        else {
            $confirmationrgSentinel = $null
            $rgSentinel = $null
            $compareValue = 100
        }
    }
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{SentinelRgName = $rgSentinelInfo.ResourceGroupName}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining Integration Resource group information
#
# Resource group names only allow up to 90 characters and 
# can only include alphanumeric, underscore, parentheses, hyphen, period (except at end), 
# and Unicode characters that match the allowed characters
# 
############################################################################################################
$rgIntegration = $null
$confirmationrgIntegration = $null
$compareValue = 0
while($confirmationRgIntegration -ne "y") {
    while ($rgIntegration -eq $null) {
        if ($parameterCount -gt $compareValue) {
            try { $rgIntegration = $( $paramsObject | Select-Object -ExpandProperty "IntegrationRgName" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($rgIntegration.length -lt 4 -or $rgIntegration.length -gt 89) {
                $rgIntegration = Read-Host 'Enter the name of the Integration Resource group to be created '
            }
        }
        while ($rgIntegration -and $confirmationrgIntegration -ne 'y' -and $confirmationrgIntegration -ne 'n') {
            $confirmationrgIntegration = Read-Host "Please confirm $rgIntegration is the correct Integration Resource group name [Y/N] "
        }
        if ($confirmationrgIntegration -eq 'y') {
            try { $rgIntegrationInfo = Get-AzResourceGroup -Name $rgIntegration -ErrorAction Stop }
            catch {
                $ErrorMessage = $_.Exception.Message
                if ($ErrorMessage -like '*Provided resource group does not exist*') {
                    $integrationRgExists = $false
                }
                else {
                    Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating Integration resource group name."
                    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage 
                } 
            }
            if ($rgIntegrationInfo) {
                $integrationRgExists = $true
                $confirmationrgIntegration = $null
                while ($confirmationrgIntegration -ne 'y' -and $confirmationrgIntegration -ne 'n') {
                    $confirmationRgIntegration = Read-Host "A Resource group with the same name was found in the tenant. Do you want to use this resource group? [Y/N] "
                }
                if ($confirmationrgIntegration -eq 'n') {
                    $confirmationrgIntegration = $null
                    $rgIntegration = $null
                    $compareValue = 100
                }
                else {
                    Write-Log -Sev 1 -Line (__LINE__) -Msg "Resource group $rgIntegration found in the", $rgIntegrationInfo.Location, "region."
                }
            }
        }
        else {
            $confirmationrgIntegration = $null
            $rgIntegration = $null
            $compareValue = 100
        }
    }
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{IntegrationRgName = $rgIntegration}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining Triage Service principal information
############################################################################################################
$triage = $null
$confirmationTriage = $null
$triageSpExists = $false
$compareValue = 0
while($confirmationTriage -ne 'y') {
    while ($triage -eq $null) {
        if ($parameterCount -gt $compareValue) {
            try { $triage = $( $paramsObject | Select-Object -ExpandProperty "TriageServicePrincipal" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
                $compareValue = 100
            }
        }
        else {
            $triage = Read-Host 'Enter a name for the Triage Service principal to be created '
        }
    }
    while ($triage -and $confirmationTriage -ne 'y' -and $confirmationTriage -ne 'n') {
        $confirmationTriage = Read-Host "Please confirm you want to use $triage as the name for the Triage Service principal [Y/N] "
    }
    if ($confirmationTriage -eq 'y') {
        try { $triageSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $triage } }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the Triage Service principal."
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        }
        if ($triageSpInfo) {
            $confirmationTriage = $null
            $triageSpExists = $true
            while ($triage -and $confirmationTriage -ne 'y' -and $confirmationTriage -ne 'n') {
                $confirmationTriage = Read-Host "A Service principal with the same name has been found in the tenant. Do you want to use this Service principal? [Y/N] "
            }
            if ($confirmationTriage -eq 'y') {
                $triageSpInfoObject = $confirmationTriage
                Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal", $triageSpInfo.DisplayName, "( App ID:", $triageSpInfo.AppId, ")"
            }
            else {
                $confirmationTriage = $null
                $triage = $null
                $compareValue = 100
            }
        }
        else {
            $triageSpExists = $false
        }
    }
    else {
        $confirmationTriage = $null
        $triage = $null
        $compareValue = 100
    }
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{TriageServicePrincipal = $triage}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining AVM information
############################################################################################################
# $confirmationAvmSp = $null
# $confirmationAvm = $null
# $avm = $null
# $compareValue = $true
# $isavm = $false
# try { $isavm = $( $paramsObject | Select-Object -ExpandProperty "IsAvmSubscriber" -ErrorAction Stop ) }
# catch {
#     $ErrorMessage = $_.Exception.Message
# }
# if ($isavm) {
#     Write-Host "$company is AVM Subscriber."
#     $isavm = $true
#     $confirmationAvm = 'y'
# }
# else {
#     while ($confirmationAvm -ne 'y' -and $confirmationAvm -ne 'n') {
#         $confirmationAvm = Read-Host "Is $company subscribed to Difenda's AVM Service? [Y/N] "
#     }
#     if ($confirmationAvm -eq 'y') { $isavm = $true }
#     else { $isavm = $false }  
# }
# while ($confirmationAvm -eq 'y') {
#     if ($compareValue) {
#         try { $avm = $( $paramsObject | Select-Object -ExpandProperty "AvmServicePrincipal" -ErrorAction Stop ) }
#         catch {
#             $ErrorMessage = $_.Exception.Message
#         }
#         if ($avm) {
#             Write-Host "AVM Service principal name $avm provided during a previous execution."
#         }
#         else { 
#             $avm = Read-Host 'Enter the name of the existing AVM Service principal ' 
#             $compareValue = $false
#         }
#     }
#     $confirmationAvm = $true
#     while ($confirmationAvm) {
#         while ($confirmationAvmSp -ne 'y' -and $confirmationAvmSp -ne 'n') {
#             $confirmationAvmSp = Read-Host "Please confirm $avm is the correct AVM Service principal name [Y/N] "
#         }
#         if ($confirmationAvmSp -eq 'y') {
#             try { $avmSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $avm } }
#             catch {
#                 $ErrorMessage = $_.Exception.Message
#                 Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal $avm was not found in tenant."
#                 $avm = Read-Host 'Enter the name of the existing AVM Service principal '
#             }
#             if ($avmSpInfo) {
#                 Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal", $avmSpInfo.DisplayName, "( App ID:", $avmSpInfo.AppId, ")"
#                 $confirmationAvm = $false
#                 $confirmationAvmSp = 'n'
#             }
#         }
#     }
# }
# Write-Host

# $paramsObject | Add-Member -NotePropertyMembers $(@{IsAvmSubscriber = $isavm}) -Force
# $paramsObject | Add-Member -NotePropertyMembers $(@{AvmServicePrincipal = $avm}) -Force
# $paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining DevOps Service principal information
############################################################################################################
$confirmationDevOpsSp = $null
$devOps = $null
while ($confirmationDevOpsSp -ne 'y') {

    try { $devOps = $( $paramsObject | Select-Object -ExpandProperty "DevOpsServicePrincipal" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }

    if ($devOps) {}
    else {
        while ($devOps.length -lt 4) {
            $devOps = Read-Host 'Enter a name of the existing DevOps Service principal '
        }
    }


    while ($confirmationDevOpsSp -eq $null) {

        $confirmationDevOpsSp = Read-Host "Please confirm $devOps is the correct DevOps Servince principal in this tenant [Y/N] "
        if ($confirmationDevOpsSp -eq 'y') {
            try { $devOpsSpInfo = Get-AzADServicePrincipal -SearchString $devOps }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the DevOps Service principal."
                Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            }
            if ($devOpsSpInfo) {}
            else {
                Write-Log -Sev 2 -Line (__LINE__) -Msg "A Service principal with the name provided was not found in the tenant."
                $confirmationDevOpsSp = $null
                $devOps = $null
            }
        }
        
    }
    
    if ($devOpsSpInfo) {
        Write-Host "DevOps Service principal" $devOpsSpInfo.DisplayName "with App ID" $devOpsSpInfo.AppId "found."
    } 
}
Write-Host

$paramsObject | Add-Member -NotePropertyMembers $(@{DevOpsServicePrincipal = $devOpsSpInfo.DisplayName}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Obtaining encryption Key
############################################################################################################

$myBase64key = Read-Host "Enter encryption key provided by Difenda " -MaskInput

Write-Host

############################################################################################################
# C3 Engineer Email
############################################################################################################
$c3Email = $null
$c3EmailConfirmation = $null
while ( $c3EmailConfirmation -ne 'y' ) {
    $c3Email = Read-Host "Enter the email address of your Difenda C3 Engineer "
    while ($c3EmailConfirmation -ne 'y' -and $c3EmailConfirmation -ne 'n') {
        $c3EmailConfirmation = Read-Host 'Please confirm the email provided is correct [Y/N] '
    }
    if ($c3EmailConfirmation -eq 'y') {}
    else {
        $c3Email = $null
        $c3EmailConfirmation = $null
    }
}
Write-Host

############################################################################################################
# Obtaining information for Lighthouse delegations
############################################################################################################
Write-Log -Msg "Enter the following information for the Lighthouse delegation as provided by Difenda :"
Write-Host

try { $DifendaTenantId = $( $paramsObject | Select-Object -ExpandProperty "DifendaTenantId" -ErrorAction Stop ) }
catch {}
if ($DifendaTenantId) { Write-Host "Difenda Tenant Id            :" $DifendaTenantId }
else {$DifendaTenantId = Read-Host "Enter Difenda Tenant Id       "}

try { $ContributorGroupId = $( $paramsObject | Select-Object -ExpandProperty "ContributorGroupId" -ErrorAction Stop ) }
catch {}
if ($ContributorGroupId) { Write-Host "Contributor Group Id         :" $DifendaTenantId }
else {$ContributorGroupId = Read-Host "Enter Contributor group Id    "}

try { $L1GroupId = $( $paramsObject | Select-Object -ExpandProperty "L1GroupId" -ErrorAction Stop ) }
catch {}
if ($L1GroupId) { Write-Host "L1 Group Id                  :" $L1GroupId }
else {$L1GroupId = Read-Host "Enter Difenda L1 group Id     "}

try { $L2GroupId = $( $paramsObject | Select-Object -ExpandProperty "L2GroupId" -ErrorAction Stop ) }
catch {}
if ($L2GroupId) { Write-Host "L2 Group Id                  :" $L2GroupId }
else {$L2GroupId = Read-Host "Enter Difenda L2 group Id     "}

try { $ReaderGroupId = $( $paramsObject | Select-Object -ExpandProperty "ReaderGroupId" -ErrorAction Stop ) }
catch {}
if ($ReaderGroupId) { Write-Host "Reader Group Id              :" $ReaderGroupId }
else {$ReaderGroupId = Read-Host "Enter Difenda Reader group Id "}

$paramsObject | Add-Member -NotePropertyMembers $(@{DifendaTenantId = $DifendaTenantId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{ContributorGroupId = $ContributorGroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{L1GroupId = $L1GroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{L2GroupId = $L2GroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{ReaderGroupId = $ReaderGroupId}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host

############################################################################################################
# Information summary
############################################################################################################
Write-Host
Write-Log -Msg "The following provided informationt has been validated and will be used by the script:"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Company name                            : $company"
$subscriptionId = $subscriptionInfo.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription Id                         :", $subscriptionId, "(", $subscriptionInfo.Name, ")"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Microsoft Sentinel Resource group name  : $rgSentinel $rgSentinelState"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Integration Resource group name         : $rgIntegration (Resource group exists: $integrationRgExists)"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Triage Service principal name           : $triage (Service principal exists: $triageSpExists)"
if ($isavm) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "AVM Service principal name              :", $avmSpInfo.DisplayName, "( App ID:", $avmSpInfo.AppId, ")"
}
Write-Log -Sev 1 -Line $(__LINE__) -Msg "DevOps Service principal name           :", $devOpsSpInfo.DisplayName, "( App ID:", $devOpsSpInfo.AppId, ")"
$location = $rgSentinelInfo.Location
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure region location for all resources : $location"
Write-Host

Write-Host "We have collected all the information to be used by the script."
Write-Log -Msg "In the next step we will validate the pre-requisites for this script are met."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

$scope = '/subscriptions/' + $subscriptionId + '/resourceGroups/' + $rgSentinel
$startDate = Get-Date
$endDate = $startDate.AddYears(3)

#################################################################
# Check and install pre-requisites
#################################################################

Write-Log -Msg "Checking Powershell version"
$version = $PSVersionTable.PSVersion.Major
if ($version -eq 7) { 
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Powershell 7 installed. Nothing to do" 
}
else {
     Write-Log -Sev 2 -Line $(__LINE__) -Msg "Older version of Powershell installed. Please upgrade to Powershell 7" 
}

Write-Log -Msg "Validating required PowerShell modules are loaded"

Write-Log -Msg "PowerShell module Az.Resources"
if ($(Get-Module -Name Az.Resources).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.Resources. Current version ->", $(Get-Module -Name Az.Resources).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.Resources."
    Install-Module -Name Az.Resources -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Import-Module -Name Az.Resources -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.Resources. Version ->", $(Get-Module -Name Az.Resources).Version
}

Write-Log -Msg "PowerShell module Az.Accounts"
if ($(Get-Module -Name Az.Accounts).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.Accounts. Current version ->", $(Get-Module -Name Az.Accounts).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.Accounts."
    Install-Module -Name Az.Accounts -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Import-Module -Name Az.Accounts -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing module Az.Accounts. Version ->", $(Get-Module -Name Az.Accounts).Version
}

Write-Log -Msg "PowerShell module AzureAD.Standard.Preview"
if ($(Get-Module -Name AzureAD.Standard.Preview).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module AzureAD.Standard.Preview. Current version ->", $(Get-Module -Name AzureAD.Standard.Preview).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module AzureAD.Standard.Preview."
    Install-Module -Name AzureAD.Standard.Preview -Scope CurrentUser -Force
    Import-Module -Name AzureAD.Standard.Preview -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module AzureAD.Standard.Preview. Version ->", $(Get-Module -Name AzureAD.Standard.Preview).Version
}

Write-Host
Write-Host "Pre-requisites validation complete."
Write-Log -Msg "In the next step we will set the execution context."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

#########################################################################
#
# Context setup and validation
#
#########################################################################
Write-Host "The actions to be executed by this script need to use the context of a Global Administrator in the Azure tenant."
Write-Host "Please make sure your are connected to your Azure portal with a Global Administrator account with the Owner role on the Subscription where the Sentinel resources are deployed."
Write-Host
Write-Log -Msg "Please enter the credentials of a Global Administrator"
$userCredential = Get-Credential

$userToCompare = $userCredential.UserName + "*"
$currentUserDetails = Get-AzADUser | ? { $_.UserPrincipalName -like $userToCompare }

if ($currentUserDetails) { Write-Log -Sev 1 -Line $(__LINE__) -Msg "Succesfully obtained details for current user ->", $currentUserDetails.UserPrincipalName }
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Failed obtaining details for current user"
    Exit
}

Write-Log -Msg "Setting and validating Azure context"
$azContext = Set-AzContext -Subscription $subscriptionId
if ($?) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure context successfully set"
}
else {
    Write-Log -Sev 2 -Line $(__LINE__) -Msg "Azure Context set failed"
    Exit
}

if ($null -eq $azContext.Account.Id) {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Information for current user could not be collected"
    Exit
}

Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Tenant Id:              ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription name:      ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure account:          ", $azContext.Account.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure region:           ", $location

$subscriptionScope = "/subscriptions/$subscriptionId"
$currentRoleAssignment = Get-AzRoleAssignment -ObjectId $currentUserDetails.Id -Scope $subscriptionScope
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Current role assignment:", $currentRoleAssignment.RoleDefinitionName
if ($currentRoleAssignment.RoleDefinitionName -eq "Owner" -Or $currentRoleAssignment.RoleDefinitionName -eq "Contributor") {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure role", $currentRoleAssignment.RoleDefinitionName ,"assigned to", $currentUserDetails.UserPrincipalName ,"on subscription", $azContext.Subscription.Name
}
else{
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "User", $currentUserDetails.UserPrincipalName, "must be Owner or Contributor on the subscription", $azContext.Subscription.Name, "to continue."
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Please assign Owner or contrinutor and run the script again."
    Exit
}

Write-Host
Write-Host "Execution context successfully set."
Write-Log -Msg "The next step will create the Integration resource group."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

#########################################################################
#
# Integration Resource group
#
##########################################################################
Write-Host
Write-Log -Msg "Creating Integration Resource group for Difenda MXDR resource ..."
Write-Host
if ($integrationRgExists) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The Integration resource group already exists. Nothing to do."
}
else {
    Write-Host "Creating Integration Resource group $rgIntegration in the Subscription" $azContext.Subscription.Name "..."

    try {
        $newIntegrationRg = New-AzResourceGroup -Name $rgIntegration -Location $location
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating Integration Resource group."
        Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    
    Start-Sleep -Seconds 5

    if ($newIntegrationRg) {
        Write-Host "Resource group name :" $newIntegrationRg.ResourceGroupName
        Write-Host "Location            :" $newIntegrationRg.Location
        Write-Host "Provisioning state  :" $newIntegrationRg.ProvisioningState
        Write-Host "Tags                :" $newIntegrationRg.Tags
        Write-Host "Resource ID         :" $newIntegrationRg.ResourceId
        Write-Host
        Write-Host
        Write-Host "Validating existing Azure role assignments ..."
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Error creating Integration Resource group."
        Exit
    }
}

Write-Log -Msg "Creating Azure role assignment for the DevOps Service principal ..."
try {
    $currentDevOpsAssignment = Get-AzroleAssignment -ObjectId $devOpsSpInfo.Id -ResourceGroupName $rgIntegration
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Error obtaining current role assignment for the DevOps Service principal"
    Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

if ($currentDevOpsAssignment) {
    $isContributor = $false
    For ($i=0; $i -lt $currentDevOpsAssignment.Count; $i++) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Current Azure role assignment : ", $currentDevOpsAssignment[$i].RoleDefinitionName
        if ($currentDevOpsAssignment[$i].RoleDefinitionName -eq "Contributor") {
            $isContributor = $true
        }
        else {}
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "No current assignments found."
}

if ($isContributor) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal", $devOpsSpInfo.DisplayName, "already has the Contributor role assignment on", $rgIntegration
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Nothing to do."
}
else {
    Write-Log -Msg "Assigning Azure Resource group Contributor role to the DevOps Service principal ..."

    try {
        $devOpsRoleAssignment = New-AzRoleAssignment -ObjectId $devOpsSpInfo.Id -RoleDefinitionName Contributor -ResourceGroupName $rgIntegration -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($ErrorMessage -like "*Conflict*") {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Conflict creating Azure role assignment. Role may be already assigned."
            Exit
        }
        else {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating role assignment for the DevOps Service principal"
            Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }

    try {
        $devOpsUserAdminRole = New-AzRoleAssignment -ObjectId $devOpsSpInfo.Id -RoleDefinitionName 'User Access Administrator' -ResourceGroupName $rgIntegration -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($ErrorMessage -like "*Conflict*") {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Conflict creating Azure role assignment. Role may be already assigned."
            Exit
        }
        else {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating role assignment for the DevOps Service principal"
            Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }

}

if ($devOpsRoleAssignment) {
    Write-Log -Msg "Azure role assignment created for DevOps Service principal with the following details :"
    Write-Host "Scope                :" $devOpsRoleAssignment.Scope
    Write-Host "Display name         :" $devOpsRoleAssignment.DisplayName
    Write-Host "Role definition name :" $devOpsRoleAssignment.RoleDefinitionName
    Write-Host "Role definition ID   :" $devOpsRoleAssignment.RoleDefinitionId
}
Write-Host
if ($devOpsUserAdminRole) {
    Write-Log -Msg "Azure role assignment created for DevOps Service principal with the following details :"
    Write-Host "Scope                :" $devOpsUserAdminRole.Scope
    Write-Host "Display name         :" $devOpsUserAdminRole.DisplayName
    Write-Host "Role definition name :" $devOpsUserAdminRole.RoleDefinitionName
    Write-Host "Role definition ID   :" $devOpsUserAdminRole.RoleDefinitionId
}

Write-Host
Write-Host "Integration Resource group creation conplete."

#########################################################################
#
# MDETVM integration service principal section
#
##########################################################################
# if ($isavm) { 

#     Write-Log -Msg "Next we will update the API permissions required by the AVM Service principal."
#     Write-Host -NoNewLine 'Press [Enter] to continue ...'
#     $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
#     Clear-Host

#     Write-Log -Msg "Difenda AVM integration service principal section"
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Using AVM service principal name:", $avm
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for Difenda AVM service principal"

#     #---------------------------------------------------------------------------------------------------------------------------------------------------------------
#     # Required permissions in Microsoft Defender for Endpoint API (WindowsDefenderATP - Microsoft Threat and Vulnerability Management to Difenda Shield integration)
#     #---------------------------------------------------------------------------------------------------------------------------------------------------------------
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
#     $tvmPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role" # Machine.Read.All
#     $tvmPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "41269fc5-d04d-4bfd-bce7-43a51cea049a","Role" # Vulnerability.Read.All
#     $tvmPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "37f71c98-d198-41ae-964d-2c49aab74926","Role" # Software.Read.All
#     $tvmPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "6443965c-7dd2-4cfd-b38f-bb7772bee163","Role" # SecurityRecommendation.Read.All
#     $tvmPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role" # AdvancedQuery.Read.All
#     $tvmPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "02b005dd-f804-43b4-8fc7-078460413f74","Role" # Score.Read.All
#     $tvmPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "6a33eedf-ba73-4e5a-821b-f057ef63853a","Role" # RemediationTasks.Read.All
#     $tvmPermission8 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "227f2ea0-c2c2-4428-b7af-9ff40f1a720e","Role" # SecurityConfiguration.Read.All

#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
#     $tvm = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
#     $tvm.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
#     $tvm.ResourceAccess = $tvmPermission1, $tvmPermission2, $tvmPermission3, $tvmPermission4, $tvmPermission5, $tvmPermission6, $tvmPermission7, $tvmPermission8

#     #--------------------------------------------------------------------
#     # Required permissions in Microsoft Threat Protection (M365 Defender)
#     #--------------------------------------------------------------------
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Threat Protection API"
#     $mtpPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7734e8e5-8dde-42fc-b5ae-6eafea078693","Role" # AdvancedHunting.Read.All

#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MTP permissions assignment"
#     $mtp = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
#     $mtp.ResourceAppId = '8ee8fdad-f234-4243-8f3b-15c294843740'
#     $mtp.ResourceAccess = $mtpPermission1

#     #------------------------------------------
#     # Required permissions in Log Analytics API
#     #------------------------------------------
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Log Analytics API"
#     $alaPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e8f6e161-84d0-4cd7-9441-2d46ec9ec3d5","Role" # Data.Read

#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Log Analytics permissions assignment"
#     $ala = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
#     $ala.ResourceAppId = 'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5'
#     $ala.ResourceAccess = $alaPermission1

#     #--------------------------------------------
#     # Required permissions in Microsoft Graph API
#     #--------------------------------------------
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Graph API"
#     $msgPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7438b122-aefc-4978-80ed-43db9fcc7715","Role" # Device.Read.All
#     $msgPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7ab1d382-f21e-4acd-a863-ba3e13f7da61","Role" # Directory.Read.All
#     $msgPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "5b567255-7703-4780-807c-7be8301ae99b","Role" # Group.Read.All
#     $msgPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "98830695-27a2-44f7-8c18-0c3ebc9698f6","Role" # GroupMember.Read.All
#     $msgPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "dc5007c0-2d7d-4c42-879c-2dab87571379","Role" # IdentityRiskyUser.Read.All
#     $msgPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "230c1aed-a721-4c5d-9cb4-a90514e508ef","Role" # Reports.Read.All
#     $msgPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "483bed4a-2ad3-4361-a73b-c83ccdbdc53c","Role" # RoleManagement.Read.Directory
#     $msgPermission8 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "c7fbd983-d9aa-4fa7-84b8-17382c103bc4","Role" # RoleManagement.Read.All
#     $msgPermission9 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "df021288-bdef-4463-88db-98f22de89214","Role" # User.Read.All

#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Microsoft Graph permissions assignment"
#     $msg = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
#     $msg.ResourceAppId = '00000003-0000-0000-c000-000000000000'
#     $msg.ResourceAccess = $msgPermission1, $msgPermission2, $msgPermission3, $msgPermission4, $msgPermission5, $msgPermission6, $msgPermission7, $msgPermission8, $msgPermission9

#     #---------------------------
#     # Creating service principal
#     #---------------------------
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if service principal exists"
#     $currentMdeTvm = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $avm }
#     if ($currentMdeTvm.Count -gt 1) {
#         Write-Log -Sev 3 -Line (__Line__) -Msg "Multiple Service principals found with the name $avm"
#         Write-Log -Msg "Select the Application ID corresponding to Service principal to use."
#         For ($i=0; $i -lt $currentMdeTvm.Count; $i++)  {
#             Write-Host "$($i+1): $($currentMdeTvm[$i].AppId)"
#           }
#           $number = Read-Host "Press the number to select a service principal: "
#           Write-Host "You've selected " $($currentMdeTvm[$number-1]).AppId
#           $currentMdeTvm = $currentMdeTvm[$number-1]
#     }
#     if ($null -eq $currentMdeTvm) {
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDETVM integration service principal"
#         try {
#             $newMdeTvm = New-AzADServicePrincipal -Scope /subscriptions/$subscriptionId/resourceGroups/$rgSentinel -DisplayName $avm -Role Reader -ErrorAction SilentlyContinue
#         }
#         catch {
#             $ErrorMessage = $_.Exception.Message
#             Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating MDETVM integration service principal"
#             Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
#             Exit
#         }
#     }
#     else {
#         Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal", $avm, "was found in the tenant"
#         $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
#         while($confirmation -ne "y") {
#             if ($confirmation -eq 'n') { Exit }
#             $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
#         }
#         $newMdeTvm = $currentMdeTvm
#     }
#     if ($null -ne $newMdeTvm) {
#         Start-Sleep -Seconds 30
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining details for MDETVM service principal"
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning API permissions"

#         $newMdeTvmDetails = Get-AzureADApplication -All $true | ? { $_.AppId -eq $newMdeTvm.AppId }

#         try {
#             Set-AzureADApplication -ObjectId $newMdeTvmDetails.ObjectId -RequiredResourceAccess $tvm, $mtp, $ala, $msg
#         }
#         catch {
#             $ErrorMessage = $_.Exception.Message
#             Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to MDETVM service principal"
#             Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
#             Exit
#         }
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "API permissions assigned successfully"
#     }
#     else {
#         Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating MDETVM integration service principal"
#     }

#     Write-Log -Msg "Difenda AVM service principal details"
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal name: ", $newMdeTvmDetails.DisplayName
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Object Id:              ", $newMdeTvmDetails.ObjectId
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Application Id:         ", $newMdeTvmDetails.AppId
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Tenant Id:              ", $(Get-AzContext).Tenant.Id
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Subscription Id:        ", $azContext.Subscription.Id
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Subscription name:      ", $azContext.Subscription.Name
# }

#########################################################################
#
# Triage service principal section
#
##########################################################################

Write-Log -Msg "The next step will create the the Triage Service principal and assign required API permissions."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

Write-Log -Msg "Difenda Triage engine service principal section"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service Triage principal name:", $triage
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for Difenda Triage service principal"

#---------------------------------------------------------------------------------------------------------------------------------------------------------------
# Required permissions in Microsoft Defender for Endpoint API (WindowsDefenderATP - Microsoft Threat and Vulnerability Management to Difenda Shield integration)
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
$mdeTriagePermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role" # AdvancedQuery.Read.All
$mdeTriagePermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role" # Machine.Read.All
$mdeTriagePermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "41269fc5-d04d-4bfd-bce7-43a51cea049a","Role" # Vulnerability.Read.All

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
$mdeTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$mdeTriageRequiredResourceAccess.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$mdeTriageRequiredResourceAccess.ResourceAccess = $mdeTriagePermission1, $mdeTriagePermission2, $mdeTriagePermission3

#--------------------------------------------------------------------
# Required permissions in Microsoft Threat Protection (M365 Defender)
#--------------------------------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Threat Protection API"
$mtpTriagePermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7734e8e5-8dde-42fc-b5ae-6eafea078693","Role" # AdvancedHunting.Read.All

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MTP permissions assignment"
$mtpTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$mtpTriageRequiredResourceAccess.ResourceAppId = '8ee8fdad-f234-4243-8f3b-15c294843740'
$mtpTriageRequiredResourceAccess.ResourceAccess = $mtpTriagePermission1

#------------------------------------------
# Required permissions in Log Analytics API
#------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Log Analytics API"
$alaTriagePermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e8f6e161-84d0-4cd7-9441-2d46ec9ec3d5","Role" # Data.Read

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Log Analytics permissions assignment"
$alaTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$alaTriageRequiredResourceAccess.ResourceAppId = 'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5'
$alaTriageRequiredResourceAccess.ResourceAccess = $alaTriagePermission1

#--------------------------------------------
# Required permissions in Microsoft Graph API
#--------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Graph API"
$msgTriagePermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "40f97065-369a-49f4-947c-6a255697ae91","Role" # MailboxSettings.Read
$msgTriagePermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "df021288-bdef-4463-88db-98f22de89214","Role" # User.Read.All
$msgTriagePermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "230c1aed-a721-4c5d-9cb4-a90514e508ef","Role" # Reports.Read.All
$msgTriagePermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "483bed4a-2ad3-4361-a73b-c83ccdbdc53c","Role" # RoleManagement.Read.Directory
$msgTriagePermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "dc5007c0-2d7d-4c42-879c-2dab87571379","Role" # IdentityRiskyUser.Read.All
$msgTriagePermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "693c5e45-0940-467d-9b8a-1022fb9d42ef","Role" # Mail.ReadBasic.All

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Microsoft Graph permissions assignment"
$msgTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$msgTriageRequiredResourceAccess.ResourceAppId = '00000003-0000-0000-c000-000000000000'
$msgTriageRequiredResourceAccess.ResourceAccess = $msgTriagePermission1, $msgTriagePermission2, $msgTriagePermission3, $msgTriagePermission4, $msgTriagePermission5, $msgTriagePermission6

#-----------------------------
# Required permissions in MDCA
#-----------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Defender for Cloud App"
$mdcaPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "83bc8d83-2679-44ef-b813-d5f556fc4474","Role" # investigation.read

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Microsoft Defender for Cloud Apps permissions assignment"
$mdcaTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$mdcaTriageRequiredResourceAccess.ResourceAppId = '05a65629-4c1b-48c1-a78b-804c4abdd4af'
$mdcaTriageRequiredResourceAccess.ResourceAccess = $mdcaPermission1

#---------------------------
# Creating service principal
#---------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if service principal exists"
$currentMdeTriage = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $triage }

if ($null -eq $currentMdeTriage) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Triage integration service principal"
    try {
        $newMdeTriage = New-AzADServicePrincipal -Scope /subscriptions/$subscriptionId/resourceGroups/$rgSentinel -DisplayName $triage -Role Reader -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating MDETVM integration service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal", $triage, "was found in the tenant"
    $confirmation = Read-Host "Do you want to use this service principal? [Y/N] "
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this service principal? [Y/N] "
    }
    $newMdeTriage = $currentMdeTriage
}

while($triageSpKeyConfirm -ne 'y' -and $triageSpKeyConfirm -ne 'n') {
    $triageSpKeyConfirm = Read-Host "Do you want to create a new secret for this Service principal? [Y/N] "
}

if ($null -ne $newMdeTriage) {
    Start-Sleep -Seconds 30
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage integration service principal successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining details for Triage service principal"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning API permissions"
    $newMdeTriageDetails = Get-AzureADApplication -All $true | ? { $_.DisplayName -eq $triage }

    if ($newMdeTriage.Length -gt 1) {
        Write-Log -Sev 3 -Line (__Line__) -Msg "Multiple Service principals found with the name $triage"
        Exit
    }

    try {
        Set-AzureADApplication -ObjectId $newMdeTriageDetails.ObjectId -RequiredResourceAccess $mdeTriageRequiredResourceAccess, $mtpTriageRequiredResourceAccess, $alaTriageRequiredResourceAccess, $msgTriageRequiredResourceAccess, $mdcaTriageRequiredResourceAccess
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to Triage service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "API permissions assigned successfully"
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Triage integration service principal"
}

if ($triageSpKeyConfirm -eq 'y') {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for Triage service principal"
    try {
        $triageSecret = New-AzureADApplicationPasswordCredential -ObjectId $newMdeTriageDetails.ObjectId -CustomKeyIdentifier "MXDR Triage Integration" -StartDate $startDate -EndDate $endDate
    }
    catch {
        
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for Triage service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

Write-Log -Msg "Difenda Triage service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal name: ", $triage
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Object Id:              ", $newMdeTriageDetails.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Application Id:         ", $newMdeTriageDetails.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Tenant Id:              ", $(Get-AzContext).Tenant.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Subscription name:      ", $azContext.Subscription.Name
if ($triageSpKeyConfirm = 'y') {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret start date:      ", $triageSecret.StartDate
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret end date:        ", $triageSecret.EndDate
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret value:           ", $triageSecret.Value
}

$triageSpInfoObject = @{
    ObjectId = $newMdeTriageDetails.ObjectId
    AppId = $newMdeTriageDetails.AppId
    DisplayName = $newMdeTriageDetails.DisplayName
    SecretStart  = $triageSecret.StartDate
    SecretEnds = $triageSecret.EndDate
    SecretValue = $triageSecret.Value
    TenantId = $(Get-AzContext).Tenant.Id
}

Write-Host "Triage service principal successfully created."
Write-Log -Msg "Next we will update Azure Lighthouse delegations."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

#########################################################################
#
# Udate Lighthouse delegation
#
##########################################################################

#-------------------------------
# Downloading ARM template files
#-------------------------------
Write-Log -Msg "Downloading Lighthouse ARM template files from repository ..."
Write-Log -Sev 1 -Line (__LINE__) -Msg "Downloading ARM template file for the Sentinel Resource group delegations."
$customProgressPref = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'
try {
    $downloadSentinelTemplate = Invoke-WebRequest https://raw.githubusercontent.com/Difenda/MDR-Onboard/main/Scripts/Shield2.0/sentinelDelegations.json -OutFile ./sentinelDelegations.json -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed downloading Sentinel Lighthouse delegation template"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($downloadSentinelTemplate) { Write-Log -Sev 1 -Line (__LINE__) -Msg "Download complete." }

Write-Log -Sev 1 -Line (__LINE__) -Msg "Downloading ARM template file for the Integration Resource group delegations."
try {
    $downloadIntegrationTemplate = Invoke-WebRequest https://raw.githubusercontent.com/Difenda/MDR-Onboard/main/Scripts/Shield2.0/integrationDelegations.json -OutFile ./integrationDelegations.json -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed downloading Integration Lighthouse delegation template"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($downloadIntegrationTemplate) { Write-Log -Sev 1 -Line (__LINE__) -Msg "Download complete." }
$ProgressPreference = $customProgressPref

#---------------------------------
# Obtaining resource group details
#---------------------------------
try { $sentinelRgDetails = Get-AzResourceGroup -Name $rgSentinel -ErrorAction Stop }
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed retrieving Sentinel resource group information"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

try { $integrationRgDetails = Get-AzResourceGroup -Name $rgIntegration -ErrorAction Stop }
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed retrieving Integration resource group information"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

#------------------------
# Executing ARM templates
#------------------------
Write-Host
Write-Log -Msg "Executing ARM templates ..."
Write-Host

$sentinelDelegationParams = @{
    managedByTenantId = $DifendaTenantId;
    contributorGroupId = $ContributorGroupId;
    readerGroupId = $ReaderGroupId;
    L1GroupId = $L1GroupId;
    L2GroupId = $L2GroupId;
    rgName = $rgSentinel;
    location = $sentinelRgDetails.Location
}
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure Lighthouse delegation for the resource group $rgSentinel"
if (Test-Path -Path ./sentinelDelegations.json -PathType Leaf) {
    try {
        $newSentinelDelegation = New-AzDeployment  -Location $sentinelRgDetails.Location -TemplateFile ./sentinelDelegations.json -TemplateParameterObject $sentinelDelegationParams -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Lighthouse delegation for Sentinel Resource group."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure Lighthouse delegation for $rgSentinel completed successfully."
    
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Sentinel delegation ARM file not found."
}
Write-Host

$integrationDelegationParams = @{
    managedByTenantId = $DifendaTenantId;
    contributorGroupId = $ContributorGroupId;
    rgName = $rgIntegration;
    location = $integrationRgDetails.Location
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure Lighthouse delegation for the resource group $rgIntegration"
if (Test-Path -Path ./integrationDelegations.json -PathType Leaf) {
    try {
        $newIntegrationDelegation = New-AzDeployment -Location $integrationRgDetails.Location -TemplateFile ./integrationDelegations.json -TemplateParameterObject $integrationDelegationParams -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Lighthouse delegation for Integration Resource group."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure Lighthouse delegation for $rgSentinel completed successfully"
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Integration delegation ARM file not found."
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Lighthouse delegations updated."
Write-Host
Write-Log -Msg "In the following step we will create the Azure AD groups to be used by the SSO configuration."
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

#########################################################################
#
# SSO security groups
#
##########################################################################

Write-Log -Msg 'Crearting Azure Active Directory groups for Single sogn-on and notifications.'
Write-Host

$groupSso1 = $company + " - IT Security Team"
Write-Log -Msg "Creating group $groupSso1"
try {
    $createSsoGroup1 = New-AzureADGroup -DisplayName $groupSso1 -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Group for SSO access to Difenda Shield. Regular notifications." -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso1"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($createSsoGroup1) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Group $groupSso1 successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name :", $createSsoGroup1.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Description  :", $createSsoGroup1.Description
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Object ID    :", $createSsoGroup1.ObjectId
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso1"
}

$groupSso2 = $company + " - High Priority Alert Group"
Write-Log -Msg "Creating group $groupSso2"
try {
    $createSsoGroup2 = New-AzureADGroup -DisplayName $groupSso2 -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Group for SSO access to Difenda Shield. HPI notifications." -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso2"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($createSsoGroup2) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Group $groupSso2 successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name :", $createSsoGroup2.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Description  :", $createSsoGroup2.Description
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Object ID    :", $createSsoGroup2.ObjectId
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso2"
}

$groupSso3 = $company + " - No Alert Group"
Write-Log -Msg "Creating group $groupSso3"
try {
    $createSsoGroup3 = New-AzureADGroup -DisplayName $groupSso3 -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description "Group for SSO access to Difenda Shield. No notifications." 
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso3"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($createSsoGroup3) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Group $groupSso3 successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name :", $createSsoGroup3.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Description  :", $createSsoGroup3.Description
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Object ID    :", $createSsoGroup3.ObjectId
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso3"
}

#####################################################
#
# Invoking customer onboard API
#
#####################################################

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$myUrl = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($myBase64key))
$body = @{
    ApprovalEmail = $c3Email
    CustomerName = $company
    Subscription = $subscriptionInfo
    SentinelResourceGroup = $rgSentinelInfo
    IntegrationResourceGroup = $rgIntegrationInfo
    TriageServicePrincipal = $triageSpInfoObject
    SsoItSecurity = $createSsoGroup1
    SsoHpiNotifications = $createSsoGroup2
    SsoNoNotifications = $createSsoGroup3
    IsAvmCustomer = $isavm
    DevOpsServicePrincipal = $devOpsSpInfo
}
try {
    $response = Invoke-RestMethod -Method 'POST' -Uri $myUrl -Headers $headers -Body ($body | ConvertTo-Json) -ErrorAction Stop
}   
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating $groupSso3"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
Write-Host $response

#######################################################################
#
# Manual section
#
#######################################################################
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host '   Script has finished'
Write-Host '   Please look at any Warnings or errors and correct manually'
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Clear-Host
Write-Host 'Next, we will guide you through the manual steps to complete this upgrade. Please follow the instructions provided.'
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host -NoNewLine
Write-Host
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host "Grant admin consent for the triage service principal $triage in Azure AD"
Write-Host 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent?pivots=portal'
Write-Host
$confirmationTriageConsent = Read-Host "Please confirm Admin consent has been granted for Triage service principal $triage [Y/N]"
while($confirmationTriageConsent -ne "y") {
    if ($confirmationTriageConsent -eq 'n') { Exit }
    $confirmationTriageConsent = Read-Host "Please confirm Admin consent has been granted for Triage service principal $triage [Y/N]"
}
Write-Host
if ($isavm) {
    Write-Host '**********************************************************************************************'
    Write-Host
    Write-Host "Grant admin consent for the AVM service principal $avm in Azure AD"
    Write-Host 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent?pivots=portal'
    Write-Host
    $confirmationAvmConsent = Read-Host "Please confirm Admin consent has been granted for AVM principal $avm [Y/N]"
    while($confirmationAvmConsent -ne "y") {
        if ($confirmationAvmConsent -eq 'n') { Exit }
        $confirmationAvmConsent = Read-Host "Please confirm Admin consent has been granted for AVM service principal $avm [Y/N]"
    }
    Write-Host
}
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Enable the Microsoft 365 Defender Sentinel Data connector. Follow instructions provided in the following link'
Write-Host 'https://github.com/Difenda/MDR-Onboard/blob/main/Scripts/Shield2.0/shieldWiki.md#111-enable-microsoft-365-defender-data-connector'
Write-Host
$confirmationM365Dconnector = Read-Host "Please confirm when enabling the Microsoft 365 Defender Sentinel Data connector has been completed [Y/N]"
while($confirmationM365Dconnector -ne "y") {
    if ($confirmationM365Dconnector -eq 'n') { Exit }
    $confirmationM365Dconnector = Read-Host "Please confirm when enabling the Microsoft 365 Defender Sentinel Data connector has been completed [Y/N]"
}
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Enable the Microsoft Defender for Cloud Sentinel Data connector. Follow instructions provided in the following link'
Write-Host 'https://github.com/Difenda/MDR-Onboard/blob/main/Scripts/Shield2.0/shieldWiki.md#112-enable-defender-for-cloud-data-connector'
Write-Host
$confirmationMdcDconnector = Read-Host "Please confirm when enabling the Microsoft Defender for Cloud Sentinel Data connector has been completed [Y/N]"
while($confirmationMdcDconnector -ne "y") {
    if ($confirmationMdcDconnector -eq 'n') { Exit }
    $confirmationMdcDconnector = Read-Host "Please confirm when enabling the Microsoft Defender for Cloud Sentinel Data connector has been completed [Y/N]"
}
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Review existing automation rules and remove any closing ALL Incidents. Follow instructions provided in the following link'
Write-Host 'https://github.com/Difenda/MDR-Onboard/blob/main/Scripts/Shield2.0/shieldWiki.md#12-remove-any-automation-rule-closing-all-incidents'
Write-Host
$confirmationCloseAr = Read-Host "Please confirm when any Automation rules closing ALL Incidents have been removed [Y/N]"
while($confirmationCloseAr -ne "y") {
    if ($confirmationCloseAr -eq 'n') { Exit }
    $confirmationCloseAr = Read-Host "Please confirm when any Automation rules closing ALL Incidents have been removed [Y/N]"
}
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Authorize Sentinel to execute playbooks in the Integration resource group provided in the following link'
Write-Host 'https://github.com/Difenda/MDR-Onboard/blob/main/Scripts/Shield2.0/shieldWiki.md#13-authorize-sentinel-to-execute-playbooks-in-the-new-resource-group'
Write-Host
$confirmationSentinelAuth = Read-Host "Please confirm when Microsoft Sentinel has been authorized to execute playbooks in the Integration resource group [Y/N]"
while($confirmationSentinelAuth -ne "y") {
    if ($confirmationSentinelAuth -eq 'n') { Exit }
    $confirmationSentinelAuth = Read-Host "Please confirm when Microsoft Sentinel has been authorized to execute playbooks in the Integration resource group [Y/N]"
}
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Configure Single sign-on for Difenda Shield access'
Write-Host 'https://github.com/Difenda/MDR-Onboard/blob/main/Scripts/Shield2.0/shieldWiki.md#5-configure-single-sign-on-for-shield-access'
Write-Host
$confirmationSentinelAuth = Read-Host "Please confirm when Single sign-on has been configured and definition files shared with Difenda [Y/N]"
while($confirmationSentinelAuth -ne "y") {
    if ($confirmationSentinelAuth -eq 'n') { Exit }
    $confirmationSentinelAuth = Read-Host "Please confirm when Single sign-on has been configured and definition files shared with Difenda [Y/N]"
}
Write-Host
Write-Host '**********************************************************************************************'
Write-Host
Write-Host 'Script execution has finished.'
Write-Host
Write-Host '**********************************************************************************************'
