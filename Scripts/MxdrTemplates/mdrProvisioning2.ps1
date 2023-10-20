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
            Write-Host 'INFO  : [' $Line ']' $Msg -ForegroundColor White
            $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - INFO [' + $Line + '] ' + $Msg >> $filePath
        }
        if ($Sev -eq 2) { 
            Write-Host 'WARN  : [' $Line ']' $Msg -ForegroundColor Yellow
            $(Get-Date -Format "dddd MM/dd/yyyy HH:mm") + ' - WARN [' + $Line + '] ' + $Msg >> $filePath
        }
        if ($Sev -eq 3) { 
            Write-Host 'ERROR : [' $Line ']' $Msg -ForegroundColor Red
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
Write-Log -Msg "Start processing PowerShell script - v0.9j"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Sample informational message"
Write-Log -Sev 2 -Line $(__LINE__) -Msg "Sample warning message"
Write-Log -Sev 3 -Line $(__LINE__) -Msg "Sample error message"

############################################################################################################
# Set log file path
############################################################################################################

$filePath = './difenda-mdrProvisioning-' + $company + "-" + $(Get-Date -Format "MM-dd-yyyy") + '.log'

############################################################################################################
# Get parameters from file - If script was run previously
############################################################################################################

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
    Write-Host
    $paramsObject = ConvertFrom-Json -InputObject $parametersFile
    $parameterCount = $paramsObject.PSObject.Properties.value.Count
}
else {
    $paramsObject = New-Object -TypeName PSObject
}

############################################################################################################
# Instructions message
############################################################################################################

# Write-Host "This is the instructions message ..."
# Write-Host "Add instructions HERE !!!"
Write-Host
Write-Host -NoNewLine 'Press [Enter] to start ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Company name
############################################################################################################

Clear-Host

Write-Host
Write-Host "Please provide the company name. Please note that special characters and spaces are not allowed."
Write-Host

$specialCharacters = ('\!|\#|\$|\%|\^|\&|\-|_|\"|\`|@|\\| ')
$confirmationCompany = $null
$company = $null
While ($null -eq $company) {
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
                Write-Host
                $confirmationCompany = Read-Host "Are you sure you want to use $company as the Company name [Y/N] "
            }
            if ($confirmationCompany -eq 'n') { 
                $company = $null
                $confirmationCompany = $null
            }
        }
        else {
            while($confirmationCompany -ne "y") {
                while ($company.length -lt 3 -or $company -match $specialCharacters) {
                    $company = Read-Host 'Enter the Customer name to be used in Difenda Services (3 or more alphanumeric characters) '
                }
                while ($confirmationCompany -ne 'y' -and $confirmationCompany -ne 'n') {
                    Write-Host
                    $confirmationCompany = Read-Host "Are you sure you want to use $company as the Company name [Y/N] "
                }
                if ($confirmationCompany -eq 'y') {
                    Write-Host
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

$paramsObject | Add-Member -NotePropertyMembers $(@{CustomerName = $company}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Azure subscription information
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg "Azure Subscription information for MXDR for IT"
Write-Host
Write-Host 'A subscription is an agreement with Microsoft to use one or more Microsoft cloud platforms or services,'
Write-Host 'for which charges accrue based on either a per-user license fee or on cloud-based resource consumption.'
Write-Host
Write-Host "Please provide the Azure subscription to be used to create the resources required for Difenda MXDR services."
Write-Host

$subscriptionId = $null
$confirmationSubs = $null
$compareValue = 0
while ($confirmationSubs -ne 'y') {
    while ($null -eq $subscriptionId) {
        if ($parameterCount -gt $compareValue) {
            try { $subscriptionId = $( $paramsObject | Select-Object -ExpandProperty "SubscriptionId" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($subscriptionId.length -ne 36) {
                $subscriptionId = Read-Host 'Enter the Subscription ID where the Sentinel resources will be deployed '
                if ($subscriptionId -match '^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$') {}
                else {
                    Write-Log -Sev 2 -Line $(__LINE__) -Msg "Invalid Subscription ID format."
                    $subscriptionId = $null
                }
            }
        }
        while ($confirmationSubs -ne 'y' -and $confirmationSubs -ne 'n') {
            Write-Host
            $confirmationSubs = Read-Host "Please confirm $subscriptionId is the correct Subscription ID to be used for MXDR for IT services [Y/N] "
        }
        if ($confirmationSubs -eq 'y') {
            try { $subscriptionInfo = Get-AzSubscription -SubscriptionId $subscriptionId -ErrorAction Stop }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem obtaining Subscription information."
                Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
                $confirmationSubs = $null
                $subscriptionId = $null
                $compareValue = 100
            }
            if ($subscriptionInfo) {
                Write-Host
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

$subscriptionInfoObject = @{
    Name = $subscriptionInfo.Name
    Id = $subscriptionInfo.Id
    TenantId = $subscriptionInfo.TenantId
    State = $subscriptionInfo.State
}

$paramsObject | Add-Member -NotePropertyMembers $(@{SubscriptionId = $subscriptionInfo.Id}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Context setup and validation
#########################################################################

Clear-Host
Write-Host
Write-Log -Msg "Azure execution context setup"
Write-Host
Write-Host "Actions to be executed by this script need to use the context of a Global Administrator in the Azure tenant."
Write-Host "Please make sure you are connected to your Azure portal with a Global Administrator account with the Owner role on the Subscription where the Sentinel resources are deployed."
Write-Host

$userToCompare = [regex]::Matches((az ad signed-in-user show --query userPrincipalName), '".*?"').Value -replace '"'
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Current user is : $userToCompare"
Write-Host

$currentUserDetails = Get-AzADUser | Where-Object { $_.UserPrincipalName -like $userToCompare }

if ($currentUserDetails) { Write-Log -Sev 1 -Line $(__LINE__) -Msg "Succesfully obtained details for user", $currentUserDetails.UserPrincipalName }
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Failed obtaining details for current user"
    Exit
}

Write-Log -Msg "Setting and validating Azure context"
Write-Host
$azContext = Set-AzContext -Subscription $subscriptionId
if ($?) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure context successfully set"
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Azure Context set failed"
    Exit
}

if ($null -eq $azContext.Account.Id) {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Information for current user could not be collected"
    Exit
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Collecting Azure tenant information."
try {
    $azTenant = Get-AzTenant -Tenant $azContext.Subscription.TenantId
}
catch {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Failed obtaining Azure tenant information"
    Exit
}

Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Directory name    : ", $azTenant.Name
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Tenant Id         : ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription name : ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription Id   : ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure account     : ", $azContext.Account.Id

$subscriptionScope = "/subscriptions/$subscriptionId"
$currentRoleAssignment = Get-AzRoleAssignment -ObjectId $currentUserDetails.Id -Scope $subscriptionScope
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Current role assignment:", $currentRoleAssignment.RoleDefinitionName
if ($currentRoleAssignment.RoleDefinitionName -eq "Owner" -Or $currentRoleAssignment.RoleDefinitionName -eq "Contributor") {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure role", $currentRoleAssignment.RoleDefinitionName ,"assigned to", $currentUserDetails.UserPrincipalName ,"on subscription", $azContext.Subscription.Name
}
else{
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "User", $currentUserDetails.UserPrincipalName, "must be Owner on the subscription", $azContext.Subscription.Name, "to continue."
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Please assign Owner role and run the script again."
    Exit
}

$tenantInfoObject = @{
    Id = $azTenant.Id
    Name = $azTenant.Name
    Category = $azTenant.Category
    Domains = $azTenant.Domains
}

$userInfoObject = @{
    DisplayName = $currentUserDetails.DisplayName
    Id = $currentUserDetails.Id
    Mail = $currentUserDetails.Mail
    UserPrincipalName = $currentUserDetails.UserPrincipalName
}

Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Execution context successfully set."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Get Azure region/location for new resources
############################################################################################################

$location = $null
$azLocations = $null
$confirmRegion = $null
$compareValue = 0

Clear-Host
Write-Host
Write-Log -Msg 'Please select the Azure region to deploy the new resources.'
Write-Host
Write-Host 'Microsoft Sentinel is a non-regional service. However, Microsoft Sentinel is built on top of Azure Monitor Logs, which is a regional service. Note that:'
Write-Host '   - Microsoft Sentinel can run on workspaces in the supported regions where Log Analytics is available.'
Write-Host '   - Microsoft Sentinel stores customer data in the same geography as the Log Analytics workspace associated with Microsoft Sentinel.'
Write-Host '   - Microsoft Sentinel processes customer data in one of two locations:'
Write-Host '      - If the Log Analytics workspace is located in Europe, customer data is processed in Europe.'
Write-Host '      - For all other locations, customer data is processed in the US.'
Write-Host

if ($parameterCount -gt $compareValue) {
    try { $location = $( $paramsObject | Select-Object -ExpandProperty "AzureLocation" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
}

if ($location) {
    while ($confirmRegion -ne 'y' -and $confirmRegion -ne 'n') {
        Write-Host
        $confirmRegion = Read-Host "Please confirm the location to deploy Azure resources is : $location [Y/N] "
    }
    try { $getLocationInfo =  Get-AzLocation | Where-Object { $_.Location -eq $location } }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed retrieving Azure location details.."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    }
    if ($getLocationInfo) {
        $locationDisplayName = $getLocationInfo.DisplayName
        $regionName = $getLocationInfo.GeographyGroup
    }
}

if ($null -eq $location -or $confirmRegion -eq 'n') {
    try {
        $azLocations = Get-AzLocation | Where-Object {$_.Providers -eq "Microsoft.OperationalInsights" }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem obtaining Azure regions."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    }
    $confirmRegion = $null
    if ($azLocations) {
        while ($confirmRegion -ne 'y') {
            $global:i=0
            $regionsIndex = 0
            $azLocations | Group-Object -Property GeographyGroup | Sort-Object GeographyGroup | Select-Object @{ Name="Item";Expression={ $global:i++;$global:i } }, Name -OutVariable regionMenu | Format-Table -AutoSize
            while ($regionsIndex -eq 0 -or $regionsIndex -gt $i) {
                $regionsIndex = Read-Host "Select the Azure region to deploy MXDR resources "
            }
            $selectedRegion = $regionMenu | Where-Object { $_.Item -eq $regionsIndex }
            Write-Host
            while ($confirmRegion -ne 'y' -and $confirmRegion -ne 'n') {
                $regionName = $($selectedRegion.name)
                $confirmRegion = Read-Host "Confirm selected region is $regionName ? [Y/N] "
            }
            if ($confirmRegion -eq 'n') { $confirmRegion = $null }
        }
    }
    else {
        Write-Host "The list of supported Azure regions could not be obtained."
        $regionName = Read-Host "Please enter the name of a supported region using the link provided "
    }
    $confirmLocation = $null
    if ($confirmLocation -ne 'y' -and $regionName) {
        while ($confirmLocation -ne 'y') {
            $global:x=0
            $locationsIndex = 0
            $azLocations | Where-Object { $_.GeographyGroup -eq $regionName } | Sort-Object DisplayName | Select-Object @{ Name="Item";Expression={ $global:x++;$global:x } }, DisplayName, Location, RegionType, PhysicalLocation -OutVariable locationMenu | Format-Table -AutoSize
            while ($locationsIndex -eq 0 -or $locationsIndex -gt $x) {
                $locationsIndex = Read-Host "Select the Azure location to deploy MXDR resources "
            }
            $selectedLocation = $locationMenu | Where-Object { $_.Item -eq $locationsIndex }
            Write-Host
            while ($confirmLocation -ne 'y' -and $confirmLocation -ne 'n') {
                $location = $($selectedLocation.Location)
                $locationDisplayName = $($selectedLocation.DisplayName)
                $confirmLocation = Read-Host "Confirm selected Azure location is $locationDisplayName ($location) ? [Y/N] "
            }
            if ($confirmLocation -eq 'n') { $confirmLocation = $null }
        }
    }
}

$AzureLocationObject = @{
    DisplayName = $locationDisplayName
    Region = $regionName
    Location = $location
}

$paramsObject | Add-Member -NotePropertyMembers $(@{AzureLocation = $location}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Sentinel Resource group information
#
# Resource group names only allow up to 90 characters and 
# can only include alphanumeric, underscore, parentheses, hyphen, period (except at end), 
# and Unicode characters that match the allowed characters
# 
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg "Sentinel resources information"
Write-Host
Write-Host 'A resource group is a container that holds related resources for an Azure solution.'
Write-Host 'The resource group can include all the resources for the solution, or only those resources that you want to manage as a group.'
Write-Host 'Generally, add resources that share the same lifecycle to the same resource group so you can easily deploy, update, and delete them as a group.'
Write-Host 'The resource group stores metadata about the resources. Therefore, when you specify a location for the resource group, you are specifying where that metadata is stored.'
Write-Host
Write-Host 'Enter a resource group name to be used. Please ensure this value is unique before creating the resource group and Azure resources. If an existing Sentinel workspace'
Write-Host 'will be used for the MDR service, enter the Resource group name containing it.'
Write-Host
Write-Host 'Resource group and Sentinel workspace names must be unique to prevent operational conflicts.'
Write-Host

$rgSentinel = $null
$confirmationrgSentinel = $null
$compareValue = 0
while($confirmationrgSentinel -ne "y") {
    while ($null -eq $rgSentinel) {
        if ($parameterCount -gt $compareValue) {
            try { $rgSentinel = $( $paramsObject | Select-Object -ExpandProperty "SentinelRgName" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($rgSentinel.length -lt 4 -or $rgSentinel.length -gt 89) {
                $rgSentinel = Read-Host 'Enter the name of the Sentinel Resource group '
            }
        }
        while ($rgSentinel -and $confirmationrgSentinel -ne 'y' -and $confirmationrgSentinel -ne 'n') {
            $confirmationrgSentinel = Read-Host "Please confirm $rgSentinel is the correct Resource group name to be used for Sentinel resources [Y/N] "
        }
        if ($confirmationrgSentinel -eq 'y') {
            try { $rgSentinelInfo = Get-AzResourceGroup -Name $rgSentinel -ErrorAction Stop }
            catch {
                $ErrorMessage = $_.Exception.Message
                if ($ErrorMessage -like '*Provided resource group does not exist*') {
                    $SentinelRgExists = $false
                }
                else {
                    Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating Sentinel resource group name."
                    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage 
                } 
            }
            if ($rgSentinelInfo) {
                $SentinelRgExists = $true
                $confirmationrgSentinel = $null
                while ($confirmationrgSentinel -ne 'y' -and $confirmationrgSentinel -ne 'n') {
                    Write-Host
                    Write-Log -Sev 2 -Line (__LINE__) -Msg "A Resource group with the same name was found in the tenant."
                    Write-Host
                    $confirmationrgSentinel = Read-Host "Do you want to use this resource group : $rgSentinel ? [Y/N] "
                }
                if ($confirmationrgSentinel -eq 'n') {
                    $confirmationrgSentinel = $null
                    $rgSentinel = $null
                    $compareValue = 100
                }
                else {
                    Write-Host
                    Write-Log -Sev 1 -Line (__LINE__) -Msg "Resource group $rgSentinel found in the", $rgSentinelInfo.Location, "region."
                }
            }
            else {
                Write-Host
                Write-Log -Sev 1 -Line (__LINE__) -Msg "New Resource group $rgSentinel will be created."
                $SentinelRgExists = $false
            }
        }
        else {
            $confirmationrgSentinel = $null
            $rgSentinel = $null
            $compareValue = 100
        }
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{SentinelRgName = $rgSentinel}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Sentinel workspace name
############################################################################################################

Write-Host
$SentinelWs =  $null
$confirmationSentinelWs = $null
$compareValue = 0
while($confirmationSentinelWs -ne "y") {
    while ($null -eq $SentinelWs) {
        if ($parameterCount -gt $compareValue) {
            try { $SentinelWs = $( $paramsObject | Select-Object -ExpandProperty "WorkspaceName" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
            }
        }
        else {
            while ($SentinelWs.length -lt 4 -or $SentinelWs.length -gt 89) {
                Write-Host
                $SentinelWs = Read-Host 'Enter the name of the Sentinel workspace to be created '
            }
        }
        while ($SentinelWs -and $confirmationSentinelWs -ne 'y' -and $confirmationSentinelWs -ne 'n') {
            Write-Host
            $confirmationSentinelWs = Read-Host "Please confirm $SentinelWs is the correct Sentinel workspace name [Y/N] "
        }
        if ($confirmationSentinelWs -eq 'y') {
            if ($SentinelRgExists -eq $true) {
                try {
                    $SentinelWsOnboardingInfo = Get-AzSentinelOnboardingState -ResourceGroupName $rgSentinel -workspaceName $SentinelWs -ErrorAction Stop
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    if ($ErrorMessage -like '*was not found*') {
                        $sentinelWsExists = $false
                    }
                    else {
                        Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the Sentinel workspace name."
                        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage 
                    } 
                }
                if ($SentinelWsOnboardingInfo) {
                    $sentinelWsExists = $true
                    $confirmationSentinelWs = $null
                    while ($confirmationSentinelWs -ne 'y' -and $confirmationSentinelWs -ne 'n') {
                        Write-Host
                        Write-Log -Sev 2 -Line (__LINE__) -Msg "A Sentinel workspace with the same name was found in the tenant."
                        Write-Host
                        $confirmationSentinelWs = Read-Host "Do you want to use this Sentinel workspace : $SentinelWs ? [Y/N] "
                    }
                    if ($confirmationSentinelWs -eq 'n') {
                        $confirmationSentinelWs = $null
                        $SentinelWs = $null
                        $compareValue = 100
                    }
                    else {
                        Write-Host
                        Write-Log -Sev 1 -Line (__LINE__) -Msg "Sentinel workspace $SentinelWs found in the Resource group $rgSentinel."
                    }
                }
            }
            else {
                Write-Host
                Write-Log -Sev 1 -Line (__LINE__) -Msg "Sentinel workspace $SentinelWs will be created in Resource group $rgSentinel"
            }
        }
        else {
            $confirmationSentinelWs = $null
            $SentinelWs = $null
            $compareValue = 100
        }
    }
}

Write-Host
Write-Log -Msg "Sentinel Workspace details."
Write-Host
Write-Host "You can configure a daily cap and limit the daily ingestion for your workspace. This setting must be used carefully as it can result in data loss for the rest of the day once"
Write-Host "the limit is reached, impacting the log collection and detection capabilities."
Write-Host
$confirmQuota = $null
$sentinelQuotaDef = 0
while ($confirmQuota -ne 'y') {
    $confirmQuota = $null
    if (!([int]$sentinelQuota = Read-Host "Daily ingestion limit in GBs. (Integer value) [ $sentinelQuotaDef for no limit ] ")) { $sentinelQuota = $sentinelQuotaDef }
    while ($confirmQuota -ne 'y' -and $confirmQuota -ne 'n') {
        if ($sentinelQuota -ne 0) {
            Write-Host
            Write-Log -Sev 2 -Line (__LINE__) -Msg "You should use care when setting a daily cap because when data collection stops, your ability to observe and receive alerts when the health conditions of your resources will be impacted."
            Write-Log -Sev 2 -Line (__LINE__) -Msg "It can also impact other Azure services and solutions whose functionality may depend on up-to-date data being available in the workspace."
            Write-Host
            $confirmQuota = Read-Host "Are you sure you want to set a daily ingestion quota for this workspace? [Y/N] "
        }
        else { $confirmQuota = 'y' }
    }
}
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft Sentinel daily ingestion limit will be set to $sentinelQuota GBs."

Write-Host
Write-Host -NoNewline 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host
Write-Host
Write-Host "Set the default retention for all the data stored in this Sentinel workspace."
Write-Host "In addition to setting the default retention for tables in this workspace, you can configure data retention and data archive on a per-table basis on the Tables page of this workspace."
Write-Host
Write-Host 'IMPORTANT: Please note that increasing data retention over 90 days will incur in additional Azure charges ($0.10 per GB per month). ' -ForegroundColor Yellow
Write-Host
$confirmRetention = $null
$sentinelRetentionDef = 90
while ($confirmRetention -ne 'y') {
    $confirmRetention = $null
    if (!([int]$sentinelRetention = Read-Host "Data Retention in Days. (Integer value) [ Default is $sentinelRetentionDef Days ] ")) { $sentinelRetention = $sentinelRetentionDef }

    if ($sentinelWsExists) {

        $currentSetRetention = Get-AzOperationalInsightsWorkspace -Name $SentinelWs -ResourceGroupName $rgSentinel
       
        if ($currentSetRetention.retentionInDays -gt 364) { 
            Write-Host
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Current Sentinel default retention (", $currentSetRetention.retentionInDays, "days ) is larger than the value specified. Retention will not be changed."
            $keepRetention = $true
            $sentinelRetention = $currentSetRetention.retentionInDays
            $tableRetention = $currentSetRetention.retentionInDays
        }
        else {
            Write-Host
            Write-Log -Sev 1 -Line (__LINE__) -Msg "In order to maintain Alerts and Incidents records for investigations, the SecurityAlert and SecurityIncident tables retention will be set to 365 days."
            $tableRetention = 365
        }
    }

    while ($confirmRetention -ne 'y' -and $confirmRetention -ne 'n') {
        if ($sentinelRetention -gt 90) {
            Write-Host
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Once Microsoft Sentinel is enabled on your Azure Monitor Log Analytics workspace, every GB of data ingested into the workspace, excluding Basic Logs,"
            Write-Log -Sev 2 -Line (__LINE__) -Msg "can be retained at no charge for the first 90 days. Retention beyond 90 days and up to 2 years will be charged per the standard Azure Monitor pricing retention prices."
            if ($keepRetention) { $confirmRetention = 'y' }
            else {
                $confirmRetention = Read-Host "Are you sure you want to set $sentinelRetention Days retention for this workspace? [Y/N] "
            }
        }
        else { $confirmRetention = 'y' }
    }
}

if ($keepRetention) {}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft Sentinel default data retention will be set to $sentinelRetention Days."
}

$paramsObject | Add-Member -NotePropertyMembers $(@{WorkspaceName = $SentinelWs}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Integration Resource group information
#
# Resource group names only allow up to 90 characters and 
# can only include alphanumeric, underscore, parentheses, hyphen, period (except at end), 
# and Unicode characters that match the allowed characters
# 
############################################################################################################

Clear-Host
Write-Host
Write-Host 'Enter the name of the Resource group to be used for the Triage integration resources.'
Write-Host

$rgIntegration = $null
$confirmationrgIntegration = $null
$compareValue = 0
while($confirmationRgIntegration -ne "y") {
    while ($null -eq $rgIntegration) {
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
            Write-Host
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
                    Write-Host
                    Write-Log -Sev 2 -Line (__LINE__) -Msg "A Resource group with the same name was found in the tenant."
                    Write-Host
                    $confirmationRgIntegration = Read-Host "Do you want to use this resource group? [Y/N] "
                }
                if ($confirmationrgIntegration -eq 'n') {
                    $confirmationrgIntegration = $null
                    $rgIntegration = $null
                    $compareValue = 100
                }
                else {
                    Write-Host
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

$paramsObject | Add-Member -NotePropertyMembers $(@{IntegrationRgName = $rgIntegration}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Triage Service principal information
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg 'Enter the name of the Service principal to be used by Difenda Automated Triage.'

$triage = $null
$confirmationTriage = $null
$triageSpExists = $false
$compareValue = 0

while($confirmationTriage -ne 'y') {
    while ($null -eq $triage) {
        if ($parameterCount -gt $compareValue) {
            try { $triage = $( $paramsObject | Select-Object -ExpandProperty "TriageServicePrincipal" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
                $compareValue = 100
            }
        }
        else {
            Write-Host
            $triage = Read-Host 'Enter a name for the Triage Service principal to be created '
        }
    }
    while ($triage -and $confirmationTriage -ne 'y' -and $confirmationTriage -ne 'n') {
        Write-Host
        $confirmationTriage = Read-Host "Please confirm you want to use $triage as the name for the Triage Service principal [Y/N] "
    }
    if ($confirmationTriage -eq 'y') {
        try { $triageSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $triage } }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the Triage Service principal."
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        }
        if ($triageSpInfo) {

            if ($triageSpInfo.Length -gt 1) {
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Multiple Service principal found with name : $triage"
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Please correct and execute the scipt again."
                Exit
            }

            $confirmationTriage = $null
            $triageSpExists = $true
            while ($triage -and $confirmationTriage -ne 'y' -and $confirmationTriage -ne 'n') {
                Write-Host
                Write-Log -Sev 2 -Line (__LINE__) -Msg "A Service principal with the same name has been found in the tenant."
                Write-Host
                $confirmationTriage = Read-Host "Do you want to use this Service principal : $triage ? [Y/N] "
                Write-Host
            }
            if ($confirmationTriage -eq 'y') {
                Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal", $triageSpInfo.DisplayName, "( App ID:", $triageSpInfo.AppId, ")"
                $triageSpExists = $true
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

$paramsObject | Add-Member -NotePropertyMembers $(@{TriageServicePrincipal = $triage}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining Response Service principal information
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg 'Enter the name of the Service principal to be used for response and containment.'

$responseSp = $null
$confirmationResponseSp = $null
$responseSpExists = $false
$compareValue = 0

while($confirmationResponseSp -ne 'y') {
    while ($null -eq $responseSp) {
        if ($parameterCount -gt $compareValue) {
            try { $responseSp = $( $paramsObject | Select-Object -ExpandProperty "ResponseServicePrincipal" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
                $compareValue = 100
            }
        }
        else {
            Write-Host
            $responseSp = Read-Host 'Enter a name for the Response Service principal to be created '
        }
    }
    while ($responseSp -and $confirmationResponseSp -ne 'y' -and $confirmationResponseSp -ne 'n') {
        Write-Host
        $confirmationResponseSp = Read-Host "Please confirm you want to use $responseSp as the name for the Response Service principal [Y/N] "
    }
    if ($confirmationResponseSp -eq 'y') {
        try { $responseSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $responseSp } }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the Response Service principal."
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        }
        if ($responseSpInfo) {

            if ($responseSpInfo.Length -gt 1) {
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Multiple Service principal found with name : $responseSp"
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Please correct and execute the scipt again."
                Exit
            }
            $confirmationResponseSp = $null
            $responseSpExists = $true
            while ($responseSp -and $confirmationResponseSp -ne 'y' -and $confirmationResponseSp -ne 'n') {
                Write-Host
                Write-Log -Sev 2 -Line (__LINE__) -Msg "A Service principal with the same name has been found in the tenant."
                Write-Host
                $confirmationResponseSp = Read-Host "Do you want to use this Service principal : $responseSp ? [Y/N] "
                Write-Host
            }
            if ($confirmationResponseSp -eq 'y') {
                Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Service principal", $responseSpInfo.DisplayName, "( App ID:", $responseSpInfo.AppId, ")"
                $responseSpExists = $true
            }
            else {
                $confirmationResponseSp = $null
                $responseSp = $null
                $compareValue = 100
            }
        }
        else {
            $responseSpExists = $false
        }
    }
    else {
        $confirmationResponseSp = $null
        $responseSp = $null
        $compareValue = 100
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{ResponseServicePrincipal = $responseSp}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining DevOps Service principal information
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg 'Enter the name of the Service principal to be used for automated resources deployment.'

$devopsSp = $null
$confirmationDevopsSp = $null
$DevopsSpExists = $false
$compareValue = 0

while ($confirmationDevopsSp -ne 'y') {
    while ($null -eq $devopsSp) {
        if ($parameterCount -gt $compareValue) {
            try { $devopsSp = $( $paramsObject | Select-Object -ExpandProperty "DevOpsServicePrincipal" -ErrorAction Stop ) }
            catch {
                $ErrorMessage = $_.Exception.Message
                $compareValue = 100
            }
        }
        else {
            Write-Host
            $devopsSp = Read-Host 'Enter a name for the DevOps Service principal to be created '
        }
    }
    while ($devopsSp -and $confirmationDevopsSp -ne 'y' -and $confirmationDevopsSp -ne 'n') {
        Write-Host
        $confirmationDevopsSp = Read-Host "Please confirm you want to use $devopsSp as the name for the DevOps Service principal [Y/N] "
    }
    if ($confirmationDevopsSp -eq 'y') {
        try { $DevopsSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $devopsSp } }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the DevOps Service principal."
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        }
        if ($DevopsSpInfo) {

            if ($DevopsSpInfo.Length -gt 1) {
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Multiple Service principal found with name : $devopsSp"
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Please correct and execute the scipt again."
                Exit
            }
            $confirmationDevopsSp = $null
            $DevopsSpExists = $true
            while ($devopsSp -and $confirmationDevopsSp -ne 'y' -and $confirmationDevopsSp -ne 'n') {
                Write-Host
                Write-Log -Sev 2 -Line (__LINE__) -Msg "A Service principal with the same name has been found in the tenant."
                Write-Host
                $confirmationDevopsSp = Read-Host "Do you want to use this Service principal : $devopsSp ? [Y/N] "
                Write-Host
            }
            if ($confirmationDevopsSp -eq 'y') {
                Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Service principal", $DevopsSpInfo.DisplayName, "( App ID:", $DevopsSpInfo.AppId, ")"
                $DevopsSpExists = $true
            }
            else {
                $confirmationDevopsSp = $null
                $devopsSp = $null
                $compareValue = 100
            }
        }
        else {
            $DevopsSpExists = $false
        }
    }
    else {
        $confirmationDevopsSp = $null
        $devopsSp = $null
        $compareValue = 100
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{DevOpsServicePrincipal = $devopsSp}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining AVM Service principal information
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg 'Enter the information required for Difenda AVM service.'

$confirmationAvmSp = $null
$confirmationAvm = $null
$avm = $null
$compareValue = 0
$isavm = $false

if ($parameterCount -gt $compareValue) {
    try { $isavm = $( $paramsObject | Select-Object -ExpandProperty "IsAvmSubscriber" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
}
if ($isavm) {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "$company is AVM Subscriber."
    $confirmationAvm = 'y'
}
else {
    while ($confirmationAvm -ne 'y' -and $confirmationAvm -ne 'n') {
        Write-Host
        $confirmationAvm = Read-Host "Is $company subscribed to Difenda's Advanced Vulnerability Management Service? [Y/N] "
    }
    if ($confirmationAvm -eq 'y') { $isavm = $true }
    else { $isavm = $false }  
}

if ($isavm) {
    while($confirmationAvmSp -ne 'y') {
        while ($null -eq $avm) {
            if ($parameterCount -gt $compareValue) {
                try { $avm = $( $paramsObject | Select-Object -ExpandProperty "AvmServicePrincipal" -ErrorAction Stop ) }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    $compareValue = 100
                }
            }
            else {
                Write-Host
                $avm = Read-Host 'Enter a name for the AVM Service principal to be created '
            }
        }
        while ($avm -and $confirmationAvmSp -ne 'y' -and $confirmationAvmSp -ne 'n') {
            Write-Host
            $confirmationAvmSp = Read-Host "Please confirm you want to use $avm as the name for the AVM Service principal [Y/N] "
        }
        if ($confirmationAvmSp -eq 'y') {
            try { $AvmSpInfo = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $avm } }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem validating the AVM Service principal."
                Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            }
            if ($AvmSpInfo) {
                if ($AvmSpInfo.Length -gt 1) {
                    Write-Log -Sev 3 -Line (__LINE__) -Msg "Multiple Service principal found with name : $avm"
                    Write-Log -Sev 3 -Line (__LINE__) -Msg "Please correct and execute the scipt again."
                    Exit
                }
                $confirmationAvmSp = $null
                $avmSpExists = $true
                while ($avm -and $confirmationAvmSp -ne 'y' -and $confirmationAvmSp -ne 'n') {
                    Write-Host
                    Write-Log -Sev 2 -Line (__LINE__) -Msg "A Service principal with the same name has been found in the tenant."
                    Write-Host
                    $confirmationAvmSp = Read-Host "Do you want to use this Service principal : $avm ? [Y/N] "
                    Write-Host
                }
                if ($confirmationAvmSp -eq 'y') {
                    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal", $AvmSpInfo.DisplayName, "( App ID:", $AvmSpInfo.AppId, ")"
                    $avmSpExists = $true
                }
                else {
                    $confirmationAvmSp = $null
                    $avm = $null
                    $compareValue = 100
                }
            }
            else {
                $avmSpExists = $false
            }
        }
        else {
            $confirmationAvmSp = $null
            $avm = $null
            $compareValue = 100
        }
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{IsAvmSubscriber = $isavm}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{AvmServicePrincipal = $avm}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining informatio for OT customers
############################################################################################################

Clear-Host
Write-Host
Write-Log -Msg 'Enter the information required for Difenda MXDR for OT service.'

$confirmationOt = $null
$compareValue = 0
$isOt = $false

if ($parameterCount -gt $compareValue) {
    try { $isOt = $( $paramsObject | Select-Object -ExpandProperty "IsOtSubscriber" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
}
if ($isOt) {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "$company is MXDR for OT Subscriber."
    $confirmationOt = 'y'
}
else {
    while ($confirmationOt -ne 'y' -and $confirmationOt -ne 'n') {
        Write-Host
        $confirmationOt = Read-Host "Is $company subscribed to Difenda's MXDR for OT Service? [Y/N] "
    }
    if ($confirmationOt -eq 'y') { $isOt = $true }
    else { $isOt = $false }  
}

if ($isOt) {
    $OtSubscriptionId = $null
    $confirmationOtSubs = $null
    $compareValue = 0
    while ($confirmationOtSubs -ne 'y') {
        while ($null -eq $OtSubscriptionId) {
            if ($parameterCount -gt $compareValue) {
                try { $OtSubscriptionId = $( $paramsObject | Select-Object -ExpandProperty "OtSubscriptionId" -ErrorAction Stop ) }
                catch {
                    $ErrorMessage = $_.Exception.Message
                }
            }
            if (-not $OtSubscriptionId) {
                while ($OtSubscriptionId.length -ne 36) {
                    $OtSubscriptionId = Read-Host 'Enter the Subscription ID where Microsoft Defendere for IoT is enabled '
                    if ($OtSubscriptionId -match '^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$') {}
                    else {
                        Write-Log -Sev 2 -Line $(__LINE__) -Msg "Invalid Subscription ID format."
                        $OtSubscriptionId = $null
                    }
                }
            }
            while ($confirmationOtSubs -ne 'y' -and $confirmationOtSubs -ne 'n') {
                Write-Host
                $confirmationOtSubs = Read-Host "Please confirm $OtSubscriptionId is the correct Subscription ID [Y/N] "
            }
            if ($confirmationOtSubs -eq 'y') {
                try { $OtSubscriptionInfo = Get-AzSubscription -SubscriptionId $OtSubscriptionId -ErrorAction Stop }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Log -Sev 3 -Line (__LINE__) -Msg "There was a problem obtaining Subscription information."
                    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
                    $confirmationOtSubs = $null
                    $OtSubscriptionId = $null
                    $compareValue = 100
                }
                if ($OtSubscriptionInfo) {
                    Write-Host
                    Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:", $OtSubscriptionInfo.Name, "(ID:", $OtSubscriptionInfo.Id, ") - Status:", $OtSubscriptionInfo.State
                }
            }
            else {
                $confirmationOtSubs = $null
                $OtSubscriptionId = $null
                $compareValue = 100
            }
        }
    }

    $OtSubscriptionInfoObject = @{
        Name = $OtSubscriptionInfo.Name
        Id = $OtSubscriptionInfo.Id
        TenantId = $OtSubscriptionInfo.TenantId
        State = $OtSubscriptionInfo.State
    }

    $paramsObject | Add-Member -NotePropertyMembers $(@{OtSubscriptionId = $OtSubscriptionInfo.Id}) -Force
    $paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath
}

$paramsObject | Add-Member -NotePropertyMembers $(@{IsOtSubscriber = $isOt}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Set Azure AD Groups to be created
#   - CompanyName - IT Security Team
#   - CompanyName - High Priority Alert Group
#   - CompanyName - No Alert Group
#   - DifendaMXDR_SecOps
############################################################################################################

$groupSso1 = $company + " - IT Security Team"
$groupSso2 = $company + " - High Priority Alert Group"
$groupSso3 = $company + " - No Alert Group"
$groupSecOps = "DifendaMXDR_SecOps"

$paramsObject | Add-Member -NotePropertyMembers $(@{ItSecurityGroup = $groupSso1}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{HpiAlertsGroup = $groupSso2}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{NoAlertsGroup = $groupSso3}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Set Key vault name (To be created in Sentinel Resource group)
############################################################################################################

# Clear-Host
# Write-Host
# Write-Log -Msg "Additional resources"
# Write-Host
# Write-Host "The following additional supporting resources will be created in the tenant."
# Write-Host
# $KeyVaultName = $null

# if ($parameterCount -gt $compareValue) {
#     try { $KeyVaultName = $( $paramsObject | Select-Object -ExpandProperty "KeyVaultName" -ErrorAction Stop ) }
#     catch {
#         $ErrorMessage = $_.Exception.Message
#     }
# }

# if ($KeyVaultName) {
#     Write-Host "   1. A Key Vault with the name $KeyVaultName will be created in the Sentinel Resource group $rgSentinel."
# }
# else {
#     $TokenSet = @{
#         U = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
#         L = [Char[]]'abcdefghijklmnopqrstuvwxyz'
#         N = [Char[]]'0123456789'
#     }
    
#     $Upper = Get-Random -Count 5 -InputObject $TokenSet.U
#     $Lower = Get-Random -Count 5 -InputObject $TokenSet.L
#     $Number = Get-Random -Count 5 -InputObject $TokenSet.N
    
#     $StringSet = $Upper + $Lower + $Number
#     $Sufix = (Get-Random -Count 21 -InputObject $StringSet) -join ''
#     $KeyVaultName = "kv-" + $Sufix
#     Write-Host "   1. A Key Vault with the name $KeyVaultName will be created in the Sentinel Resource group $rgSentinel."
# }

# $paramsObject | Add-Member -NotePropertyMembers $(@{KeyVaultName = $KeyVaultName}) -Force
# $paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

############################################################################################################
# Set User Assigned Managed Identity name (To be created in Sentinel Resource group)
############################################################################################################

# $UamiName = $null
# Write-Host

# if ($parameterCount -gt $compareValue) {
#     try { $UamiName = $( $paramsObject | Select-Object -ExpandProperty "ManagedIdentityName" -ErrorAction Stop ) }
#     catch {
#         $ErrorMessage = $_.Exception.Message
#     }
# }

# if ($UamiName) {
#     Write-Host "   2. A User Assigned Managed Identity with the name $UamiName will be created in the Sentinel Resource group $rgSentinel."
# }
# else {
#     $UamiName = "uai-" + $Sufix
#     Write-Host "   2. A User Assigned Managed Identity with the name $UamiName will be created in the Sentinel Resource group $rgSentinel."
# }

# $paramsObject | Add-Member -NotePropertyMembers $(@{ManagedIdentityName = $UamiName}) -Force
# $paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

# Write-Host
# Write-Host -NoNewLine 'Press [Enter] to continue ...'
# $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining encryption Key
############################################################################################################

Clear-Host
Write-Host "Please enter the encryption key that will be provided by Difenda."
Write-Host

$compareValue = 0

$myBase64key = $null

if ($parameterCount -gt $compareValue) {
    try { $myBase64key = $( $paramsObject | Select-Object -ExpandProperty "EncryptionKey" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
}

if ($myBase64key) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Encryption key previously provided will be used."
}
else {
    while ($null -eq $myBase64key) {
        $myBase64key = Read-Host "Enter encryption key provided by Difenda " -MaskInput
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{EncryptionKey = $myBase64key}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# C3 Engineer Email
############################################################################################################

$c3Email = $null
$c3EmailConfirmation = $null
$compareValue =0

Write-Host

if ($parameterCount -gt $compareValue) {
    try { $c3Email = $( $paramsObject | Select-Object -ExpandProperty "DifendaEngineer" -ErrorAction Stop ) }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
}

if ($c3Email) {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Email address $c3Email was previously provided."
}
else {
    while ( $c3EmailConfirmation -ne 'y' ) {
        Write-Host
        $c3Email = Read-Host "Enter the email address of your Difenda C3 Engineer "
        while ($c3EmailConfirmation -ne 'y' -and $c3EmailConfirmation -ne 'n') {
            Write-Host
            $c3EmailConfirmation = Read-Host 'Please confirm the email provided is correct [Y/N] '
        }
        if ($c3EmailConfirmation -eq 'y') {}
        else {
            $c3Email = $null
            $c3EmailConfirmation = $null
        }
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{DifendaEngineer = $c3Email}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Obtaining information for Lighthouse delegations
############################################################################################################

Clear-Host
Write-Log -Msg "Enter the following information for the Lighthouse delegation as provided by Difenda :"
Write-Host

$DifendaTenantId = $null
$ContributorGroupId = $null
$L1GroupId = $null
$L2GroupId = $null
$ReaderGroupId = $null
$lhConfirmation = $null

if ($parameterCount -gt $compareValue) {
    try { $DifendaTenantId = $( $paramsObject | Select-Object -ExpandProperty "DifendaTenantId" -ErrorAction Stop ) }
    catch {}
    try { $ContributorGroupId = $( $paramsObject | Select-Object -ExpandProperty "ContributorGroupId" -ErrorAction Stop ) }
    catch {}
    try { $L1GroupId = $( $paramsObject | Select-Object -ExpandProperty "L1GroupId" -ErrorAction Stop ) }
    catch {}
    try { $L2GroupId = $( $paramsObject | Select-Object -ExpandProperty "L2GroupId" -ErrorAction Stop ) }
    catch {}
    try { $ReaderGroupId = $( $paramsObject | Select-Object -ExpandProperty "ReaderGroupId" -ErrorAction Stop ) }
    catch {}
}

while ($null -eq $lhConfirmation) {
    if ($DifendaTenantId) { Write-Host "Difenda Tenant Id            :" $DifendaTenantId }
    else {
        while($null -eq $DifendaTenantId) {
            $DifendaTenantId = Read-Host "Enter Difenda Tenant Id       "
        }
    }
    Write-Host
    if ($ContributorGroupId) { Write-Host "Contributor Group Id         :" $ContributorGroupId }
    else {
        while ($null -eq $ContributorGroupId) {
            $ContributorGroupId = Read-Host "Enter Contributor group Id    "
        }
    }
    if ($L1GroupId) { Write-Host "L1 Group Id                  :" $L1GroupId }
    else {
        while ($null -eq $L1GroupId) {
            $L1GroupId = Read-Host "Enter Difenda L1 group Id     "
        }
    }
    if ($L2GroupId) { Write-Host "L2 Group Id                  :" $L2GroupId }
    else {
        while ($null -eq $L2GroupId) {
            $L2GroupId = Read-Host "Enter Difenda L2 group Id     "
        }
    }
    if ($ReaderGroupId) { Write-Host "Reader Group Id              :" $ReaderGroupId }
    else {
        while ($null -eq $ReaderGroupId) {
            $ReaderGroupId = Read-Host "Enter Difenda Reader group Id "
        }
    }
    Write-Host
    while ($lhConfirmation -ne 'y' -and $lhConfirmation -ne 'n') {
        $lhConfirmation = Read-Host "Is this information correct? [Y/N] "
        if ($lhConfirmation -eq 'n') {
            $DifendaTenantId = $null
            $ContributorGroupId = $null
            $L1GroupId = $null
            $L2GroupId = $null
            $ReaderGroupId = $null
            Write-Host
        }
    }
    if ($lhConfirmation -eq 'n') {
        $lhConfirmation = $null
    }
}

$paramsObject | Add-Member -NotePropertyMembers $(@{DifendaTenantId = $DifendaTenantId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{ContributorGroupId = $ContributorGroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{L1GroupId = $L1GroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{L2GroupId = $L2GroupId}) -Force
$paramsObject | Add-Member -NotePropertyMembers $(@{ReaderGroupId = $ReaderGroupId}) -Force
$paramsObject | ConvertTo-Json -Depth 100 | Out-File $paramsFilePath

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Information summary
############################################################################################################

Clear-Host
Write-Log -Msg "The following provided informationt has been validated and will be used by the script:"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Company name                            : $company"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure Subscription (MXDR for IT)        :", $subscriptionInfo.Name, "(", $subscriptionInfo.Id, ")"
if ($isOt) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure Subscription (MXDR for OT)        :", $OtSubscriptionInfo.Name, "(", $OtSubscriptionInfo.Id, ")"
}
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Microsoft Sentinel Resource group name  : $rgSentinel (Resource group exists: $sentinelRgExists)"
Write-Log -Sev 1 -Line $(__LINE__) -msg "Microsoft Sentinel workspace name       : $SentinelWs"
Write-Log -Sev 1 -Line $(__LINE__) -msg "Microsoft Sentinel daily ingest quota   : $sentinelQuota GBs"
Write-Log -Sev 1 -Line $(__LINE__) -msg "Microsoft Sentinel data retention       : $sentinelRetention Days"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Integration Resource group name         : $rgIntegration (Resource group exists: $integrationRgExists)"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Triage Service principal name           : $triage (Service principal exists: $triageSpExists)"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Response Service principal name         : $responseSp (Service principal exists: $responseSpExists)"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "DevOps Service principal name           : $devopsSp (Service principal exists: $devopsSpExists)"
if ($isavm) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "AVM Service principal name              : $avm (Service principal exists: $avmSpExists)"
}
if ($locationDisplayName) {
    $resourcesLocation = $locationDisplayName, "(", $location, ")"
}
else {
    $resourcesLocation = $location
}
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure region location for all resources : $resourcesLocation"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Difenda Tenant Id                       : $DifendaTenantId"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Contributor Group Id                    : $ContributorGroupId"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "L1 Group Id                             : $L1GroupId"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "L2 Group Id                             : $L2GroupId"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Reader Group Id                         : $ReaderGroupId"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "AAD Group for Regular notifications     : $groupSso1"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "AAD Group for HPI notifications         : $groupSso2"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "AAD Group for No notifications          : $groupSso3"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "AAD Group for SecOps Access             : $groupSecOps"
# Write-Host
# Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure Key Vault name                    : $KeyVaultName"
# Write-Log -Sev 1 -Line $(__LINE__) -Msg "User Assigned Managed Identity          : $UamiName"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Difenda Engineer email address          : $c3Email"
Write-Host

Write-Host "We have collected all the information to be used by the script."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

############################################################################################################
# Setting parameters for the creation of Service principals
############################################################################################################

$startDate = Get-Date
$endDate = $startDate.AddYears(3)

###########################################################################################################
# Check and install pre-requisites
###########################################################################################################

Clear-Host
Write-Host "This next section of the script will validate the PowerShell environment and install any modules that are required."
Write-Host

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

Write-Log -Msg "PowerShell module Az.ManagementPartner"
if ($(Get-Module -Name Az.ManagementPartner).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.ManagementPartner. Current version ->", $(Get-Module -Name Az.ManagementPartner).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.ManagementPartner."
    Install-Module -Name Az.ManagementPartner -Scope CurrentUser -Force
    Import-Module -Name Az.ManagementPartner -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.ManagementPartner. Version ->", $(Get-Module -Name Az.ManagementPartner).Version
}

Write-Log -Msg "PowerShell module Az.ManagedServiceIdentity"
if ($(Get-Module -Name Az.ManagedServiceIdentity).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.ManagedServiceIdentity. Current version ->", $(Get-Module -Name Az.ManagedServiceIdentity).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.ManagedServiceIdentity."
    Install-Module -Name Az.ManagedServiceIdentity -Scope CurrentUser -Force
    Import-Module -Name Az.ManagedServiceIdentity -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.ManagedServiceIdentity. Version ->", $(Get-Module -Name Az.ManagedServiceIdentity).Version
}

Write-Log -Msg "PowerShell module Az.KeyVault"
if ($(Get-Module -Name Az.KeyVault).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.KeyVault. Current version ->", $(Get-Module -Name Az.KeyVault).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.KeyVault."
    Install-Module -Name Az.KeyVault -Scope CurrentUser -Force
    Import-Module -Name Az.KeyVault -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.KeyVault.", $(Get-Module -Name Az.KeyVault).Version
}

Write-Log -Msg "PowerShell module Az.SecurityInsights"
if ($(Get-Module -Name Az.SecurityInsights).Version) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "PowerShell module Az.SecurityInsights. Current version ->", $(Get-Module -Name Az.SecurityInsights).Version
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installing PowerShell module Az.SecurityInsights."
    Install-Module -Name Az.SecurityInsights -Scope CurrentUser -Force
    Import-Module -Name Az.SecurityInsights -ErrorAction SilentlyContinue
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.SecurityInsights.", $(Get-Module -Name Az.SecurityInsights).Version
}

Write-Log -Msg "Pre-requisites validation complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

##########################################################################
# ManagedIdentity provider validation/registration
##########################################################################

Clear-Host
Write-Log -Msg "ManagedIdentity provider validation/registration"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if ManagedIdentity provider is registered. If not, will try to register."
Write-Host
$azResourceProvider = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedIdentity
$providersCount = $azResourceProvider.Count - 1
$register = $false

foreach ($i in 0..$providersCount) {
    $resourceType1 = $azResourceProvider[$i].ResourceTypes.ResourceTypeName
    $registrationState1 = $azResourceProvider[$i].RegistrationState
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType1, " (", $registrationState1, ")"
    if ($registrationState1 -eq "NotRegistered" -or $registrationState1 -eq "Unregistered") {
        $register = $true
    }
}
if ($register) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide ManagedIdentity is not registered. Will try to register ..."
    try { $registrationResult = Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity -ErrorAction Stop }
    catch {
        $ErrorMessage = $_.ErrorDetails.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Something went wrong.", $registrationResult, $ErrorMessage
        break
    }
    Write-Log -Msg "Registering Provider NameSpace Microsoft.ManagedIdentity."
    Start-Sleep -Seconds 5
    $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedIdentity
    foreach ($i in 0..$providersCount) {
        $registrationState2 = $azResourceProvider2[$i].RegistrationState
        if ($registrationState2 -eq "Registering") {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Registration in progress. Pausing for 5 seconds to validate again."
            $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedIdentity
            Start-Sleep -Seconds 5
            $foreach.Reset()
        }
    }
    Write-Log -Msg "Registration complete."
    $azResourceProvider3 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedIdentity
    foreach ($i in 0..$providersCount) {
        $resourceType3 = $azResourceProvider3[$i].ResourceTypes.ResourceTypeName
        $registrationState3 = $azResourceProvider3[$i].RegistrationState
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType3, " (", $registrationState3, ")"
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide ManagedIdentity already registered."
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "ManagedIdentity provider registration complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

##########################################################################
# ManagedService provider validation/registration
##########################################################################

Clear-Host
Write-Log -Msg "ManagedService provider validation/registration"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if ManagedService provider is registered. If not, will try to register."
Write-Host
$azResourceProvider = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedServices
$providersCount = $azResourceProvider.Count - 1
$register = $false

foreach ($i in 0..$providersCount) {
    $resourceType1 = $azResourceProvider[$i].ResourceTypes.ResourceTypeName
    $registrationState1 = $azResourceProvider[$i].RegistrationState
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType1, " (", $registrationState1, ")"
    if ($registrationState1 -eq "NotRegistered" -or $registrationState1 -eq "Unregistered") {
        $register = $true
    }
}
if ($register) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide ManagedServices is not registered. Will try to register ..."
    try { $registrationResult = Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedServices -ErrorAction Stop }
    catch {
        $ErrorMessage = $_.ErrorDetails.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Something went wrong.", $registrationResult, $ErrorMessage
        break
    }
    Write-Log -Msg "Registering Provider NameSpace Microsoft.ManagedServices."
    Start-Sleep -Seconds 5
    $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedServices
    foreach ($i in 0..$providersCount) {
        $registrationState2 = $azResourceProvider2[$i].RegistrationState
        if ($registrationState2 -eq "Registering") {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Registration in progress. Pausing for 5 seconds to validate again."
            $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedServices
            Start-Sleep -Seconds 5
            $foreach.Reset()
        }
    }
    Write-Log -Msg "Registration complete."
    $azResourceProvider3 = Get-AzResourceProvider -ProviderNameSpace Microsoft.ManagedServices
    foreach ($i in 0..$providersCount) {
        $resourceType3 = $azResourceProvider3[$i].ResourceTypes.ResourceTypeName
        $registrationState3 = $azResourceProvider3[$i].RegistrationState
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType3, " (", $registrationState3, ")"
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide ManagedServices already registered."
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "ManagedService provider registration complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

##########################################################################
# Microsoft.Web provider validation/registration
##########################################################################

Clear-Host
Write-Log -Msg "Microsoft.Web provider validation/registration"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Microsoft.Web provider is registered. If not, will try to register."
Write-Host
$azResourceProvider = Get-AzResourceProvider -ProviderNameSpace Microsoft.Web
$providersCount = $azResourceProvider.Count - 1
$register = $false

foreach ($i in 0..$providersCount) {
    $resourceType1 = $azResourceProvider[$i].ResourceTypes.ResourceTypeName
    $registrationState1 = $azResourceProvider[$i].RegistrationState
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType1, " (", $registrationState1, ")"
    if ($registrationState1 -eq "NotRegistered" -or $registrationState1 -eq "Unregistered") {
        $register = $true
    }
}
if ($register) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide Web is not registered. Will try to register ..."
    try { $registrationResult = Register-AzResourceProvider -ProviderNamespace Microsoft.Web -ErrorAction Stop }
    catch {
        $ErrorMessage = $_.ErrorDetails.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Something went wrong.", $registrationResult, $ErrorMessage
        break
    }
    Write-Log -Msg "Registering Provider NameSpace Microsoft.Web."
    Start-Sleep -Seconds 5
    $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Web
    foreach ($i in 0..$providersCount) {
        $registrationState2 = $azResourceProvider2[$i].RegistrationState
        if ($registrationState2 -eq "Registering") {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Registration in progress. Pausing for 5 seconds to validate again."
            $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Web
            Start-Sleep -Seconds 5
            $foreach.Reset()
        }
    }
    Write-Log -Msg "Registration complete."
    $azResourceProvider3 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Web
    foreach ($i in 0..$providersCount) {
        $resourceType3 = $azResourceProvider3[$i].ResourceTypes.ResourceTypeName
        $registrationState3 = $azResourceProvider3[$i].RegistrationState
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType3, " (", $registrationState3, ")"
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide Microsoft.Web already registered."
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft.Web provider registration complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

##########################################################################
# Microsoft.Logic provider validation/registration
##########################################################################

Clear-Host
Write-Log -Msg "Microsoft.Logic provider validation/registration"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Microsoft.Logic provider is registered. If not, will try to register."
Write-Host
$azResourceProvider = Get-AzResourceProvider -ProviderNameSpace Microsoft.Logic
$providersCount = $azResourceProvider.Count - 1
$register = $false

foreach ($i in 0..$providersCount) {
    $resourceType1 = $azResourceProvider[$i].ResourceTypes.ResourceTypeName
    $registrationState1 = $azResourceProvider[$i].RegistrationState
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType1, " (", $registrationState1, ")"
    if ($registrationState1 -eq "NotRegistered" -or $registrationState1 -eq "Unregistered") {
        $register = $true
    }
}
if ($register) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provide Logic is not registered. Will try to register ..."
    try { $registrationResult = Register-AzResourceProvider -ProviderNamespace Microsoft.Logic -ErrorAction Stop }
    catch {
        $ErrorMessage = $_.ErrorDetails.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Something went wrong.", $registrationResult, $ErrorMessage
        break
    }
    Write-Log -Msg "Registering Provider NameSpace Microsoft.Logic."
    Start-Sleep -Seconds 5
    $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Logic
    foreach ($i in 0..$providersCount) {
        $registrationState2 = $azResourceProvider2[$i].RegistrationState
        if ($registrationState2 -eq "Registering") {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Registration in progress. Pausing for 5 seconds to validate again."
            $azResourceProvider2 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Logic
            Start-Sleep -Seconds 5
            $foreach.Reset()
        }
    }
    Write-Log -Msg "Registration complete."
    $azResourceProvider3 = Get-AzResourceProvider -ProviderNameSpace Microsoft.Logic
    foreach ($i in 0..$providersCount) {
        $resourceType3 = $azResourceProvider3[$i].ResourceTypes.ResourceTypeName
        $registrationState3 = $azResourceProvider3[$i].RegistrationState
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Provider Namespace:", $resourceType3, " (", $registrationState3, ")"
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure provider Microsoft.Logic already registered."
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft.Logic provider registration complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Setting up Management partner
#########################################################################

Clear-Host
Write-Log -Msg "Setting up Partner Id"
Write-Host
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Obtaining existing management partner information"
Write-Host
try { $partner = Get-AzManagementPartner -ErrorAction Stop}
catch {
    if ($_) {
        Write-Log -Sev 2 -Line $(__LINE__) -Msg "No management partner information found"
    }
}
if ($partner) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Management partner already assigned"
    if ($partner.PartnerId -eq '4914876') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg $partner.PartnerName, "(", $partner.PartnerId, ")"
    }
    else {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Partner ID was ->", $partner.PartnerName, "(", $partner.PartnerId, ")"
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Updating Partner ID"
        $partner = Update-AzManagementPartner -PartnerId '4914876'
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Management partner updated. New partner ->", $partner.PartnerName, "(", $partner.PartnerId, ")"
    }
}
else {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Assigning management partner"
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Assigning Partner ID"
    $partner = New-AzManagementPartner -PartnerId '4914876'
    if ($partner.State -eq 'Active') { 
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Assigned partner ID ->", $partner.PartnerName, "(", $partner.PartnerId, ")"
    }
    else {
        Write-Log -Sev 2 -Line $(__LINE__) -Msg "Failed assigning Partner ID"
    }
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Management partner setup complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Creation of Sentinel Resource group
#########################################################################

Clear-Host
Write-Host
Write-Log -Msg "Set up Sentinel Resource group for Difenda MXDR resource ..."
Write-Host

if ($sentinelRgExists) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The Sentinel resource group already exists. Nothing to do."
    $newSentinelRg = $rgSentinelInfo
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Sentinel Resource group", $rgSentinel, "in the Subscription", $azContext.Subscription.Name, "..."
    Write-Host
    try {
        $newSentinelRg = New-AzResourceGroup -Name $rgSentinel -Location $location
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating Sentinel Resource group."
        Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Start-Sleep -Seconds 5
    if ($newSentinelRg) {
        Write-Host "Resource group name :" $newSentinelRg.ResourceGroupName
        Write-Host "Location            :" $newSentinelRg.Location
        Write-Host "Provisioning state  :" $newSentinelRg.ProvisioningState
        Write-Host "Resource ID         :" $newSentinelRg.ResourceId
        Write-Host
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Error creating Sentinel Resource group."
        Exit
    }
}

$sentinelRgObject = @{
    ResourceGroupName = $newSentinelRg.ResourceGroupName
    Location = $newSentinelRg.Location
    ProvisioningState = $newSentinelRg.ProvisioningState
    ResourceId = $newSentinelRg.ResourceId
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft Sentinel Resource group set-up complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Creation of Sentinel workspace
#########################################################################

try {
    $downloadSentinelArmTemplate = Invoke-WebRequest https://raw.githubusercontent.com/Difenda/MDR-Onboard/main/Scripts/MxdrTemplates/sentinelArmTemplate.json -OutFile ./sentinelArmTemplate.json -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed downloading Sentinel ARM template"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($downloadSentinelArmTemplate) { Write-Log -Sev 1 -Line (__LINE__) -Msg "Download complete." }

Write-Host
Write-Log -Msg "Executing Microsoft Sentinel ARM template ..."
Write-Host

if ($SentinelRgExists) { $SentinelWsAction = "Update" }
else { $SentinelWsAction = "Create" }

$sentinelArmTemplateParams = @{
    workspaceName = $SentinelWs;
    pricingTier = 'PerGB2018';
    dailyQuota = $sentinelQuota;
    dataRetention = $sentinelRetention;
    tableRetention = $tableRetention;
    immediatePurgeDataOn30Days = $false;
    location = $rgSentinel.Location;
    subscriptionId = $azContext.Subscription.Id
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "$SentinelWsAction Microsoft Sentinel workspace $SentinelWs in the resource group $rgSentinel"
if (Test-Path -Path ./sentinelArmTemplate.json -PathType Leaf) {
    try {
        $newSentinelArmTemplate = New-AzResourceGroupDeployment -ResourceGroupName $newSentinelRg.ResourceGroupName -TemplateFile ./sentinelArmTemplate.json -TemplateParameterObject $sentinelArmTemplateParams -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed Microsoft Sentinel workspace."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft Sentinel workspace $SentinelWs $SentinelWsAction successful."
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Sentinel ARM template file not found."
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Collecting information for Sentinel workspace $SentinelWs ..."
Start-Sleep -Seconds 15
try {
    $workspaceDetails = Get-AzOperationalInsightsWorkspace -Name $SentinelWs -ResourceGroupName $newSentinelRg.ResourceGroupName -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed to retrieve Sentinel workspace details for $SentinelWs."
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

try {
    $workspaceKeys = Get-AzOperationalInsightsWorkspaceSharedKey -Name $SentinelWs -ResourceGroupName $newSentinelRg.ResourceGroupName -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed to retrieve Sentinel workspace details for $SentinelWs."
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

$sentinelWsObject = @{
    ResourceGroupName = $newSentinelArmTemplate.ResourceGroupName
    ProvisioningState = $newSentinelArmTemplate.ProvisioningState
    WorkspaceName = $newSentinelArmTemplate.Parameters.workspaceName.Value
    Location = $newSentinelArmTemplate.Parameters.location.Value
    PricingTier = $newSentinelArmTemplate.Parameters.pricingTier.Value
    DataRetention = $newSentinelArmTemplate.Parameters.dataRetention.Value
    WorkspaceId = $workspaceDetails.CustomerId
    WorkspacePrimaryKey = $workspaceKeys.PrimarySharedKey
}

Start-Sleep -Seconds 10
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Microsoft Sentinel workspace $SentinelWsAction complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Integration Resource group
#########################################################################

Clear-Host
Write-Host
Write-Log -Msg "Set up Integration Resource group for Difenda MXDR resource ..."
Write-Host

if ($integrationRgExists) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The Integration resource group already exists. Nothing to do."
    $newIntegrationRg = $rgIntegrationInfo
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
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Error creating Integration Resource group."
        Exit
    }
}

$integrationRgObject = @{
    ResourceGroupName = $newIntegrationRg.ResourceGroupName
    Location = $newIntegrationRg.Location
    ProvisioningState = $newIntegrationRg.ProvisioningState
    ResourceId = $newIntegrationRg.ResourceId
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Integration Resource group creation complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Triage service principal section
##########################################################################

Clear-Host
Write-Log -Msg "Difenda Triage engine service principal section"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service Triage principal name:", $triage
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for Difenda Triage service principal"

#---------------------------------------------------------------------------------------------------------------------------------------------------------------
# Required permissions in Microsoft Defender for Endpoint API (WindowsDefenderATP - Microsoft Threat and Vulnerability Management to Difenda Shield integration)
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
$mdeTriagePermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role" # AdvancedQuery.Read.All
$mdeTriagePermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role" # Machine.Read.All
$mdeTriagePermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "41269fc5-d04d-4bfd-bce7-43a51cea049a","Role" # Vulnerability.Read.All
$mdeTriagePermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "15405ab2-2103-4a3c-ad80-e829841cedcc","Role" # Machine.CollectForensics

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
$mdeTriageRequiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$mdeTriageRequiredResourceAccess.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$mdeTriageRequiredResourceAccess.ResourceAccess = $mdeTriagePermission1, $mdeTriagePermission2, $mdeTriagePermission3, $mdeTriagePermission4

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
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Sp exists : $triageSpExists" 
if ($triageSpExists) {
    $newTriage = $triageSpInfo
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Triage Serviceprincipal", $newTriage.DisplayName, "exists and will be used."
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning required permissions ..."
    try {
        $newTriageSp = Get-AzADServicePrincipal -DisplayName $triage -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining Triage service principal information"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Triage integration service principal"
    try {
        $newTriageSp = New-AzADServicePrincipal -Scope /subscriptions/$subscriptionId/resourceGroups/$rgSentinel -DisplayName $triage -Role Reader -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Triage service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Start-Sleep -Seconds 30
    try {
        $newTriage = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $triage }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining Triage service principal details"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

if ($newTriage) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning API permissions ..."
    try {
        Set-AzureADApplication -ObjectId $newTriage.ObjectId -RequiredResourceAccess $mdeTriageRequiredResourceAccess, $mtpTriageRequiredResourceAccess, $alaTriageRequiredResourceAccess, $msgTriageRequiredResourceAccess, $mdcaTriageRequiredResourceAccess
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
while($triageSpKeyConfirm -ne 'y' -and $triageSpKeyConfirm -ne 'n') {
    Write-Host
    $triageSpKeyConfirm = Read-Host "Do you want to create a new secret for this Service principal? [Y/N] "
}
if ($triageSpKeyConfirm -eq 'y') {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for Triage service principal"
    Start-Sleep -Seconds 5
    try {
        $triageSecret = New-AzureADApplicationPasswordCredential -ObjectId $newTriage.ObjectId -CustomKeyIdentifier "MXDR Triage Integration" -StartDate $startDate -EndDate $endDate
    }
    catch {
        
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for Triage service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

if ($triageSpKeyConfirm -eq 'y') {
    $triageSecretStartDate = $triageSecret.StartDate
    $triageSecretEndDate = $triageSecret.EndDate
    $triageSecretValue = $triageSecret.Value
}
else {
    $triageSecretStartDate = "Null"
    $triageSecretEndDate = "Null"
    $triageSecretValue = "Null"
}

Write-Log -Msg "Difenda Triage service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal name: ", $newTriage.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Object Id:              ", $newTriage.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Application Id:         ", $newTriage.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Tenant Id:              ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Subscription name:      ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret start date:      ", $triageSecretStartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret end date:        ", $triageSecretEndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Secret value:           ", $triageSecretValue

$triageSpInfoObject = @{
    DisplayName = $newTriage.DisplayName
    ObjectId = $newTriage.ObjectId
    AppId = $newTriage.AppId
    TenantId = $azContext.Subscription.TenantId
    SubscriptionId = $azContext.Subscription.Id
    SubscriptionName = $azContext.Subscription.Name
    SecretStart  = $triageSecretStartDate
    SecretEnds = $triageSecretEndDate
    SecretValue = $triageSecretValue
}

if ($isOt) {
    $subScope = "/subscriptions/" + $OtSubscriptionInfo.Id
    $targetRole = "Security Reader"
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The MXDR for OT service required additional permissions to be assigned to the Triage Service principal."
    Write-Log -Msg "Validating Azure role assignment for the Triage Service principal on the subscription", $OtSubscriptionInfo.Name, "(ID:", $OtSubscriptionInfo.Id, ") ..."
    try {
        $currentTriageAssignment = Get-AzroleAssignment -ObjectId $newTriageSp.Id -Scope $subScope -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 2 -Line (__LINE__) -Msg "Error obtaining current role assignment for the Triage Service principal"
        Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    if ($currentTriageAssignment) {
        $isSecReader = $false
        For ($i=0; $i -lt $currentTriageAssignment.Count; $i++) {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Current Azure role assignment : ", $currentTriageAssignment[$i].RoleDefinitionName
            if ($currentTriageAssignment[$i].RoleDefinitionName -eq $targetRole) {
                $isSecReader = $true
            }
        }
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "No current assignments found."
    }

    if ($isSecReader) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal", $newTriage.DisplayName, "already has the", $targetRole, "role assignment on", $OtSubscriptionInfo.Name, ". Nothing to do."
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure", $targetRole, "role to the Triage Service principal on", $OtSubscriptionInfo.Name, "..."
        try {
            $triageRoleAssignment = New-AzRoleAssignment -ObjectId $newTriageSp.Id -RoleDefinitionName $targetRole -Scope $subScope -ErrorAction Stop
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            if ($ErrorMessage -like "*Conflict*") {
                Write-Log -Sev 2 -Line (__LINE__) -Msg "Conflict creating Azure role assignment. Role may be already assigned."
                Exit
            }
            else {
                Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating role assignment for the Triage Service principal"
                Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
                Exit
            }
        }
    }

}



Write-Log -Sev 1 -Line (__LINE__) -Msg "Triage Service principal setup complete."

Write-Log -Msg "Please grant Admin consent"
Write-Host "   1. Open a new browser tab and connect to your Azure tenant as a Global Administrator."
Write-Host "   2. Select Azure Active Directory."
Write-Host "   3. Select 'App registrations', then 'All applications'."
Write-Host "   4. Search for", $newTriage.DisplayName, "then select the App registration."
Write-Host "   5. Select 'API permissions'."
Write-Host "   6. Review the permissions configured and click on 'Grant admin consent for", $azTenant.Name, "'."
Write-Host "   7. and confirm 'Yes' when prompted."

Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Clear-Host

#########################################################################
# DevOps automation service principal section
##########################################################################

Clear-Host
Write-Log -Msg "DevOps automation service principal section"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service principal name", $devopsSp

#---------------------------
# Creating service principal
#---------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Service principal exists : $DevopsSpExists" 

if ($DevopsSpExists) {
    $newDevOpsApp = $DevopsSpInfo
    try {
        $newDevOpsSp = Get-AzADServicePrincipal -DisplayName $newDevOpsApp.DisplayName
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining information for DevOps automation service principal."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 2 -Line (__LINE__) -Msg "DevOps Service principal", $newDevOpsSp.DisplayName, "exists and will be used."
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating DevOps automation service principal ..."
    try {
        $newDevOpsSp = New-AzADServicePrincipal -Scope /subscriptions/$subscription/resourceGroups/$rgSentinel -DisplayName $devopsSp -Role Contributor -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating DevOps automation service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Start-Sleep -Seconds 30
    try {
        $newDevOpsApp = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $devopsSp }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining DevOps service principal details."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

if ($newDevOpsSp -and $newDevOpsApp) {
    while($devopsSpKeyConfirm -ne 'y' -and $devopsSpKeyConfirm -ne 'n') {
        Write-Host
        $devopsSpKeyConfirm = Read-Host "Do you want to create a new secret for this Service principal? [Y/N] "
    }
    if ($devopsSpKeyConfirm -eq 'y') {
        Write-Host
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for DevOps service principal"
        Start-Sleep -Seconds 5
        try {
            $devopsSecret = New-AzureADApplicationPasswordCredential -ObjectId $newDevOpsApp.ObjectId -CustomKeyIdentifier "MXDR DevOps Integration" -StartDate $startDate -EndDate $endDate
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for DevOps service principal"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }
    if ($devopsSpKeyConfirm -eq 'y') {
        $devopsSecretStartDate = $devopsSecret.StartDate
        $devopsSecretEndDate = $devopsSecret.EndDate
        $devopsSecretValue = $devopsSecret.Value
    }
    else {
        $devopsSecretStartDate = "Null"
        $devopsSecretEndDate = "Null"
        $devopsSecretValue = "Null"
    }
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating DevOps service principal. Please review the log and correct."
    Exit
}

Write-Log -Msg "DevOps service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Service principal name:", $newDevOpsSp.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Object Id:             ", $newDevOpsApp.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Application Id:        ", $newDevOpsSp.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Tenant Id:             ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Subscription Id:       ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Subscription name:     ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Secret start date:     ", $devopsSecretStartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Secret end date:       ", $devopsSecretEndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Secret value:          ", $devopsSecretValue

Write-Log -Msg "Validating Azure role assignment for the DevOps Service principal on", $newSentinelRg.ResourceGroupName, "..."
Write-Host
try {
    $currentDevOpsAssignment = Get-AzroleAssignment -ObjectId $newDevOpsSp.Id -ResourceGroupName $newSentinelRg.ResourceGroupName
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
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "No current assignments found."
}

if ($isContributor) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal", $newDevOpsSp.DisplayName, "already has the Contributor role assignment on", $newSentinelRg.ResourceGroupName, ". Nothing to do."
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure Resource group Contributor role to the DevOps Service principal on", $newSentinelRg.ResourceGroupName, "..."
    try {
        $devOpsRoleAssignment = New-AzRoleAssignment -ObjectId $newDevOpsSp.Id -RoleDefinitionName Contributor -ResourceGroupName $newSentinelRg.ResourceGroupName -ErrorAction Stop
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
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure role assignment created for DevOps Service principal with the following details :"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Scope                :", $devOpsRoleAssignment.Scope
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name         :", $devOpsRoleAssignment.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition name :", $devOpsRoleAssignment.RoleDefinitionName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition ID   :", $devOpsRoleAssignment.RoleDefinitionId
}

Write-Log -Msg "Validating Azure role assignment for the DevOps Service principal on", $newIntegrationRg.ResourceGroupName, "..."
try {
    $currentDevOpsAssignment2 = Get-AzroleAssignment -ObjectId $newDevOpsSp.Id -ResourceGroupName $newIntegrationRg.ResourceGroupName
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Error obtaining current role assignment for the DevOps Service principal"
    Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

if ($currentDevOpsAssignment2) {
    $isContributor2 = $false
    $isUserAm2 = $false
    For ($i=0; $i -lt $currentDevOpsAssignment2.Count; $i++) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Current Azure role assignment : ", $currentDevOpsAssignment2[$i].RoleDefinitionName
        if ($currentDevOpsAssignment2[$i].RoleDefinitionName -eq "Contributor") {
            $isContributor2 = $true
        }
        if ($currentDevOpsAssignment2[$i].RoleDefinitionName -eq "User Access Administrator") {
            $isUserAm2 = $true
        }
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "No current assignments found."
}
if ($isContributor2) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal", $newDevOpsSp.DisplayName, "already has the Contributor role assignment on", $newIntegrationRg.ResourceGroupName, ". Nothing to do."
}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure Resource group Contributor role to the DevOps Service principal on", $newIntegrationRg.ResourceGroupName, "..."
    try {
        $devOpsCRoleAssignment = New-AzRoleAssignment -ObjectId $newDevOpsSp.Id -RoleDefinitionName Contributor -ResourceGroupName $newIntegrationRg.ResourceGroupName -ErrorAction Stop
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
    if ($devOpsCRoleAssignment) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure role assignment created for DevOps Service principal with the following details :"
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Scope                :", $devOpsCRoleAssignment.Scope
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name         :", $devOpsCRoleAssignment.DisplayName
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition name :", $devOpsCRoleAssignment.RoleDefinitionName
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition ID   :", $devOpsCRoleAssignment.RoleDefinitionId
    }
    Write-Host
}

if ($isUserAm2) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal", $newDevOpsSp.DisplayName, "already has the User Access Administrator role assignment on", $newIntegrationRg.ResourceGroupName, ". Nothing to do."
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure Resource group User Access Administrator role to the DevOps Service principal on", $newIntegrationRg.ResourceGroupName, "..."
    try {
        $devOpsURoleAssignment = New-AzRoleAssignment -ObjectId $newDevOpsSp.Id -RoleDefinitionName 'User Access Administrator' -ResourceGroupName $newIntegrationRg.ResourceGroupName -ErrorAction Stop
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
    if ($devOpsURoleAssignment) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure role assignment created for DevOps Service principal with the following details :"
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Scope                :", $devOpsURoleAssignment.Scope
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Display name         :", $devOpsURoleAssignment.DisplayName
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition name :", $devOpsURoleAssignment.RoleDefinitionName
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Role definition ID   :", $devOpsURoleAssignment.RoleDefinitionId
    }
}

$devopsInfoObject = @{
    DisplayName = $newDevOpsSp.DisplayName
    Id = $newDevOpsSp.Id
    AppId = $newDevOpsSp.AppId
    ObjectId = $newDevOpsApp.ObjectId
    TenantId = $azContext.Subscription.TenantId
    SubscriptionId = $azContext.Subscription.Id
    SubscriptionName = $azContext.Subscription.Name
    SecretStart  = $devopsSecretStartDate
    SecretEnds = $devopsSecretEndDate
    SecretValue = $devopsSecretValue
}

Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps Service principal setup complete."
Write-Host
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

################################################################################################################################################################
# Response automation service principal section
################################################################################################################################################################

Clear-Host
Write-Log -Msg "Response automation service principal section"
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service principal name:", $responseSp
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for Response service principal"

#---------------------------------------------------------------------------------------------------------------------------------------------------------------
# Required permissions in Microsoft Defender for Endpoint API (Isolate/Unisolate/EP discovery)
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
$responseAtpPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role"
$responseAtpPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7e4e1300-e1b9-4102-88ba-f0cb6e6d5974","Role"
$responseAtpPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role"
$responseAtpPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "a86d9824-b2b6-45f8-b042-16bc4922ed4e","Role"

# Building the object with the set of permissions for MDE
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
$responseAtp = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$responseAtp.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$responseAtp.ResourceAccess = $responseAtpPermission1, $responseAtpPermission2, $responseAtpPermission3, $responseAtpPermission4

#---------------------------------------------------------------------------------------------------------------------------------------------------------------
# Required permissions in Microsoft Graph API (User Enable/Disable)
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MS Graph API"
$responseMgPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "741f803b-c850-494e-b5df-cde7c675a1ca","Role"
$responseMgPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "bf394140-e372-4bf9-a898-299cfc7564e5","Role"
$responseMgPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "c529cfca-c91b-489c-af2b-d92990b66ce6","Role"
$responseMgPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "19dbc75e-c2e2-444c-a770-ec69d8559fc7","Role"

# Building the object with the set of permissions for Microsoft Graph
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MS Graph permissions assignment"
$responseMg = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$responseMg.ResourceAppId = '00000003-0000-0000-c000-000000000000'
$responseMg.ResourceAccess = $responseMgPermission1, $responseMgPermission2, $responseMgPermission3, $responseMgPermission4

#---------------------------
# Creating service principal
#---------------------------

Write-Log -Sev 1 -Line (__LINE__) -Msg "Response automation Service principal exists : $responseSpExists"

if ($responseSpExists) {
    $newResponse = $responseSpInfo
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Response Service principal", $newResponse.DisplayName, "exists and will be used."
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning required permissions ..."
    try {
        $newResponseSp = Get-AzADServicePrincipal -DisplayName $responseSp -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining Response service principal information"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Response automation service principal ..."
    try {
        $newResponseSp = New-AzADServicePrincipal -Scope /subscriptions/$subscriptionId/resourceGroups/$rgSentinel -DisplayName $responseSp -Role Reader -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Response automation service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Start-Sleep -Seconds 30
    try {
        $newResponse = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $responseSp }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining details for the Response service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

if ($newResponse) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning API permissions ..."
    try {
        Set-AzureADApplication -ObjectId $newResponse.ObjectId -RequiredResourceAccess $responseAtp, $responseMg
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to Response automation service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "API permissions assigned successfully"
    try{
        $pwdAdminRole = Get-AzureADDirectoryRole -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "Password administrator" }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining Role definition"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining Application details for", $newResponse.DisplayName
    try {
        $newResponseApp = Get-AzureADServicePrincipal -SearchString $newResponse.DisplayName -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining Application details."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating roles assigned to", $newResponse.DisplayName
    try {
        $pwAdminRoleAssignment = Get-AzureADDirectoryRoleMember -ObjectId $pwdAdminRole.ObjectId | Where-Object { $_.DisplayName -eq $newResponse.DisplayName }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Unable to get current role assignments."
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    if ($pwAdminRoleAssignment.Length -eq 0) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Password administrator role to the Response service principal"
        try {
            $null = Add-AzureADDirectoryRoleMember -ObjectId $pwdAdminRole.ObjectId -RefObjectId $newResponseApp.ObjectId -ErrorAction SilentlyContinue
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning Role to Service principal"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assignined Azure AD Password administrator role to the Response service principal."
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Role Password administrator already assigned to", $newResponse.DisplayName
    }
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Response automation service principal"
}

while($responseSpKeyConfirm -ne 'y' -and $responseSpKeyConfirm -ne 'n') {
    Write-Host
    $responseSpKeyConfirm = Read-Host "Do you want to create a new secret for this Service principal? [Y/N] "
}

if ($responseSpKeyConfirm -eq 'y') {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for Response service principal"
    Start-Sleep -Seconds 5
    try {
        $responseSecret = New-AzureADApplicationPasswordCredential -ObjectId $newResponse.ObjectId -CustomKeyIdentifier "MXDR Response Automation" -StartDate $startDate -EndDate $endDate
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for Response service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}

if ($responseSpKeyConfirm -eq 'y') {
    $responseSecretStartDate = $responseSecret.StartDate
    $responseSecretEndDate = $responseSecret.EndDate
    $responseSecretValue = $responseSecret.Value
}
else {
    $responseSecretStartDate = "Null"
    $responseSecretEndDate = "Null"
    $responseSecretValue = "Null"
}

Write-Log -Msg "Difenda Response service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Service principal name: ", $newResponse.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Object Id:              ", $newResponse.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Application Id:         ", $newResponse.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Tenant Id:              ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Subscription name:      ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Secret start date:      ", $responseSecretStartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Secret end date:        ", $responseSecretEndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Secret value:           ", $responseSecretValue

$responseSpInfoObject = @{
    DisplayName = $newResponse.DisplayName
    ObjectId = $newResponse.ObjectId
    AppId = $newResponse.AppId
    TenantId = $azContext.Subscription.TenantId
    SubscriptionId = $azContext.Subscription.Id
    SubscriptionName = $azContext.Subscription.Name
    SecretStart  = $responseSecretStartDate
    SecretEnds = $responseSecretEndDate
    SecretValue = $responseSecretValue
}

if ($isOt) {
    $subScope = "/subscriptions/" + $OtSubscriptionInfo.Id
    $targetRole = "Security Admin"
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "The MXDR for OT service required additional permissions to be assigned to the Response Service principal."
    Write-Log -Msg "Validating Azure role assignment for the Response Service principal on the subscription", $OtSubscriptionInfo.Name, "(ID:", $OtSubscriptionInfo.Id, ") ..."
    try {
        $currentResponseAssignment = Get-AzroleAssignment -ObjectId $newResponse.ObjectId -Scope $subScope -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 2 -Line (__LINE__) -Msg "Error obtaining current Azure role assignment for the Response Service principal"
        Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    if ($currentResponseAssignment) {
        $isSecAdmin = $false
        For ($i=0; $i -lt $currentResponseAssignment.Count; $i++) {
            Write-Log -Sev 1 -Line (__LINE__) -Msg "Current Azure role assignment : ", $currentResponseAssignment[$i].RoleDefinitionName
            if ($currentResponseAssignment[$i].RoleDefinitionName -eq $targetRole) {
                $isSecAdmin = $true
            }
        }
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "No current assignments found."
    }
}

if ($isSecAdmin) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Service principal", $newResponse.DisplayName, "already has the", $targetRole, "role assignment on", $OtSubscriptionInfo.Name, "Nothing to do."
}
else {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure", $targetRole, "role to the Response Service principal on", $OtSubscriptionInfo.Name, "..."
    try {
        $responseRoleAssignment = New-AzRoleAssignment -ObjectId $newResponseSp.Id -RoleDefinitionName $targetRole -Scope $subScope -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($ErrorMessage -like "*Conflict*") {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Security Admin role already assigned."
        }
        else {
            Write-Log -Sev 2 -Line (__LINE__) -Msg "Error creating role assignment for the Response Service principal"
            Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Response Service principal setup complete."

Write-Log -Msg "Please grant Admin consent"
Write-Host "   1. Open a new browser tab and connect to your Azure tenant as a Global Administrator."
Write-Host "   2. Select Azure Active Directory."
Write-Host "   3. Select 'App registrations', then 'All applications'."
Write-Host "   4. Search for", $newResponse.DisplayName, "then select the App registration."
Write-Host "   5. Select 'API permissions'."
Write-Host "   6. Review the permissions configured and click on 'Grant admin consent for", $azTenant.Name, "'."
Write-Host "   7. and confirm 'Yes' when prompted."
Write-Host

Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# MDETVM integration service principal section
#########################################################################
if ($isavm) { 

    Clear-Host
    Write-Log -Msg "Difenda AVM service principal section"
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service Triage principal name:", $avm
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for Difenda AVM service principal"

    #---------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Required permissions in Microsoft Defender for Endpoint API (WindowsDefenderATP - Microsoft Threat and Vulnerability Management to Difenda Shield integration)
    #---------------------------------------------------------------------------------------------------------------------------------------------------------------
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
    $AvmTvmPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role" # Machine.Read.All
    $AvmTvmPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "41269fc5-d04d-4bfd-bce7-43a51cea049a","Role" # Vulnerability.Read.All
    $AvmTvmPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "37f71c98-d198-41ae-964d-2c49aab74926","Role" # Software.Read.All
    $AvmTvmPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "6443965c-7dd2-4cfd-b38f-bb7772bee163","Role" # SecurityRecommendation.Read.All
    $AvmTvmPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role" # AdvancedQuery.Read.All
    $AvmTvmPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "02b005dd-f804-43b4-8fc7-078460413f74","Role" # Score.Read.All
    $AvmTvmPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "6a33eedf-ba73-4e5a-821b-f057ef63853a","Role" # RemediationTasks.Read.All
    $AvmTvmPermission8 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "227f2ea0-c2c2-4428-b7af-9ff40f1a720e","Role" # SecurityConfiguration.Read.All

    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
    $AvmTvm = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $AvmTvm.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
    $AvmTvm.ResourceAccess = $AvmTvmPermission1, $AvmTvmPermission2, $AvmTvmPermission3, $AvmTvmPermission4, $AvmTvmPermission5, $AvmTvmPermission6, $AvmTvmPermission7, $AvmTvmPermission8

    #--------------------------------------------------------------------
    # Required permissions in Microsoft Threat Protection (M365 Defender)
    #--------------------------------------------------------------------
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Threat Protection API"
    $AvmMtpPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7734e8e5-8dde-42fc-b5ae-6eafea078693","Role" # AdvancedHunting.Read.All

    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MTP permissions assignment"
    $AvmMtp = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $AvmMtp.ResourceAppId = '8ee8fdad-f234-4243-8f3b-15c294843740'
    $AvmMtp.ResourceAccess = $AvmMtpPermission1

    #------------------------------------------
    # Required permissions in Log Analytics API
    #------------------------------------------
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Log Analytics API"
    $AvmAlaPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e8f6e161-84d0-4cd7-9441-2d46ec9ec3d5","Role" # Data.Read

    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Log Analytics permissions assignment"
    $AvmAla = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $AvmAla.ResourceAppId = 'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5'
    $AvmAla.ResourceAccess = $AvmAlaPermission1

    #--------------------------------------------
    # Required permissions in Microsoft Graph API
    #--------------------------------------------
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for Microsoft Graph API"
    $AvmMsgPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7438b122-aefc-4978-80ed-43db9fcc7715","Role" # Device.Read.All
    $AvmMsgPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7ab1d382-f21e-4acd-a863-ba3e13f7da61","Role" # Directory.Read.All
    $AvmMsgPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "5b567255-7703-4780-807c-7be8301ae99b","Role" # Group.Read.All
    $AvmMsgPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "98830695-27a2-44f7-8c18-0c3ebc9698f6","Role" # GroupMember.Read.All
    $AvmMsgPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "dc5007c0-2d7d-4c42-879c-2dab87571379","Role" # IdentityRiskyUser.Read.All
    $AvmMsgPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "230c1aed-a721-4c5d-9cb4-a90514e508ef","Role" # Reports.Read.All
    $AvmMsgPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "483bed4a-2ad3-4361-a73b-c83ccdbdc53c","Role" # RoleManagement.Read.Directory
    $AvmMsgPermission8 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "c7fbd983-d9aa-4fa7-84b8-17382c103bc4","Role" # RoleManagement.Read.All
    $AvmMsgPermission9 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "df021288-bdef-4463-88db-98f22de89214","Role" # User.Read.All

    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Microsoft Graph permissions assignment"
    $AvmMsg = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $AvmMsg.ResourceAppId = '00000003-0000-0000-c000-000000000000'
    $AvmMsg.ResourceAccess = $AvmMsgPermission1, $AvmMsgPermission2, $AvmMsgPermission3, $AvmMsgPermission4, $AvmMsgPermission5, $AvmMsgPermission6, $AvmMsgPermission7, $AvmMsgPermission8, $AvmMsgPermission9

    #---------------------------
    # Creating service principal
    #---------------------------

    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal exists : $avmSpExists"

    if ($avmSpExists) {
        $newAvm = $AvmSpInfo
        Write-Log -Sev 2 -Line (__LINE__) -Msg "AVM Serviceprincipal", $newAvm.DisplayName, "exists and will be used."
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning required permissions ..."
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating AVM service principal"
        try{
            $newAvm = New-AzADServicePrincipal -Scope /subscriptions/$subscriptionId/resourceGroups/$rgSentinel -DisplayName $avm -Role Reader -ErrorAction SilentlyContinue
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating AVM service principal"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
        Start-Sleep -Seconds 30
        try {
            $newAvm = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $avm }
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining AVM service principal details"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }
    if ($newAvm) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning API permissions ..."
        try {
            Set-AzureADApplication -ObjectId $newAvm.ObjectId -RequiredResourceAccess $AvmTvm, $AvmMtp, $AvmAla, $AvmMsg
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to AVM service principal"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
        Write-Log -Sev 1 -Line (__LINE__) -Msg "API permissions assigned successfully"
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating AVM service principal"
    }
    while($avmSpKeyConfirm -ne 'y' -and $avmSpKeyConfirm -ne 'n') {
        Write-Host
        $avmSpKeyConfirm = Read-Host "Do you want to create a new secret for this Service principal? [Y/N] "
    }
    if ($avmSpKeyConfirm -eq 'y') {
        Write-Host
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for AVM service principal"
        Start-Sleep -Seconds 5
        try {
            $avmSecret = New-AzureADApplicationPasswordCredential -ObjectId $newAvm.ObjectId -CustomKeyIdentifier "AVM Integration" -StartDate $startDate -EndDate $endDate
        }
        catch {
            
            $ErrorMessage = $_.Exception.Message
            Write-Host
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for AVM service principal"
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            Exit
        }
    }
    if ($avmSpKeyConfirm -eq 'y') {
        $avmSecretStartDate = $avmSecret.StartDate
        $avmSecretEndDate = $avmSecret.EndDate
        $avmSecretValue = $avmSecret.Value
    }
    else {
        $avmSecretStartDate = "Null"
        $avmSecretEndDate = "Null"
        $avmSecretValue = "Null"
    }

    Write-Log -Msg "Difenda AVM service principal details"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal name: ", $newAvm.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Object Id:              ", $newAvm.ObjectId
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Application Id:         ", $newAvm.AppId
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Tenant Id:              ", $azContext.Subscription.TenantId
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Subscription Id:        ", $azContext.Subscription.Id
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Subscription name:      ", $azContext.Subscription.Name
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Secret start date:      ", $avmSecretStartDate
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Secret end date:        ", $avmSecretEndDate
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Secret value:           ", $avmSecretValue

    $avmSpInfoObject = @{
        DisplayName = $newAvm.DisplayName
        ObjectId = $newAvm.ObjectId
        AppId = $newAvm.AppId
        TenantId = $azContext.Subscription.TenantId
        SubscriptionId = $azContext.Subscription.Id
        SubscriptionName = $azContext.Subscription.Name
        SecretStart  = $avmSecretStartDate
        SecretEnds = $avmSecretEndDate
        SecretValue = $avmSecretValue
    }
    
    Write-Log -Sev 1 -Line (__LINE__) -Msg "AVM Service principal setup complete."

    Write-Log -Msg "Please grant Admin consent"
    Write-Host "   1. Open a new browser tab and connect to your Azure tenant as a Global Administrator."
    Write-Host "   2. Select Azure Active Directory."
    Write-Host "   3. Select 'App registrations', then 'All applications'."
    Write-Host "   4. Search for", $newAvm.DisplayName, ", select the App registration."
    Write-Host "   5. Select 'API permissions'."
    Write-Host "   6. Review the permissions configured and click on 'Grant admin consent for", $azTenant.Name, "'."
    Write-Host "   7. and confirm 'Yes' when prompted."
    Write-Host

    Write-Host -NoNewLine 'Press [Enter] to continue ...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

#########################################################################
# Create/update Lighthouse delegations
##########################################################################

Clear-Host
#-------------------------------
# Downloading ARM template files
#-------------------------------
Write-Log -Msg "Downloading Lighthouse ARM template files from repository ..."
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Downloading ARM template file for the Sentinel Resource group delegations."

try {
    $downloadSentinelTemplate = Invoke-WebRequest https://raw.githubusercontent.com/Difenda/MDR-Onboard/main/Scripts/MxdrTemplates/sentinelDelegations.json -OutFile ./sentinelDelegations.json -ErrorAction Stop
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
    $downloadIntegrationTemplate = Invoke-WebRequest https://raw.githubusercontent.com/Difenda/MDR-Onboard/main/Scripts/MxdrTemplates/integrationDelegations.json -OutFile ./integrationDelegations.json -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed downloading Integration Lighthouse delegation template"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}
if ($downloadIntegrationTemplate) { Write-Log -Sev 1 -Line (__LINE__) -Msg "Download complete." }

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
        $newSentinelDelegation = New-AzDeployment -Location $sentinelRgDetails.Location -TemplateFile ./sentinelDelegations.json -TemplateParameterObject $sentinelDelegationParams -ErrorAction Stop
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
Write-Host -NoNewLine 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#########################################################################
# Creation of Managed Identity
#########################################################################

# Clear-Host
# Write-Log -Msg "User provided managed identity section"
# Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if user managed Id exists"
# $midentity = Get-AzUserAssignedIdentity -ResourceGroupName $rgSentinel -Name $UamiName -ErrorAction SilentlyContinue
# Start-Sleep -Seconds 10
# if ($midentity.Name -eq $UamiName) {
#     Write-Log -Sev 2 -Line (__LINE__) -Msg "User managed Id", $midentity.Name, "already exists in the resource group", $rgSentinel
#     $confirmation = Read-Host "Do you want to use this Id? [y/n]"
#     while($confirmation -ne "y") {
#         if ($confirmation -eq 'n') { Exit }
#         $confirmation = Read-Host "Do you want to use this Id? [y/n]"
#     }
# }
# else {
#     $createManagedId = $true
# }

# Write-Log -Sev 2 -Line (__LINE__) -Msg "Connecting to Azure AD"
# try { Connect-AzureAD }
# catch {
#     $ErrorMessage = $_.Exception.Message
#     Write-Log -Sev 2 -Line (__LINE__) -Msg "Invalid response connecting to Azure AD"
#     Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
# }

# if ($createManagedId) {
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating user provided managed identity"
#     $midentity = New-AzUserAssignedIdentity -ResourceGroupName $rgSentinel -Name $UamiName -Location $location -ErrorAction SilentlyContinue
#     Start-Sleep -Seconds 30
#     if ($midentity.Id) {
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "User provided managed identity created successfully"
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "Managed Id name:  ", $midentity.Name
#         Write-Log -Sev 1 -Line (__LINE__) -Msg "Managed Id type:  ", $midentity.Type
#     }
#     else {
#         Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating user provided managed identity"
#         Write-Log -Sev 3 -Line (__LINE__) -Msg $_.Exception.Message
#         Exit
#     }
# }
# $roleAssigned = $true
# $azureAdRole = Get-AzureADDirectoryRole | ? { $_.DisplayName -eq "Global Administrator" }

# Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure AD role", $azureAdRole.ObjectId ,"to user provided managed identity"
# Start-Sleep -Seconds 30
# try {
#     Add-AzureADDirectoryRoleMember -ObjectId $azureAdRole.ObjectId -RefObjectId $midentity.PrincipalId -ErrorAction Stop
# }
# catch {
#     $ErrorMessage = $_.Exception.Message
#     if ($ErrorMessage -like "*added object references already exist*") {
#         Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD role was already assigned to user provided managed identity"
#         $roleAssigned = $false
#     }
#     else {
#         Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning Azure AD role to user provided managed identity"
#         Write-Log -Sev 3 -Line (__LINE__) -Msg $_.Exception.Message
#         Exit
#     }
# }

# if ($roleAssigned) {
#     Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure AD role", $azureAdRole.ObjectId ,"successfully assigned to user provided managed identity"
# }

#########################################################################
# Create AAD group for SecOps account. Reader on all active subscriptions
##########################################################################
Clear-Host

Write-Log -Msg "Azure AD Security groups section."

#---------------------------------------------------
# SecOps Security group
#---------------------------------------------------
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Security group $groupSecOps exists ..."
try {
    $grpSecOpsInfo = Get-AzureADGroup -SearchString $groupSecOps
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining information for Azure AD security group $groupSecOps"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
if ($grpSecOpsInfo) {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD Security group ", $grpSecOpsInfo.DisplayName, "already exists."
    $grpSecOpsId = $grpSecOpsInfo.ObjectId

}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure AD security group $groupSecOps ..."
    try {
        $grpSecOpsInfo = New-AzureADMSGroup -DisplayName $groupSecOps -Description 'Difenda MXDR Security group' -MailEnabled $false -SecurityEnabled $true -MailNickName "DifendaMXDR"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Azure AD security group"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    $grpSecOpsId = $grpSecOpsInfo.Id
    Start-Sleep -Seconds 5
}

Write-Log -Sev 1 -Line (__LINE__) -Msg $grpSecOpsInfo.DisplayName, "details."
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Display Name : ", $grpSecOpsInfo.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Object ID    : ", $grpSecOpsId
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Description  : ", $grpSecOpsInfo.Description

#---------------------------------------------------
# IT Security Team group
#---------------------------------------------------
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Security group $groupSso1 exists ..."
try {
    $groupSso1Info = Get-AzureADGroup -SearchString $groupSso1
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining information for Azure AD security group $groupSso1"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
if ($groupSso1Info) {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD Security group ", $groupSso1Info.DisplayName, "already exists."
    $groupSso1Id = $groupSso1Info.ObjectId
}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure AD security group $groupSso1 ..."
    try {
        $groupSso1Info = New-AzureADMSGroup -DisplayName $groupSso1 -Description 'Difenda MXDR - SSO group for Regular notifications' -MailEnabled $false -SecurityEnabled $true -MailNickName "DifendaMXDR"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Azure AD security group"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    $groupSso1Id = $groupSso1Info.Id
    Start-Sleep -Seconds 5
}

Write-Log -Sev 1 -Line (__LINE__) -Msg $groupSso1Info.DisplayName, "details."
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Display Name : ", $groupSso1Info.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Object ID    : ", $groupSso1Id
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Description  : ", $groupSso1Info.Description

#---------------------------------------------------
# High Priority Alert group
#---------------------------------------------------
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Security group $groupSso2 exists ..."
try {
    $groupSso2Info = Get-AzureADGroup -SearchString $groupSso2
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining information for Azure AD security group $groupSso2"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
if ($groupSso2Info) {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD Security group ", $groupSso2Info.DisplayName, "already exists."
    $groupSso2Id = $groupSso2Info.ObjectId
}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure AD security group $groupSso2 ..."
    try {
        $groupSso2Info = New-AzureADMSGroup -DisplayName $groupSso2 -Description 'Difenda MXDR - SSO group for HPI notifications' -MailEnabled $false -SecurityEnabled $true -MailNickName "DifendaMXDR"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Azure AD security group"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    $groupSso2Id = $groupSso2Info.Id
    Start-Sleep -Seconds 5
}

Write-Log -Sev 1 -Line (__LINE__) -Msg $groupSso2Info.DisplayName, "details."
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Display Name : ", $groupSso2Info.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Object ID    : ", $groupSso2Id
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Description  : ", $groupSso2Info.Description

#---------------------------------------------------
# No Alert group
#---------------------------------------------------
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if Security group $groupSso3 exists ..."
try {
    $groupSso3Info = Get-AzureADGroup -SearchString $groupSso3
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining information for Azure AD security group $groupSso3"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
if ($groupSso3Info) {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD Security group ", $groupSso3Info.DisplayName, "already exists."
    $groupSso3Id = $groupSso3Info.ObjectId
}
else {
    Write-Host
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure AD security group $groupSso3 ..."
    try {
        $groupSso3Info = New-AzureADMSGroup -DisplayName $groupSso3 -Description 'Difenda MXDR - SSO group for suppressed notifications' -MailEnabled $false -SecurityEnabled $true -MailNickName "DifendaMXDR"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Azure AD security group"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    $groupSso3Id = $groupSso3Info.Id
}

Write-Log -Sev 1 -Line (__LINE__) -Msg $groupSso3Info.DisplayName, "details."
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Display Name : ", $groupSso3Info.DisplayName
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Object ID    : ", $groupSso3Id
Write-Log -Sev 1 -Line (__LINE__) -Msg " - Description  : ", $groupSso3Info.Description

#---------------------------------------------------
# List all subscriptions in tenant
#---------------------------------------------------
Write-Log -Msg "Assigning Azure Reader role on all subscriptions to the SecOps AAD Security group. Required for incident investigation and response."
Write-Host
Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining list of all active subscriptions in tenant"
$activeSubs = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
Start-Sleep -Seconds 5
if ($null -ne $activeSubs) {
    foreach($s in $activeSubs) {
        $sScope = '/subscriptions/' + $s.Id
        Write-Host
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Reader role on"
        Write-Log -Sev 1 -Line (__LINE__) -Msg "  Scope             : ", $sScope
        Write-Log -Sev 1 -Line (__LINE__) -Msg "  Subscription name : ", $s.Name
        try { $grpRoleAssign = New-AzRoleAssignment -ObjectId $grpSecOpsId -RoleDefinitionName 'Reader' -Scope $sScope -ErrorAction Stop }
        catch {
            $ErrorMessage = $_.Exception.Message
            if ($ErrorMessage -like "*Conflict*") {
                Write-Log -Sev 2 -Line (__LINE__) -Msg "Reader role is already assigned."
            }
            else {
                Write-Log -Sev 3 -Line (__LINE__) -Msg "Role assignment operation for Security group failed."
                Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
            }
        }
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Reader role successfully assigned on", $s.Name, "(", $s.Id , ")"
    }
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining list of active subscriptions in tenant"
    Exit
}

Write-Host
Write-Host 'Press [Enter] to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#####################################################
#
# Invoking customer onboard API
#
#####################################################

if ($isOt) { $InfoOtSubcription = $OtSubscriptionInfoObject }
else { $InfoOtSubcription = $null }

if ($isAvm) { $InfoAvmSp = $avmSpInfoObject }
else { $InfoAvmSp = $null }

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$myUrl = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($myBase64key))
$body = @{
    ApprovalEmail = $c3Email
    CustomerName = $company
    TenantInfo = $tenantInfoObject
    AzureLocation = $AzureLocationObject
    MxdrItSubscription = $subscriptionInfoObject
    MxdrOtSubscription = $InfoOtSubcription
    SentinelResourceGroup = $sentinelRgObject
    SentinelWorkspace = $sentinelWsObject
    IntegrationResourceGroup = $integrationRgObject
    TriageServicePrincipal = $triageSpInfoObject
    DevOpsServicePrincipal = $devopsInfoObject
    ResponseServicePrincipal = $responseSpInfoObject
    AvmServicePrincipal = $InfoAvmSp
    SentinelDelegation = $newSentinelDelegation
    IntegrationDelegation = $newIntegrationDelegation
    SsoItSecurity = $groupSso1Info
    SsoHpiNotifications = $groupSso2Info
    SsoNoNotifications = $groupSso3Info
    IsAvmCustomer = $isavm
    IsOtCustomer = $isOt
    UserInfo = $userInfoObject
    SecOpsGroupInfo = $grpSecOpsInfo
}
try {
    $response = Invoke-RestMethod -Method 'POST' -Uri $myUrl -Headers $headers -Body ($body | ConvertTo-Json -Depth 100) -ErrorAction Stop
}   
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed sending onboarding information ..."
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}
Write-Host $response

#######################################################################
#
# Clean-up section
#
#######################################################################

Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '
Write-Host '   Script has finished'
Write-Host '   Please look at any Warnings or errors and correct manually'
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '