#
# This script will create all App registrations required for the Difenda MDR service.
#
# Must be executed in an the Azure Powershell session with a Global Administrator account.
#
# USAGE: 1) Upload the PS1 file to the Azure Powershell session.
#        2) Run ./mdr-createServicePrincipals.ps1 -company <company name> -subscription <subscription ID> -rg <Resource group name> -soar <SOAR App reg name> -ti <TI App reg name> -devops <DevOps App reg name> -group <Security group>
#
# EXAMPLE: ./mdrProvisioningScriptV1.ps1 -company ACME -subscription c8cf612a-3efe-4d63-9d3c-11e4ef108064 -rg mdr-prod-rg -location canadacentral -soar mdr-prod-int-sp -ti mdr-prod-ti-sp -devops mdr-prod-devops-sp -group mdr-prod-group -key kv-mdr-prod -managedid mdr-prod-managedid
#
# IMPORTANT: If the script faile with the message "You must call the Connect-AzureAD cmdlet before calling any other cmdlets",
#            this means that the Azure AD authorization token for the current session has expired and need to be renewed.
#            To do so execute the following commands and provide the credentials of a Global or Security Administrator.
#
#                           > $adCredential = Get-Credential
#                           > Connect-AzureAD -Credential $adCredential 
#
#            Then execute this script again.
#

param (
    [Parameter(Mandatory=$true)]$company,
    [Parameter(Mandatory=$true)]$subscription,
    [Parameter(Mandatory=$true)]$rg,
    [Parameter(Mandatory=$true)]$location,
    [Parameter(Mandatory=$true)]$soar,
    [Parameter(Mandatory=$true)]$ti,
    [Parameter(Mandatory=$true)]$devops,
    [Parameter(Mandatory=$true)]$group,
    [Parameter(Mandatory=$true)]$key,
    [Parameter(Mandatory=$true)]$managedid
)

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
function Get-ScriptLineNumber { return $MyInvocation.ScriptLineNumber }
new-item alias:__LINE__ -value Get-ScriptLineNumber

$filePath = './difenda-mdrProvisioning-' + $company + "-" + $(Get-Date -Format "dddd-MM-dd-yyyy-HH_mm") + '.log'
$scope = '/subscriptions/' + $subscription + '/resourceGroups/' + $rg
$startDate = Get-Date
$endDate = $startDate.AddYears(99)

Write-Log -Msg "Start processing PowerShell script"

Write-Log -Sev 1 -Line $(__LINE__) -Msg "Sample informational message"
Write-Log -Sev 2 -Line $(__LINE__) -Msg "Sample warning message"
Write-Log -Sev 3 -Line $(__LINE__) -Msg "Sample error message"

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
    Install-Module -Name AzureAD -Scope CurrentUser -Force
    Import-Module -Name AzureAD -ErrorAction SilentlyContinue
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
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Installed module Az.ManagementPartner. Version->", $(Get-Module -Name Az.ManagementPartner).Version
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

Write-Log -Msg "Parameter validation section"
# Validating if Subscription ID was provided and correct
if ($subscription) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription ID", $subscription ,"provided."
    if ($subscription -match '^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription ID format is valid."
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid Subscription ID format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Subscription Id not provided"
    Exit
}

# Validating if Resource group name was provided and correct
if ($rg) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Resource group name", $rg ,"provided."
    if ($rg -match '^[\w\-\(\)\.]{4,156}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Resource group name format is valid."
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid Resource group format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Resource group name not provided"
    Exit
}

# Validating if SOAR service principal was provided and correct
if ($soar) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "SOAR service principal name", $soar ,"provided."
    if ($soar -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "SOAR service principal name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid SOAR service principal name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "SOAR service principal name not provided"
    Exit
}

# Validating if TI service principal was provided and correct
if ($ti) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "TI service principal name", $ti ,"provided."
    if ($ti -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "TI service principal name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid TI service principal name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "TI service principal name not provided"
    Exit
}

# Validating if DevOps service principal was provided and correct
if ($devops) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "DevOps service principal name", $devops ,"provided."
    if ($devops -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "DevOps service principal name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid DevOps service principal name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "DevOps service principal name not provided"
    Exit
}

# Validating if the security group name was provided and correct
if ($group) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Security group name", $group ,"provided."
    if ($group -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Security group name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid security group name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Security group name not provided"
    Exit
}

# Validating if the key vault name was provided and correct
if ($key) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Key vault name", $key ,"provided."
    if ($key -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Key vault name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid Key vault name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Key vault name not provided"
    Exit
}

# Validating if the managed ID was provided and correct
if ($managedid) {
    Write-Log -Sev 1 -Line $(__LINE__) -Msg "Managed ID name", $managedid ,"provided."
    if ($managedid -match '^[\w\-]{4,56}[^\.]$') {
        Write-Log -Sev 1 -Line $(__LINE__) -Msg "Managed name format is valid"
    }
    else {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Invalid managed ID name format"
        Exit
    }
}
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Managed ID name not provided"
    Exit
}

Write-Host ' '
Write-Log -Msg "All validations passed"
Write-Host -NoNewLine 'Press any key to continue ...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host -NoNewLine ' '
Write-Host ' '

#########################################################################
#
# Context setup and validation
#
#########################################################################
Write-Log -Msg "Please enter the credentials of a Global or Security Administrator"
$userCredential = Get-Credential

$userToCompare = $userCredential.UserName + "*"
$currentUserDetails = Get-AzADUser | ? { $_.UserPrincipalName -like $userToCompare }

if ($currentUserDetails) { Write-Log -Sev 1 -Line $(__LINE__) -Msg "Succesfully obtained details for current user ->", $currentUserDetails.UserPrincipalName }
else {
    Write-Log -Sev 3 -Line $(__LINE__) -Msg "Failed obtaining details for current user"
    Exit
}

Write-Log -Msg "Setting and validating Azure context"
$azContext = Set-AzContext -Subscription $subscription
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
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Tenant Id:              ", $azContext.Subscription.TenantId
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription name:      ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure account:          ", $azContext.Account.Id
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Azure region:           ", $location

$subscriptionScope = "/subscriptions/$subscription"
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

#########################################################################
#
# Setting up Management partner
#
#########################################################################
Write-Log -Msg "Setting up Partner Id"
Write-Log -Sev 1 -Line $(__LINE__) -Msg "Obtaining existing management partner information"
try { $partner = Get-AzManagementPartner -ErrorAction Stop}
catch {
    if ($_) {
        Write-Log -Sev 3 -Line $(__LINE__) -Msg "Error while obtaining management partner information"
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

#########################################################################
#
# Resource group
#
##########################################################################
Write-Log -Msg "Resource group section"

try { $currentRg = Get-AzResourceGroup -name $rg -ErrorAction Stop }
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Exception while collecting resource group information"
    Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
}

if ($null -eq $currentRg) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating resource group"
    $newRg = New-AzResourceGroup -Name $rg -Location $location
    Start-Sleep -Seconds 30
    if ($null -eq $newRg) {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating resource group"
        Exit
    }
    else {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Resource group successfully created ->", $newRg.ResourceGroupName
    }
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Resource group", $currentRg.ResourceGroupName, "already exists and will be used"
}


#########################################################################
#
# Managed Id
#
##########################################################################
Write-Log -Msg "User provided managed identity section"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if user managed Id exists"
$midentity = Get-AzUserAssignedIdentity -ResourceGroupName $rg -Name $managedid -ErrorAction SilentlyContinue
Start-Sleep -Seconds 10
if ($midentity.Name -eq $managedid) {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "User managed Id", $midentity.Name, "already exists in the resource group", $rg
    $confirmation = Read-Host "Do you want to use this Id? [y/n]"
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this Id? [y/n]"
    }
}
else {
    $createManagedId = $true
}

Write-Log -Sev 2 -Line (__LINE__) -Msg "Connecting to Azure AD"
try { Connect-AzureAD }
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Invalid response connecting to Azure AD"
    Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
}

if ($createManagedId) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating user provided managed identity"
    $midentity = New-AzUserAssignedIdentity -ResourceGroupName $rg -Name $managedid -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 30
    if ($midentity.Id) {
        Write-Log -Sev 1 -Line (__LINE__) -Msg "User provided managed identity created successfully"
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Managed Id name:  ", $midentity.Name
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Managed Id type:  ", $midentity.Type
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating user provided managed identity"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $_.Exception.Message
        Exit
    }
}
$roleAssigned = $true
$azureAdRole = Get-AzureADDirectoryRole | ? { $_.DisplayName -eq "Global Administrator" }

Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Azure AD role", $azureAdRole.ObjectId ,"to user provided managed identity"
try {
    Add-AzureADDirectoryRoleMember -ObjectId $azureAdRole.ObjectId -RefObjectId $midentity.PrincipalId -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    if ($ErrorMessage -like "*added object references already exist*") {
        Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD role was already assigned to user provided managed identity"
        $roleAssigned = $false
    }
    else {
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning Azure AD role to user provided managed identity"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $_.Exception.Message
        Exit
    }
}

if ($roleAssigned) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure AD role", $azureAdRole.ObjectId ,"successfully assigned to user provided managed identity"
}

#########################################################################
#
# Pause for ARM template execution
#
##########################################################################
Write-Host ' '
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '
Write-Host 'The next step of the process consists on continuing with the execution'
Write-Host 'of the ARM template to deploy Azure Sentinel resources.'
Write-Host ' '
Write-Host 'To start the deployment of the ARM template click the Next button above.'
Write-Host 'When the deployment completes, come back to the script execution and press any'
Write-Host 'key to continue with the final phase of the process.'
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '

Write-Host -NoNewLine 'Please proceed with execution of the ARM deployment and press any key once completed'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host -NoNewLine ' '
Write-Host ' '
Write-Host ' '

#########################################################################
#
# Key Vault permissions
#
##########################################################################
Write-Log -Msg "Assigning permissions to Key vault"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Current user: ", $currentUserDetails.UserPrincipalName

try {
    Set-AzKeyVaultAccessPolicy -VaultName $key -ObjectId $(Get-AzAdUser -UserPrincipalName $currentUserDetails.UserPrincipalName).Id -PermissionsToSecrets all -ErrorAction SilentlyContinue
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning Key vault access policy"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Key vault access policy successfully assigned to user"

#########################################################################
#
# SOAR integration service principal section
#
##########################################################################
Write-Log -Msg "SOAR integration service principal section"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service principal name:", $soar
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for SOAR service principal"

# Required permissions in Microsoft Defender for Endpoint API (Isolate/Unisolate/EP discovery)
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MDE API"
$atpPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "93489bf5-0fbc-4f2d-b901-33f2fe08ff05","Role"
$atpPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "7e4e1300-e1b9-4102-88ba-f0cb6e6d5974","Role"
$atpPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","Role"
$atpPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "a86d9824-b2b6-45f8-b042-16bc4922ed4e","Role"

# Required permissions in Microsoft Graph API (User Enable/Disable)
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MS Graph API"
$mgPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "741f803b-c850-494e-b5df-cde7c675a1ca","Role"
$mgPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "bf394140-e372-4bf9-a898-299cfc7564e5","Role"

# Building the object with the set of permissions for MDE
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MDE permissions assignment"
$atp = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$atp.ResourceAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$atp.ResourceAccess = $atpPermission1, $atpPermission2, $atpPermission3, $atpPermission4

# Building the object with the set of permissions for Microsoft Graph
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MS Graph permissions assignment"
$mg = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$mg.ResourceAppId = '00000003-0000-0000-c000-000000000000'
$mg.ResourceAccess = $mgPermission1, $mgPermission2

Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if service principal exists"
$currentSoar = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $soar }

if ($null -eq $currentSoar) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating SOAR integration service principal"
    try {
        $newSoar = New-AzADServicePrincipal -Scope /subscriptions/$subscription/resourceGroups/$rg -DisplayName $soar -Role Reader -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating SOAR integration service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal", $soar, "was found in the tenant"
    $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    }
    $newSoar = $currentSoar
}

if ($null -ne $newSoar) {
    Start-Sleep -Seconds 30
    Write-Log -Sev 1 -Line (__LINE__) -Msg "SOAR integration service principal successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining details for SOAR service principal"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning MDE and MS Graph API permissions"
    $newSoarDetails = Get-AzureADApplication -All $true | ? { $_.DisplayName -eq $soar }
    try {
        Set-AzureADApplication -ObjectId $newSoarDetails.ObjectId -RequiredResourceAccess $atp, $mg
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to SOAR service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "MDE and MS Graph API permissions assigned successfully"
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating SOAR integration service principal"
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for SOAR service principal"
try {
    $aadSoarSecret = New-AzureADApplicationPasswordCredential -ObjectId $newSoarDetails.ObjectId -CustomKeyIdentifier "MDR SOAR Integration" -StartDate $startDate -EndDate $endDate
}
catch {
    
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for SOAR integration service principal"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Saving SOAR secret in the key vault"
try {
    $soarSecretvalue = ConvertTo-SecureString $aadSoarSecret.Value -AsPlainText -Force
    $secret = Set-AzKeyVaultSecret -VaultName $key -Name 'SoarSecret' -SecretValue $soarSecretvalue
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed saving secret for SOAR integration service principal in the keyvault"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}


Write-Log -Msg "SOAR service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal name: ", $soar
Write-Log -Sev 1 -Line (__LINE__) -Msg "Object Id:              ", $newSoarDetails.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Application Id:         ", $newSoarDetails.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Tenant Id:              ", $(Get-AzContext).Tenant.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription Id:        ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:      ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret start date:      ", $aadSoarSecret.StartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret end date:        ", $aadSoarSecret.EndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret value:           ", $aadSoarSecret.Value

#########################################################################
#
# Threat Intelligence integration service principal section
#
##########################################################################
Write-Log -Msg "Threat Intelligence integration service principal section"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service principal name", $ti
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating permissions object for TI service principal"

# Required permissions in Microsoft Graph API (User Enable/Disable)
Write-Log -Sev 1 -Line (__LINE__) -Msg "Building permissions object for MS Graph API"
$tiPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "21792b6c-c986-4ffc-85de-df9da54b52fa","Role"

# Building the object with the set of permissions for Microsoft Graph
Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating MS Graph permissions assignment"
$tiApiPermissions = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$tiApiPermissions.ResourceAppId = '00000003-0000-0000-c000-000000000000'
$tiApiPermissions.ResourceAccess = $tiPermission1

Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if service principal exists"
$currentTi = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $ti }

if ($null -eq $currentTi) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating TI integration service principal"
    try {
        $newTi = New-AzADServicePrincipal -Scope /subscriptions/$subscription/resourceGroups/$rg -DisplayName $ti -Role Reader -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating TI integration service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal", $ti, "was found in the tenant"
    $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    }
    $newTi = $currentTi
}

if ($null -ne $newTi) {
    Start-Sleep -Seconds 30
    Write-Log -Sev 1 -Line (__LINE__) -Msg "TI integration service principal successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining details for TI service principal"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning MS Graph API permissions"
    $newTiDetails = Get-AzureADApplication -All $true | ? { $_.DisplayName -eq $ti }
    try {
        Set-AzureADApplication -ObjectId $newTiDetails.ObjectId -RequiredResourceAccess $tiApiPermissions
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed assigning API permissions to TI service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    Write-Log -Sev 1 -Line (__LINE__) -Msg "MDE and MS Graph API permissions assigned successfully"
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating TI integration service principal"
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for TI service principal"
try {
    $aadTiSecret = New-AzureADApplicationPasswordCredential -ObjectId $newTiDetails.ObjectId -CustomKeyIdentifier "MDR TI Integration" -StartDate $startDate -EndDate $endDate
}
catch {
    
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for TI integration service principal"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Saving TI secret in the key vault"
try {
    $tiSecretvalue = ConvertTo-SecureString $aadTiSecret.Value -AsPlainText -Force
    $secret = Set-AzKeyVaultSecret -VaultName $key -Name 'TiSecret' -SecretValue $tiSecretvalue
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed saving secret for TI integration service principal in the keyvault"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Msg "TI service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal name:", $ti
Write-Log -Sev 1 -Line (__LINE__) -Msg "Object Id:             ", $newTiDetails.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Application Id:        ", $newTiDetails.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Tenant Id:             ", $(Get-AzContext).Tenant.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription Id:       ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:     ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret start date:     ", $aadTiSecret.StartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret end date:       ", $aadTiSecret.EndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret value:          ", $aadTiSecret.Value

#########################################################################
#
# DevOps integration service principal section
#
##########################################################################
Write-Log -Msg "DevOps integration service principal section"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Using service principal name", $devops

Write-Log -Sev 1 -Line (__LINE__) -Msg "Validating if service principal exists"
$currentDevops = Get-AzureADApplication -All $true -ErrorAction SilentlyContinue | ? { $_.DisplayName -eq $devops }

if ($null -eq $currentDevops) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating DevOps integration service principal"
    try {
        $newDevops = New-AzADServicePrincipal -Scope /subscriptions/$subscription/resourceGroups/$rg -DisplayName $devops -Role Contributor -ErrorAction SilentlyContinue
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating DevOps integration service principal"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Service principal", $devops, "was found in the tenant"
    $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this service principal? [y/n]"
    }
    $newDevops = $currentDevops
}

if ($null -ne $newDevops) {
    Start-Sleep -Seconds 30
    Write-Log -Sev 1 -Line (__LINE__) -Msg "DevOps integration service principal successfully created"
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining details for DevOps service principal"
    $newDevopsDetails = Get-AzureADApplication -All $true | ? { $_.DisplayName -eq $devops }
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating DevOps integration service principal"
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating secret for DevOps service principal"
try {
    $aadDevopsSecret = New-AzureADApplicationPasswordCredential -ObjectId $newDevopsDetails.ObjectId -CustomKeyIdentifier "MDR DevOps Integration" -StartDate $startDate -EndDate $endDate
}
catch {
    
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating secret for DevOps integration service principal"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Sev 1 -Line (__LINE__) -Msg "Saving DevOps secret in the key vault"
try {
    $devopsSecretvalue = ConvertTo-SecureString $aadDevopsSecret.Value -AsPlainText -Force
    $secret = Set-AzKeyVaultSecret -VaultName $key -Name 'DevopsSecret' -SecretValue $devopsSecretvalue
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed saving secret for DevOps integration service principal in the keyvault"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
    Exit
}

Write-Log -Msg "DevOps service principal details"
Write-Log -Sev 1 -Line (__LINE__) -Msg "Service principal name:", $devops
Write-Log -Sev 1 -Line (__LINE__) -Msg "Object Id:             ", $newDevopsDetails.ObjectId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Application Id:        ", $newDevopsDetails.AppId
Write-Log -Sev 1 -Line (__LINE__) -Msg "Tenant Id:             ", $(Get-AzContext).Tenant.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription Id:       ", $azContext.Subscription.Id
Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:     ", $azContext.Subscription.Name
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret start date:     ", $aadDevopsSecret.StartDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret end date:       ", $aadDevopsSecret.EndDate
Write-Log -Sev 1 -Line (__LINE__) -Msg "Secret value:          ", $aadDevopsSecret.Value

#########################################################################
#
# Threat hunters security group
#
##########################################################################
Write-Log -Msg "AD Security group section"

Write-Log -Sev 1 -Line (__LINE__) -Msg "Connecting to Azure AD"
try { Connect-AzureAD }
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Invalid response connecting to Azure AD"
    Write-Log -Sev 2 -Line (__LINE__) -Msg $ErrorMessage
}

$currentGroup = Get-AzureADGroup -SearchString $group

if ($null -eq $currentGroup) {
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Creating Azure AD security group"
    try {
        $newGroup = New-AzureADMSGroup -DisplayName $group -Description 'Difenda MDR Security group' -MailEnabled $false -SecurityEnabled $true -MailNickName "DifendaMDR"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed creating Azure AD security group"
        Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        Exit
    }
    $groupId = $newGroup.Id
    Start-Sleep -Seconds 30
    Write-Log -Sev 1 -Line (__LINE__) -Msg "Azure AD security group successfully created -> "
    Write-Log -Sev 1 -Line (__LINE__) -Msg "   ->", $newGroup.DisplayName
    Write-Log -Sev 1 -Line (__LINE__) -Msg "   ->", $newGroup.Id
    Write-Log -Sev 1 -Line (__LINE__) -Msg "   ->", $newGroup.Description
}
else {
    Write-Log -Sev 2 -Line (__LINE__) -Msg "Azure AD security group", $group, "already exists"
    $confirmation = Read-Host "Do you want to use this group? [y/n]"
    while($confirmation -ne "y") {
        if ($confirmation -eq 'n') { Exit }
        $confirmation = Read-Host "Do you want to use this group? [y/n]"
    }
    $groupId = $currentGroup.ObjectId
    $newGroup = $currentGroup
}

# List all subscriptions in tenant
Write-Log -Sev 1 -Line (__LINE__) -Msg "Obtaining list of all active subscriptions in tenant"
$subs = Get-AzSubscription | ? { $_.State -eq "Enabled" }
Start-Sleep -Seconds 10
# Assigns Reader AzAD role to security group on all enabled subscriptions
if ($null -ne $subs) {
    foreach($s in $subs) {
        $sScope = '/subscriptions/' + $s.Id
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Assigning Reader role on"
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Scope:            ", $sScope
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Subscription name:", $s.Name
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Group name:       ", $newGroup.DisplayName
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Group ObjectId:   ", $groupId
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Group description:", $newGroup.Description
        try { $grpRoleAssign = New-AzRoleAssignment -ObjectId $groupId -RoleDefinitionName 'Reader' -Scope $sScope -ErrorAction Stop }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Sev 3 -Line (__LINE__) -Msg "Role assignment operation for Security group", $newGroup.DisplayName, "on", $s.Name , "failed."
            Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
        }
        Write-Log -Sev 1 -Line (__LINE__) -Msg "Reader role successfully assigned on", $s.Name, "(", $s.Id , ")"
    }
    
}
else {
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed obtaining list of active subscriptions in tenant"
    Exit
}

#######################################################################
#
# Clean-up section
#
#######################################################################

Write-Log -Msg "Cleaning-up all the mess :)"
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '
Write-Host '   1. Remove user assigned managed identity'
Write-Host '   2. Remove access to the key vault for the current user'
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '

Write-Log -Msg "Removing user assigned managed identity from resource group"
Write-Log -Sev 1 -Line (__LINE__) -Msg $rg
Write-Log -Sev 1 -Line (__LINE__) -Msg $managedid
try {
    Remove-AzUserAssignedIdentity -ResourceGroupName $rg -Name $managedid
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed removing user assigned managed identity from resource group"
}

Write-Log -Msg "Removing access to the key vault for current user ->"
Write-Log -Sev 1 -Line (__LINE__) -Msg $key
Write-Log -Sev 1 -Line (__LINE__) -Msg $userCredential.UserName
Write-Log -Sev 1 -Line (__LINE__) -Msg $(Get-AzAdUser -UserPrincipalName $userCredential.UserName).Id

try {
    Remove-AzKeyVaultAccessPolicy -VaultName $key -UserPrincipalName $userCredential.UserName -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Log -Sev 3 -Line (__LINE__) -Msg "Failed removing access to Key vault for current user"
    Write-Log -Sev 3 -Line (__LINE__) -Msg $ErrorMessage
}

Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '
Write-Host '   Script has finished'
Write-Host '   Please look at any Wrnings or errors and correct manually'
Write-Host ' '
Write-Host '**********************************************************************************************'
Write-Host ' '