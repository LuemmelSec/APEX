# APEX (previously AzurePwn)- Azure Post Exploitation Framework  

An attempt to ease up post ex tasks once we have access to some sort of credentials to an Azure related account.

## Architecture  
APEX is built on a modular architecture combining:  
- Microsoft Graph PowerShell Module : For accessing and querying Azure AD resources and dynamic groups.  
- Azure CLI : Utilized for storage account interrogations and key vault management.  
- Az PowerShell Module : Provides additional exploratory capabilities within Azure resources.  

## Usage
Just run APEX via IEX or .\APEX.ps1, however you like.
The first steps are to set a tenant and login to the three tools.
Afterwards it is all about the Queries and Attack menu.  
Leverage the built-in queries to quickly get an overview of the capabilities of your current account.  
Take advantage of combining the output of the three different tools, getting as much info as possible on the stuff you are interested in.  
Some features like the Storage and Key Vault menu allow easy navigation through available resources, making it a breeze to find the juice stuff and exfiltrate it.
More on this on YouTube: https://www.youtube.com/watch?v=wDbf-JVsW5c
