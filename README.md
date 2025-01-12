# APEX (previously AzurePwn)- Azure Post Exploitation Framework  

An attempt to ease up post ex tasks once we have access to some sort of credentials to an Azure related account.  
To be honest it is nothing new or spectacular. Just my old lazy ass doing some shortcuts so I don't need to remember all the commands I need over and over again.

## Architecture  
APEX is built on a modular architecture combining:  
- Microsoft Graph PowerShell Module : For accessing and querying Azure AD resources and dynamic groups.  
- Azure CLI : Utilized for storage account interrogations and key vault management.  
- Az PowerShell Module : Provides additional exploratory capabilities within Azure resources.  

It has pre-buildin queries and attacks which you can use to speed things up and to also not forget to check certain stuff.

## Usage
Just run APEX via IEX or .\APEX.ps1, however you like.  
Make sure to use PS7 as some functions might not be available or work with lower PowerShell versions.
The first steps are to set a tenant and login to the three tools.
Afterwards it is all about the Queries and Attack menu.  
Leverage the built-in queries to quickly get an overview of the capabilities of your current account.  
Take advantage of combining the output of the three different tools, getting as much info as possible on the stuff you are interested in.  
Some features like the Storage and Key Vault menu allow easy navigation through available resources, making it a breeze to find the juice stuff and exfiltrate it.
More on this on YouTube: https://www.youtube.com/watch?v=wDbf-JVsW5c

![APEX](https://github.com/user-attachments/assets/ec80621d-93e2-42d7-8714-6ee02c01dfa5)

![APEX1](https://github.com/user-attachments/assets/c16d1399-a7cf-4888-9ff0-37529a2218d3)
