This ingratiation requires a Stealth account with the Portal Administrator role. Also, you must ensure that a Global isolation role has been created. Please see EcoAPI documentation for you specific Stealth version. 

## Setting Up XOAR Engine: 
1. Ensure that you have at least one XSOAR engine installed on your corporate network. 
2. Install Stealth Client on XSOAR Engine. 
3. If #2 does not work, you may need to create an exception of the engine within Stealth EM console. 

Recommended to have at least one XSOAR engine that is installed on your corporate network. Under `Run on` select the XSOAR engine you wish to use for the integration. 

## Setting up the Stealth XSOAR Integration: 
1. Enter your EM IP Address or hostname (without port number or http:// or HTTPS://) `Example: 172.168.1.1`
2. Enter the Stealth EcoAPI Port (default 8448)
3. Enter your Stealth username (must have Portal Administrator role) and password. 
4. Run the `!stealth-get-stealth-roles` command within the playground and copy the `ID` of the Global Isolation role. 
5. Enter the ID copied in step #4 into the Isolation Role ID parameter. 
