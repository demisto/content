## Get a FireWall API Key
  To use this integration, you need a Firewall API key.
  1. Log in to your Palo Alto NGFW console.
  2. Add a role to Device --> Admin Roles
  3. Enable XML/REST API features
  4. Add a user to Administrators
  5. Choose the new role you created in profile

  ## Configure Demisto
  1. Enter your newly created username and password to your Integration instance
  2. Go to the command line of XSOAR and use the ##!panos-get-api-key## command
  3. Enter the key generated in the playground into your Integration instance
  4. Now you can use the Test Button