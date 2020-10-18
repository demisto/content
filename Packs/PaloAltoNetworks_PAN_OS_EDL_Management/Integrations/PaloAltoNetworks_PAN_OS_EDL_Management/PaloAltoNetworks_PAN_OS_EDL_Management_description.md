 ## Set Up a Remote Web Server
 To use the Palo Alto Networks PAN-OS EDL Management integration, you need to set up a remote web server.
 1. Set up a remote server with Apache.
 2. Generate a pair of SSH keys. Send the private key into the user’s home directory, into “.ssh” folder in the Apache server. 
    Append it to the “authorized_keys” file.
 3. Save the private SSH key in Demisto Credentials.
 4. To verify the location of the document root where the files are stored, run the following command.
   - **CentOS**: `"httpd -S"` 
   - **Ubuntu**: `apcahe2 -S"`

