## How to Create the RSA Key Pair
Before you configure the ePO server, you need to generate the RSA key pair. Make sure that **openssl** is installed.
1. Open a new directory.
2. Download the [sh script](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys.sh.zip) and move it to the new directory.
3. Unzip the file.
4. Complete the required fields, except the challenge password and the optional company name (leave empty).  
The certificate (*client.crt*) is valid for 365 days (you can change the value in the script).

After the script finishes running, you should have the following files.
        - *client.key* (private key)
        - *client.crt* (public key)
        - *client.csr* (certificate request that is not required for the configuration flow)

## Configure the ePO Server
To configure the ePO server, you need to upload the public key.

1. In ePO server go to **Menu > Server Settings**.
    ![go to menu](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/go_to_menu.png)
    ![go to server settings](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/go_to_serevr_settings.png)
2. Under DXL certificates (Third Party) click **Edit**.
    ![click edit](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/click_edit.png)
3. download the brokers certificate.
    ![export Broker certificates](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/export_Broker_certificates.png)
4. Download the brokers list.
    ![export Broker list](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/export_Brocker_list.png)
5. Click **Import** and select the *client.crt* file.
    ![click import](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/click_import.png)
    ![select client.crt file](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/select_client.crt_file.png)
    ![click ok](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/click_ok.png)
6. Click **Save**.
    ![click save](https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys/img/click_save.png)
7. Test the integration (it may take a few minutes until the key is enabled).
