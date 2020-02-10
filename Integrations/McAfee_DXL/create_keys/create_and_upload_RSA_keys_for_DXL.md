## how to configure DXL based integration
- create RSA key pair.
    - make sure that **openssl** is installed
    - open a new directory.
    - download the sh script https://github.com/demisto/content/raw/master/Integrations/McAfee_DXL/create_keys.sh.zip and move to the directory.
    - unzip the file run.
    - fill out the required fields except the challenge password and the optional company name (leave it empty).
- upload the public key.
    - In ePO server go to Menu -> Server Settings.
    ![go to menu](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/go_to_menu.png)
    ![go to serevr settings](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/go_to_serevr_settings.png)
    - under DXL certificates (Third Party) click edit.
    ![click edit](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/click_edit.png)
    - download the brokers certificate.
    ![export Broker certificates](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/export_Broker_certificates.png)
    - download the brokers list.
    ![export Brocker list](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/export_Brocker_list.png)
    - click import and select `client.crt` file click ok and upload it.
    ![click import](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/click_import.png)
    ![select client.crt file](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/select_client.crt_file.png)
    ![click ok](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/click_ok.png)
    - click save.
    ![click save](https://github.com/demisto/content/raw/dxl_exemple/Integrations/McAfee_DXL/create_keys/img/click_save.png)
- test the integration (it may take a while before the key will be enable).
