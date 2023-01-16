Note: This integration is meant for testing purposes when developing playbooks or automations to download files from a web server. Do not use for public or production access.

### How to Access the File Management UI

#### Access the File Management UI by URL and Port (HTTP)
In a web browser, go to **http://<cortex-xsoar-server-address>:<listen_port>**.

#### Access the File Management UI by Instance Name (HTTPS)

To access the File Management UI by instance name, make sure ***Instance.execute.external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the `instance.execute.external.<instance_name>` key is set to `true`. If this key does not exist, click **+ Add Server Configuration** and add the `instance.execute.external.<instance_name>` and set the value to `true`. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3. In a web browser, go to `https://<cortex-xsoar-address>/instance/execute/<instance_name>/`.

   In Multi Tenant environments, go to `https://<cortex-xsoar-address>/acc_<account name>/instance/execute/<instance_name>/`