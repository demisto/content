## Prerequisite - Connect to McAfee Threat Intelligence Exchange (TIE) using the DXL TIE Client
To connect the McAfee TIE using the DXL TIE client, you need to create certificates and configure DXL. For more information, see the [documentation](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-dxl#how-to-create-the-rsa-key-pair). After you complete this configuration, you will have the following files.
   * Broker CA certificates ('brokercerts.crt' file)
   * Client certificate ('client.crt' file)
   * Client private key ('client.key' file)
   * Broker list properties file ('brokerlist.properties' file)
   
**Important**: These are the actual certificates, not request certificates.

To use the `tie-set-file-reputation` command, you need to authorize the client (Cortex XSOAR) to run the command. Follow the [instructions](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html) to do so. In step 4, instead of selecting **Active Response Server API**, select **TIE Server Set Enterprise Reputation**.

## Dependencies (Python packages)
You don't need to install the packages, they are included in the Docker image.
  - DXL Client [documentation](https://opendxl.github.io/opendxl-client-python/pydoc/dxlclient.client.html)
  - DXL TIE Client [documentation](https://opendxl.github.io/opendxl-tie-client-python/pydoc/dxltieclient.client.html)
