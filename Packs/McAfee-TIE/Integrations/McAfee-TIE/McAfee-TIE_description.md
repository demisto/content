## Prerequisite - Connect to McAfee Threat Intelligence Exchange (TIE) using the DXL TIE Client
To connect the McAfee TIE using the DXL TIE client, you need to create certificates and configure DXL. For more information, see the [DXL documentation](https://github.com/demisto/content/blob/master/Packs/McAfee_DXL/Integrations/McAfee_DXL/README.md). After you complete this configuration, you will have the following files.
   * Broker CA certificates ('brokercerts.crt' file)
   * Client certificate ('client.crt' file)
   * Client private key ('client.key' file)
   * Broker list properties file ('brokerlist.properties' file)
   
**Important**: these are the actual certificates, not request certificates.

To use the ***tie-set-file-reputation*** command, you need to authorize the client (Demisto) to run the command. Follow the instructions in the [OpenDXL documentation](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html). In step #4, instead of selecting **Active Response Server API**, select **TIE Server Set Enterprise Reputation**.

## Dependencies (Python packages)
You don't need to install the packages, they are included in the Docker image.
  - dxlclient [docs](https://opendxl.github.io/opendxl-client-python/pydoc/index.html)
  - dxltieclient [docs](https://opendxl.github.io/opendxl-tie-client-python/pydoc/)
