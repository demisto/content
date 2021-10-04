### Prerequisites - Connect to McAfee Active Response (MAR) using the DXL MAR client.
  - Create certificates & configure dxl. (see: https://github.com/demisto/content/blob/master/Packs/McAfee_DXL/Integrations/McAfee_DXL/README.md)
  - You must have the following files:
    - Broker CA certificates (`brokercerts.crt` file)
    - Client certificate (`client.crt` file)
    - Client private key (`client.key` file)
  - copy and paste the files content to the fields.
  - from `brokerlist.properties` copy IP and port to dxl servers.
  - [Enable MAR Search API](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html)

### API Documentation:
MAR docs - [Here](https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26820/en_US/mar_200_pg_0-00_en-us.pdf)

### Dependencies (Python packages) - No need to install, already installed in docker image :
dxlclient [docs](https://opendxl.github.io/opendxl-client-python/pydoc/index.html)
dxlmarclient [docs](https://opendxl.github.io/opendxl-mar-client-python/pydoc/)
