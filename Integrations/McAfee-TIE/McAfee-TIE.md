  ### Prerequisites - Connect to McAfee Threat Intelligence Exchange (TIE) using the DXL TIE client.
  [Create certificates & configure dxl](https://opendxl.github.io/opendxl-client-python/pydoc/index.html). After this phase you must have:
   * Broker CA certificates ('brokercerts.crt'  file)
   * Client certificate ('client.crt' file)
   * Client private key ('client.key' file)
   * Broker list properties file ('brokerlist.properties' file)

   To use 'tie-set-file-reputation' - you must have an appropriate permission. Follow [this insructions](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html), and ** with the exception of swapping the 'Active Response Server API' in 'TIE Server Set Enterprise Reputation'**

  ### Dependencies (Python packages) - No need to install, already installed in docker image :
  dxlclient [docs](https://opendxl.github.io/opendxl-client-python/pydoc/index.html)
  dxltieclient [docs](https://opendxl.github.io/opendxl-tie-client-python/pydoc/)