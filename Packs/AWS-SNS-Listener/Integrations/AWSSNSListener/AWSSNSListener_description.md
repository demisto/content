## AWS-SNS-Listener Help

In order to configure the AWS-SNS-Listener

XSOAR6

* http: configure an endpoint and a free port for the internal long running server.
* https: In addition to http configuration please add a CA certificate and private
* key AWS-SNS works only with CA certificates.
* Another option is via engine. 
   
Configuring the subscriber on AWS-SNS UI is straightforward:
```http/https://<instance-name_or_IP>:<port>/<endpoint_configured>```
For more general information on long running integrations on XSOAR6:
[XSOAR6 Long Running](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke)

XSOAR8 or XSIAM:

* The instance should be configured to run only on HTTP. 
* The instance is using the HTTPS certificate of the server.
* Please set a user and password (can be global via long running integrations configurations)
* or local for this integration only.
   
Configuring the subscriber on AWS-SNS UI:
```https://<username:password>@ext-<cortex-xsoar-address>/xsoar/instance/execute/<instance-name>```

example:
```https://user:pass@ext-myxsoar-address/xsoar/instance/execute/My-AWS-SNS-Listener/sns_ep```

For more info on long running integrations on XSOAR8 or XSIAM:
[XSOAR8 or XSIAM Long Running](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations)