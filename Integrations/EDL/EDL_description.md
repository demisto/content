You can access the EDL service via **https://*demisto_address*/instance/execute/*instance_name*** or via **http(s)://*demisto_address*:*listen_port***
To access by instance name make sure ***Instance execute external*** is enabled. 
To enable ***Instance execute external*** go to Settings->About->Troubleshooting. Make sure that under **Server Configuration**
you have ***instance.execute.external*** set to true, if not then click on *+ Add Server Configuration* and add in Key *instance.execute.external* and in Value *true* 
