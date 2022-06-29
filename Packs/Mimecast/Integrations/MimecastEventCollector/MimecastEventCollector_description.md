## Mimecast Event Collector  

In order to retrieve your Mimecast credentials for XSIEM follow the instructions below. 

### Application id & Application key 
follow the next steps in your Mimecast application:  

Administration console -> Administration -> Services -> 
API and Platform Integrations -> Your Application Integrations   
- if you already have an application  
press the '3 dot' symbol and press view to retrieve your application id,   
application key.   
- else press 'Add API Application' and follow the instruction.   
  
### Secret Key & Access Key 

follow the instruction at:
Administration console -> Administration -> Services -> 
API and Platform Integrations -> Your Application Integrations
press the '3 dot' symbol and press 'Create Keys' 
follow the steps to retrieve your Access Key and Secret Key

Fair notice - for this step you may have to wait up to 20 minutes upon creation of a new API Application.
  
  
### Base URL 

Insert your custom base url or checkout 
[Mimecast base url](https://integrations.mimecast.com/documentation/api-overview/global-base-urls/)
inorder to find your base url. (example: https://us-api.mimecast.com) 

### Pre-requisites

##### Audit logs 
[Audit pre-requisites](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/#:~:text=Sample%20Code-,Pre,-%2Drequisites)

##### Siem logs
[Siem pre-requisites](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-siem-logs/#description:~:text=in%20logs%27%20downloaded.-,Pre%2Drequisites,-The%20data%20served)
