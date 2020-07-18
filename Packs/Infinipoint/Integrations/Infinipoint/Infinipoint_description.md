## Generate Infinipoint API Key:
To generate Infinipoint API Key, go to the API Keys tab in the Tenant Settings page under the settings menu.
Click "Generate API Key" to create a new API Key.
Generating an API Key will allow you to use Infinipoint's APIs by generating JWT tokens.

Email: support@infinipoint.io

####
-V#1 -V-where to find api key in the pro ? until UI ... 
V#2 -V- change name of page size with info - Gilad ? Can we remove this ? yes
V#3 -V- add proxy - handle_proxy - add to yml file as well ? 
V#4 -@@ https://xsoar.pan.dev/docs/integrations/integration-cache - add store token ?? NO 
V#5 -@@ timestamp_to_datestring -> 
V #6 -@ remove the $ -> ?? not now - stay 
V#7 -V- https://xsoar.pan.dev/docs/integrations/context-and-outputs#return-cve-reputation 
#8 -V- unitest 
#9 -V- https://xsoar.pan.dev/docs/playbooks/generic-polling
#10 - custom icednt type - https://xsoar.pan.dev/docs/incidents/incident-customize-incident-layout 
V#11 -V- add luminate intgraion - add discovery details  



unitesting - Take a look at my unitesting here: 

When I tried to run "demisto-sdk lint -i Packs/Infinipoint" I get 1 fail on this test. 
And the reason is there are missing parameters like "BASE_URL" and ect  