### Group-IB Threat Intelligence & Attribution  
  
  
- This section explains how to configure the instance of Threat Intelligence & Attribution in Cortex XSOAR.  
  
1. Open Group-IB TI&A web interface. (It may be either new interface: [https://tap.group-ib.com](https://tap.group-ib.com) or old interface: [https://bt.group-ib.com](https://bt.group-ib.com))  
2. To generate API key(password):  
2.1. In old interface:  click on your name in right upper corner -> choose **Profile** option -> click on **Go to my setting** button under your name -> under **Change password** button you will see **API KEY generator** -> enter your password, click **Generate**,  then click **Save**. **Do not forget to save the API key**.  
2.2. In the new interface: click on your name in the right upper corner -> choose **Profile** option -> switch to **Security and Access** tab -> click **Personal token** -> follow instructions to generate API token.  
3. Your server URL is the same as your TI&A web interface URL.  
4. Your username is the email that you use to enter in the web interface.
5. Set classifier and mapper with Group-IB Threat Intelligence & Attribution classifier and mapper or with our own if you want so.
6. Go to Settings->Integrations->Pre-Processing Rules and set up the pre-processing rule:
* Set up conditions: "gibid Is not empty (General)" and "Type Doesn't equal(String) GIB Data Breach".
* Action: "Run a script".
* Script: "GIBIncidentUpdate" (will recreate closed incidents if they get an update, in other cases will update the existing one) or "GIBIncidentUpdateIncludingClosed"(will only update incidents). 
7. Don't forget to contact Group-IB to add to allow list your Cortex IP or public IP of a proxy that you are using with Cortex.
