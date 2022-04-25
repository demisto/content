# Instructions

## Forescout CounterACT Module Requirements
Before you can use this integration in Cortex XSOAR, you need to enable certain modules in your Forescout environment.
1. In the Forescout CounterACT console, from the navigation bar select *Tools > Options*.
2. In the dialog that appears, from the categories section on the left, click *Modules*. 
3. In the main area of the dialog, from the drop-down menu, select *Open Integration Module*. 
Make sure that the integration module and the following submodules are installed and enabled: *Data Exchange (DEX)* and *Web API* are all installed and enabled. If they aren't, install and enable them.

## Configuration Parameters

**url**  
This is the network address of the Forescout Enterprise Manager or standalone Appliance. (The host on which the the Forescout Appliance is hosted.) For example, if the Forescout Appliance is hosted at the IP address *192.168.10.23*, then you enter *https://192.168.10.23*.

**Web API Username** and **Password**  
The credentials entered here should be those created in the Forescout CounterACT console for the *Web API*.
1. In the Forescout CounterACT console, from the top navigation bar,  click *Tools > Options*. 
2. From the dialog that appears, in the categories section on the left, click *Web API*, and select *User Settings*.
3. Create a username and password by clicking the *Add* button, and completing the fields. These are the credentials that you will enter when configuring the Cortex XSOAR-Forescout integration: *Web API Username* and *Password*. 
4. Select *Client IPs* towards the top of the main area of the dialog, next to *User Settings*. 
5. Add the IP address where your Cortex XSOAR instance is hosted or allow requests from all IP addresses to make sure that requests made by the Cortex XSOAR-Forescout integration will be permitted. 
5. Click the *Apply* button to save the changes you made.

**Data Exchange (DEX) Username** and **Password**  
The credentials entered here should be those created in the Forescout CounterACT console for *Data Exchange (DEX)*.
1. In the Forescout CounterACT console, from the top navigation bar,  click *Tools > Options*.
2. From the dialog that appears, in the categories section on the left, click *Data Exchange (DEX)*. 
3. Select *CounterACT Web Service > Accounts*. 
4. Create a username and password by clicking the *Add* button, and completing the fields. **Note**: The value you entered for the *Name* field in the account-creation pop-up window is the value that you should enter for the *Data Exchange (DEX) Account* configuration parameter. 
5. Click the *Apply* button to save the changes you made. 

The username and password inserted in the account-creation dialog are the credentials that you will enter when configuring the Cortex XSOAR-Forescout integration: *Data Exchange (DEX) Username* and *Password*.

**Data Exchange (DEX) Account**  
The *Data Exchange (DEX)* credentials *Name* field. This can be found by navigating to *Tools > Options > Data Exchange (DEX) > CounterACT Web Service > Accounts*.

## Important Usage Notes
This integration allows the user to update host properties and Forescout Lists.
To create Forescout properties, which can then be updated using the Cortex XSOAR-Forescout integration, from the Forescout console, navigate to *Tools > Options > Data Exchange (DEX) > CounterACT Web Console > Properties*. This is where you create new properties. Make sure to associate the properties with the account you created, and which you used in the configuration parameters of the Forescout integration in Cortex XSOAR.
Lists must also be defined and created in the Forescout console before you can update them using the Cortex XSOAR-Forescout integration. For more information, reference the *Defining and Managing Lists* section in the [Forescout Administration Guide](https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf).
