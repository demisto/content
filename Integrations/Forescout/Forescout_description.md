# Instructions

## Forescout Module Requirements
Before you can use this integration in Demisto, you need to enable certain modules in your Forescout environment.
1. In the Forescout console, from the navigation bar select *Tools > Options*.
2. In the dialog that appears, from the categories section on the left, click *Modules*. 
3. In the main area of the dialog, from the drop-down menu, select *Open Integration Module*. 
Make sure that the integration module and the following submodules are installed and enabled: *Data Exchange (DEX)* and *Web API* are all installed and enabled. If they aren't, install and enable them.

## Configuration Parameters

**url**  
This is the network address of the Forescout Enterprise Manager or standalone Appliance. (The host on which the the Forescout Appliance is hosted.) For example, if the Forescout Appliance is hosted at the IP address *192.168.10.23*, then one would enter *https://192.168.10.23*.

**Web API Username** and **Password**  
The credentials entered here should be those created in the Forescout console for the *Web API*.
In the Forescout console click on *Tools* in the navigation bar at the top of the window and click *Options*. In the resulting pop-up window, in the categories section on the left, click on *Web API*. Select *User Settings* near the top of main area of the pop-up window. Create a username and password by clicking the *Add* button at the right of the window and filling out the presented fields. These are the credentials that should be entered for the Demisto Forescout integration configuration parameters of *Web API Username* and *Password*. Select *Client IPs* towards the top of the main area of the pop-up window next to *User Settings*. Now, either add the IP address where your Demisto instance is hosted or allow requests from all IP addresses in order to make sure that requests made by the Demisto Forescout integration will be permitted. Click the *Apply* button at the bottom right of the pop-up window to save the changes you made.

**Data Exchange (DEX) Username** and **Password**  
The credentials entered here should be those created in the Forescout console for *Data Exchange (DEX)*.
In the Forescout console click on *Tools* in the navigation bar at the top of the window and click *Options*. In the resulting pop-up window, in the categories section on the left, click on *Data Exchange (DEX)*. In the main area of the pop-up window, towards the top, select *CounterACT Web Service*. Select *Accounts* from the sub-menu that appeared after you clicked *CounterACT Web Service*. In the main area of the pop-up window create a username and password by clicking the *Add* button and filling out the presented fields. **Note**: The value you entered for the *Name* field in the account-creation pop-up window is the value that you should enter for the *Data Exchange (DEX) Account* configuration parameter. Click the *Apply* button at the bottom right of the pop-up window to save the changes you made. The username and password entered in the account-creation pop-up window are the credentials that should be entered for the Demisto Forescout integration configuration parameters of *Data Exchange (DEX) Username* and *Password*.

**Data Exchange (DEX) Account**  
The *Data Exchange (DEX)* credentials *Name* field. This can be found by navigating to *Tools* -> *Options* -> *Data Exchange (DEX)* -> *CounterACT Web Service* -> *Accounts*.

## Important Usage Notes
This integration allows the user to update host properties and Forescout Lists.
To create Forescout properties which may then be updated via Demisto's Forescout integration, navigate to *Tools* -> *Options* -> *Data Exchange (DEX)* -> *CounterACT Web Console* -> *Properties* in the Forescout Console. Create new properties here and make sure to associate them with the account you created and which you used in the configuration parameters of the Forescout integration in Demisto.
Lists must also be defined and created in the Forescout console before being able to update them using the Demisto Forescout integration. For more information, reference the *Defining and Managing Lists* section in the [Forescout Administration Guide](https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf).
