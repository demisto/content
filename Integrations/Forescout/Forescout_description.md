# Instructions

## Forescout Module Requirements
In order for this integration to operate there are requirements that must be setup from within the Forescout console.
In the Forescout console click on `Tools` in the navigation bar at the top of the window and click `Options`. In the resulting pop-up window, in the categories section on the left, click on `Modules`. In the main area of the pop-up window select `Openmodule Integration` and make sure that both `DEX` and `Web API` are both installed and enabled. If they aren't install them and enable them.

## Configuration Parameters

**url**  
This is the network address of the Forescout Enterprise Manager or standalone Appliance. (The host on which the the Forescout Appliance is hosted.) For example, if the Forescout Appliance is hosted at the IP address `192.168.10.23`, then one would enter `https://192.168.10.23`.

**Username** and **Password**  
The credentials entered here should be those created in the Forescout console for the Web API.
In the Forescout console click on `Tools` in the navigation bar at the top of the window and click `Options`. In the resulting pop-up window, in the categories section on the left, click on `Web API`. In the main area of the pop-up window create a username and password. These are the credentials that should be entered for the Demisto Forescout integration configuration parameters of `Username` and `Password`. Select the security settings in the main area of the pop-up window and either add the IP address where your Demisto instance is hosted or allow requests from all IP addresses in order to make sure that requests made by the Demisto Forescout integration will be permitted.

**Data Exchange (DEX) Username** and **Password**  
The credentials entered here should be those created in the Forescout console for DEX.
In the Forescout console click on `Tools` in the navigation bar at the top of the window and click `Options`. In the resulting pop-up window, in the categories section on the left, click on `DEX`. In the main area of the pop-up window select `CounterACT Web Console`. In the main area of the pop-up window create a username and password. These are the credentials that should be entered for the Demisto Forescout integration configuration parameters of `Data Exchange (DEX) Username` and `Password`. If the created username and password for DEX is identical to the credentials created for the Web API then you may leave these fields blank in the integration configuration. Note the `label` value for the account you created here as this is the value that you should enter for the `The Data Exchange (DEX) Account` configuration parameter.

**The Data Exchange (DEX) Account**  
The DEX credentials label. This can be found by navigating to `Tools` -> `Options` -> `DEX` -> `CounterACT Web Console`.

## Important Usage Notes
This integration allows the user to update host properties and Forescout Lists.
To create Forescout properties which may then be updated via Demisto's Forescout integration, navigate to `Tools` -> `Options` -> `DEX` -> `CounterACT Web Console` -> `Account Properties` in the Forescout Console. Create new properties here and associate them with the account you created and which you used in the configuration parameters of the Forescout integration in Demisto.
Lists must also be defined and created in the Forescout console before being able to update them using the Demisto integration. For more information, reference the `Defining and Managing Lists` section in the [Forescout Administration Guide](https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf).