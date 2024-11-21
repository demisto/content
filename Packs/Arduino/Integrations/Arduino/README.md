Connects to and controls an Arduino pin system using the network.

## Configure Arduino in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Hostname or IP | Hostname or IP | True |
| Port number | Port number | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### arduino-set-pin
***
Requests that a pin be set


#### Base Command

`arduino-set-pin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pin_type | The type of pin. Possible values are: digital, analog. Default is digital. | Required | 
| pin_number | The pin number to set. | Required | 
| value | The value to set the pin to. | Required | 
| host | Host name / IP address (optional - overrides parameters). | Optional | 
| port | Port number (optional - overrides parameters). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arduino.DigitalPins | unknown | Digital Pins | 
| Arduino.DigitalPins.PinNumber | number | PinNumber | 
| Arduino.DigitalPins.PinType | string | Pin Type | 
| Arduino.DigitalPins.PinValue | number | Pin Value | 
| Arduino.AnalogPins | unknown | Analog Pins | 
| Arduino.AnalogPins.PinNumber | number | PinNumber | 
| Arduino.AnalogPins.PinType | string | Pin Type | 
| Arduino.AnalogPins.PinValue | number | Pin Value | 

### arduino-get-pin
***
Requests the value of a pin


#### Base Command

`arduino-get-pin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pin_type | Pin type. Possible values are: digital, analog. Default is digital. | Required | 
| pin_number | The pin to read the value from. | Required | 
| host | Host name / IP address (optional - overrides parameters). | Optional | 
| port | Port number (optional - overrides parameters). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arduino.DigitalPins | unknown | Digital Pins | 
| Arduino.DigitalPins.PinNumber | number | PinNumber | 
| Arduino.DigitalPins.PinType | string | Pin Type | 
| Arduino.DigitalPins.PinValue | number | Pin Value | 
| Arduino.AnalogPins | unknown | Analog Pins | 
| Arduino.AnalogPins.PinNumber | number | PinNumber | 
| Arduino.AnalogPins.PinType | string | Pin Type | 
| Arduino.AnalogPins.PinValue | number | Pin Value | 

### arduino-send-data
***
Send arbitrary data to the Arduino


#### Base Command

`arduino-send-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The data to send. | Required | 
| host | Host name / IP address (optional - overrides parameters). | Optional | 
| port | Port number (optional - overrides parameters). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arduino.DataSend | unknown | Data Send | 
| Arduino.DataSend.Sent | string | The data sent | 
| Arduino.DataSend.Received | string | The data received | 