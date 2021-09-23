Custom Indicator Demo is a demo integration that demonstrates the usage of the CustomIndicator helper class.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### test-custom-indicator
***
This command demonstrates the usage of CustomIndicator.


#### Base Command

`test-custom-indicator`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demo.Result.Output | String | Dummy output. | 

#### Context Example

```
DBotScore
[
	{
		"Indicator": "custom_value",
		"Score": 1,
		"Type": "MyCustomIndicator",
		"Vendor": "CustomIndicatorDemo"
	}
]
Demo.Result
{
	"dummy": "test"
}
custom
[
	{
		"Value": "custom_value",
		"param1": "value1",
		"param2": "value2"
	}
]
```

#### Command Example
``` !test-custom-indicator```

#### Human Readable Output
>custom_value

