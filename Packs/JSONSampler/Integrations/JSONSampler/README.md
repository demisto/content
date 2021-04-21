Save the string of a JSON object for simulating the fetching of incidents.
This can also be used to test classifiers and mappers on static incoming data.
Currently supports only single JSON object as sample.

## Configure JSONSampler on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for JSONSampler.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Fetch incidents | False |
    | Incident type | False |
    | Incidents Fetch Interval | False |
    | The raw JSON string to use as the sample data | True |
    | The incident name to give to the created incident | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sampler
***
Sample the provided JSON and return the results to the Context and Warroom.  Can use key and value arg to change a JSON values if desired.


#### Base Command

`sampler`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | The key to change.  Must also set value arguement.  Can be comma separated to change multiple values. | Optional | 
| value | The new key value. Must also set key argument. Can be comma separated to support changing multiple values. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sampler key="somekey" value="somevalue"```

#### Context Example
```json
{
    "JSON": {
        "Sample": {
            "IP": "8.8.8.8",
            "Name": "Suspected Web Monitoring",
            "Type": "Malware",
            "somekey": "somevalue"
        }
    }
}
```

#### Human Readable Output

>### Results
>|IP|Name|Type|somekey|
>|---|---|---|---|
>| 8.8.8.8 | Suspected Web Monitoring | Malware | somevalue |

