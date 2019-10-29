## Intro
You can use long running containers to run specific processes in an integration forever.

## Getting Started

### Prerequisites
In order to implement and run long running integrations, you need a Demisto v5.0 and later.

The integration must be written in Python.

### First step
To make an integration long running, you need to enable the `longRunning` property:
![image](https://user-images.githubusercontent.com/35098543/66122533-9b2b7280-e5e8-11e9-92de-f9fbe75b7250.png)

You will then have the `Long running instance` parameter:
![image](https://user-images.githubusercontent.com/35098543/66122634-e6458580-e5e8-11e9-9030-6514832c9422.png)

If you check the checkbox, the server will launch a long running container each time an instance is enabled. When the checkbox is unchecked or the instance is disabled, the container will die.
You can distinguish it from the rest of the containers by its name:
![image](https://user-images.githubusercontent.com/35098543/66122754-2d337b00-e5e9-11e9-8775-562e228e3fe6.png)


## Implementation
When the container runs, it calls a dedicated command in the integration, much like fetch-incidents. The command is called `long-running-execution` 
You'll have to implement it in your integration code. In order to run this code forever, you will need it to never stop executing, for example - a never ending loop (`while True`).

### Interaction with the server
Since the long running container does not run in a scope of an incident, it has no standard place to output results into.
For that we have dedicated functions to interact with the server:
* `addEntry` - Adds an entry to a specified incident War Room.
* `createIncidents` - Creates incidents according to a provided JSON. Unlike `demisto.incidents()`, this function requires actual incident fields in the JSON argument.
For example - `{'name': 'incident', 'type': 'Phishing', 'customFields': {'field1': 'value'}`.
* `findUser` - Find a Demisto user by a name or email. Useful for creating incidents.
* `handleEntitlementForUser` - Adds an entry with entitlement to a provided investigation.
* `updateModuleHealth` - Update the instance status. It's a way to reflect the container state to the user.
![image](https://user-images.githubusercontent.com/35098543/66123930-cb284500-e5eb-11e9-804d-6154423e6cee.png)
* `mirrorInvestigation` - For chat based integrations, mirror a provided Demisto investigation to the corresponding chat module.
* `directMessage` - For chat based integrations, handle free text sent from a user to the chat module and process it in the server.

### Manage container states 
One of the most important and useful things in the long running process is the integration context:
`demisto.setIntegrationContext(context)`
`demisto.getIntegrationContext()`
Use it to store information and manage the state of the container per integration instance.
This context is stored in a format of a dict of `{'key': 'value'} where value **must** be a string. To store complex objects as values, parse them to JSON.

Use logging to notify and report different states inside the long running process - `demisto.info(str)` and `demisto.error(str)`. These will show up in the server log.

## Troubleshooting
Use `updateModuleHealth`, `info` and `error` to report errors and debug. It's also important to segregate the logic into functions so you'll be able to unit test them.

## Best practices
It's important to maintain a never ending process in the container. That means:
1. Never use `sys.exit()` (`return_error` and friends).
2. Always catch exceptions and log them.
3. Run in a never ending loop.

To run multiple processes in parallel, you can use async code. For an example you can check out the `Slack v2` or `Microsoft Teams` integrations.





