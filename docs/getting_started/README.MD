## The Demisto IDE
It is important to take a moment and familiarise yourself with the Demisto IDE as it may work differently than other IDEs you are familiar with. Some key differences between the Demisto IDE and ,for example pyCharm, is the absence of an interpreter. You will have to be mindful of Demisto reserved variables as you develop your integration. **(See Reserved Variables) **

### The Script Helper
Demisto is equipped with a script helper which is accessible via the button below:

<img src="https://github.com/demisto/etc/blob/master/.web/script-helper.png?raw=true" width="100" align="middle">


The script helper will open up a flyout menu which presents all of the functions that are part of the common server. If you are trying to accomplish something that may seem trivial, check the script helper as a function for it may already exist.

<img src="https://github.com/demisto/etc/blob/master/.web/script-helper-flyout.png?raw=true" width="350" align="middle">

## The Settings Menu
The settings menu contains configurations for Basic Settings, Parameters, Detailed Instructions, Commands and Script settings. Clicking the **Settings** button <img src="https://github.com/demisto/etc/blob/master/.web/settings-button.png?raw=true" width="100" align="middle"> will open a flyout menu as seen below:
<img src="https://github.com/demisto/etc/blob/master/.web/settings-menu.png?raw=true" width="700" align="middle">

### Basic Settings
In the basic settings menu, is where we give an integration the following:
* **Integration Name** - This is what the display name will be for the integration.
* **Description** - This is a basic description of what the integration does and displays in the integration menu.
* **Type** - Denotes what type of integration we are building. Please note: This setting is required.
* **Fetches Incidents** - If the integration pulls events periodically, we must have this setting enabled.

### Parameters
Parameters are fields which are required for the integration to function properly. This is where we configure a proxy, set API keys, as well as set other global variables for the integration. Parameters have the following configurable settings:
* **Parameter Name** - This is the name of the variable we will use in our integration. Please note that these names need to follow standard python/JS naming conventions.
* **Select Type** - The type of variable being used.
* **Mandatory** - The parameter is required in order for the integration to operate.
* **Initial Value** - The default value for the given parameter.
* **Display Name** - This is the name for the parameter that will be visible in the menu to create an instance.

Add additional parameters with the (+) symbol at the bottom of the menu.

### Detailed Instructions
Use this section to include a "How to" for the integration as well as some common troubleshooting steps. These instructions need to help the user to configure the instance/connection. If there are special user permissions that are required, or the user needs to create an api key, or if a special port need to be configured. Additionally, it is advised to link to the original product's documentation. This section supports markdown.

### Commands
The Command menu consists of the command name and details, as well as Arguments, Outputs, and Important.
* **Command Name** - The name given for the command. Is used by entering ```!command-name``` in the command-line.
* **Potentially Harmful** - Use this to indicate that the command runs scripts that my be seen as harmful.
* **Description** - Seen in the command-line, the description should include an example of how the command is executed, as well as a brief summary of what the command does.

### Arguments
Arguments are variables for a command that are dynamic and can be changed each time the command is executed. For example ```!test-command query="This is an example"``` Shows "query" as an argument for the command "test-command". The configurable fields for arguments are listed below:
* **Argument** - The name used for the argument and should follow Python/JS naming conventions.
* **Mandatory** - If the argument is required, tick this checkbox.
* **Default** - When enabled, the command will always use this argument with its default setting, unless changed.
* **Description** - A brief description of the argument. Should also include an example.
* **Is Array** - Indicates that the argument is an array of variables.
* **List Options** - Add options separated by a comma to include a dropdown list of options for the argument.

### Outputs
Please [read here](/docs/context_and_ouputs/README.MD) to learn more about Outputs and Context.

## Content development lifecycle
1. [Define/gather use cases](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BUse-cases%5D)
2. [Design of the integration and the commands](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BDesign%5D/_edit)
3. Implementation and code conventions in [JavaScript](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BImplementation-in-JavaScript%5D) or [Python](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BImplementation-in-Python%5D)
4. [Test the integration and add test playbook](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BTests%5D)
5. [Add documentation](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BDocumentation%5D)
6. [Mapping/Incident Types/Layouts/Custom Fields](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BMapping%5D)






