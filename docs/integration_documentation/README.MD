# Overview
Documentation is a critical step that assists customers who may use your integration by providing insight into how the integration is supposed to work. From creating custom playbooks, to providing background information to assist in debugging, it is important to ensure that the documentation explains every aspect of the integration.

## Creating Documentation
Within Demisto, exists the ability to generate documentation for your integration. First verify that the DocumentationAutomation script exists in your content by navigating to the **Automation** tab in Demisto.

If the script is not there, [you may download it here](https://github.com/demisto/content/blob/master/Scripts/script-DocumentationAutomation.yml)

First, take the YAML file of your integration and upload it to the War Room. Please note the entry ID as you will need it in the next step.

To use the DocumentationAutomation script, navigate to the War Room and execute the command:
 ```
!DocumentationAutomation entryID="the_entry_id_of_the_uploaded_yml_integration"
```
You may choose to include the other arguments depending on what you may need.

Once the command has been executed, you will see the documentation markdown file in the War Room as a new entry file. Download this file and open it in an IDE that supports markdown. We suggest either opening a Github issue, or a standalone program such as [Brackets](http://brackets.io/).

Where there is missing information, be sure to fill out the document completely. It is advised to include use-cases, screenshots, and examples of the context. 

## Documentation _must_ be generated if:
1.  If the integration is new then you are required to create new documentation
2.  If the integration is existing but missing documentation then please create new documentation
3.  If the integration is existing and some the integration has changed. For example, a new command was added, context was changed, or anything else; please update the documentation.


**The documentation must conform to [this format](https://github.com/demisto/etc/wiki/Document-structure:-Integrations)**


### Good documentation examples:

https://support.demisto.com/hc/en-us/articles/360004197454-Preempt - Shows how the commands and examples should be presented

https://support.demisto.com/hc/en-us/articles/360002253814-EWSv2 - Shows an example of the troubleshooting section

Example: 
![image](https://user-images.githubusercontent.com/7270217/40935346-7ca3b24a-6840-11e8-8540-b00677cd6657.png)
![image](https://user-images.githubusercontent.com/7270217/40935354-8406dcc4-6840-11e8-9b0c-b0a9c4bd8a99.png)


***
[Next step - Mapping](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BMapping%5D)
