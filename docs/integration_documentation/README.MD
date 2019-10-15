# Overview
Documentation is a critical step that assists customers who may use your integration by providing insight into how the integration is supposed to work. From creating custom playbooks, to providing background information to assist in debugging, it is important to ensure that the documentation explains every aspect of the integration.

## Creating Documentation
Within Demisto, exists the ability to generate documentation for your integration. First verify that the DocumentationAutomation script exists in your content by navigating to the **Automation** tab in Demisto.

First, take the YAML file of your integration and upload it to the War Room. Please note the entry ID as you will need it in the next step.

To use the HTMLDocsAutomation script, navigate to the War Room and execute the command:
 ```
!HTMLDocsAutomation entryID="the_entry_id_of_the_uploaded_yml_integration"
```
You may choose to include the other arguments depending on what you may need.

Once the command has been executed, you will see the documentation html in the War Room as a new entry and a copy of it as a file entry. Review the generated document.

Where there is missing information, be sure to fill out the document completely. It is advised to include use-cases, screenshots, and examples of the context. 

## Documentation _must_ be generated if:
1.  If the integration is new then you are required to create new documentation.
2.  If the integration is existing but missing documentation then please create new documentation.
3.  If the integration is existing and some of the integration has changed. For example, a new command was added, context was changed, or anything else; please update the documentation.


**The documentation must conform to [this format](https://github.com/demisto/content/blob/master/docs/integration_documentation/integration_documentation_structure.md)**


### Using commands parameter
To automatically generate example output (human readable and context), you should create a text file containing command examples, one per line. The command examples should appear the same way they would as in the CLI in Demisto, for example `!url url=8.8.8.8`.
Commands will be executed one at a time, in the order in which they appear in the file. If there are duplicates of a command included in the text file, only the output of the command's first execution  will be included in the generated documentation output.

Example for commands file: [commands.txt](https://github.com/demisto/content/blob/master/docs/integration_documentation/commands.txt)


![ScreenRecording2019-09-22at16241](https://user-images.githubusercontent.com/31018228/65404184-313ced00-dde0-11e9-9257-e61e2943fd75.gif)


### Good documentation examples:

https://support.demisto.com/hc/en-us/articles/360004197454-Preempt - Shows how the commands and examples should be presented

https://support.demisto.com/hc/en-us/articles/360002253814-EWSv2 - Shows an example of the troubleshooting section

Example: 
![image](https://user-images.githubusercontent.com/7270217/40935346-7ca3b24a-6840-11e8-8540-b00677cd6657.png)
![image](https://user-images.githubusercontent.com/7270217/40935354-8406dcc4-6840-11e8-9b0c-b0a9c4bd8a99.png)


### Posting Documentation
The documentation should be posted in the integration/automation script package directory as `README.md`


***
[Next step - Mapping](https://github.com/demisto/etc/wiki/Creating-an-Integration-in-Demisto-%5BMapping%5D)
