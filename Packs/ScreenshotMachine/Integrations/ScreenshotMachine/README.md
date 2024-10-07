Uses screenshot machine to get a screenshot
## Configure Screenshot Machine in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Api Key | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### screenshot
***
Retrieve screenshot


#### Base Command

`screenshot-machine-get-screenshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to screenshot. | Required | 
| device | Capture as desktop, mobile, tablet. Possible values are: desktop, mobile, tablet. Default is desktop. | Optional | 
| dimension | Dimensions to capture. Possible values are: 320x240, 800x600, 1024x768, 1920x1020, 1240xfull. Default is 1024xfull. | Optional | 
| cacheLimit | Allows cached images (up to max lifetime of 1 day). Possible values are: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14. Default is 1. | Optional | 
| delay | Delay before capturing image. Possible values are: 200, 400, 600, 800, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000. Default is 200. | Optional | 
| md5Secret | leave secret phrase empty, if not needed. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output

