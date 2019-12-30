Most IT services are moving from on-premise solutions to cloud-based solutions. The public IP addresses, domains and URL's that function as the endpoints for these solutions, are very often not fixed and the providers of the service publish their details on their websites in a less than ideal format (i.e.: HTML) rather than through a proper REST API (i.e.: JSON).

This fact makes it very difficult for IT and Security teams to provide these services with an appropriate level of security and automation. Any changes in the HTML schema of the provider website, will break the automation and has the potential to cause serious disruption to the users and the business. The alternative is to compromise on the security posture of the organization.

One example of these providers is Microsoft, and an example of their services is [Microsoft Intune](https://en.wikipedia.org/wiki/Microsoft_Intune).

The goal of this pack is to address this issue by automating the collection of endpoint data, performing validation and pushing the changes to an EDL that can be consumed automatically by security enforcement technologies (i.e.: firealls, proxies, etc.).

The most important element in the provided playbook is the inclusion of a human decision checkpoint in the process. Any changes in the list of endpoints will halt the process until a human analyst reviews the information (which is neatly provided) and takes the appropriate decision.

## Requirements
* Integrations
    - Palo Alto Networks PAN-OS EDL Management
    
        This is the server that will host the EDL file. It requires SSH authentication with certificate

    - Palo Alto Networks MineMeld
    
        A miner based on stdlib.localDB prototype is required

* Scripts
    - GetMSFTIntuneEndpointsList
    
        This script scrapes Microsoft Intune endpoints website, compares the list of entries with the current list and provides the results of the analysis to the analyst.

        The result of the scrape will clearly indicate when there have been relevant changes to the website. In such case, the analyst will need to review the script and/or open a ticket with Demisto Support notifying the issue.

* Docker Image

    The script above requires a Docker image with Python3 and BeautifulSoup.

    The image can be created from the War Room or Playground with the following command:

    ```
    /docker_image_create <image_name> base=demisto/python3:3.7.5.4583 dependencies=bs4
    ```

    Where <image_name> is the name of the new image to be created. 
    
    This image will need to be linked to the automation GetMSFTIntuneEndpointsList script settings, under Advanced --> Docker image name

## Playbook Instructions
The playbook requires the following inputs:
- EDL Filename. Name of the file with the EDL entries hosted on the Web Server (i.e.: msft-intune.txt). And/or
- MineMeld Miner name (based on localdb prototype). This is needed in order to update Minemeld when there are any changes
- An internal Demisto list named "msft-intune" will be created (unless already existed). This name should not be changed







