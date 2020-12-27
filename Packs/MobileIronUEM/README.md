MobileIron UEM is the foundation for the industry’s first mobile-centric, security platform. 
With MobileIron, organizations can quickly and easily onboard devices and provision them over the 
air with all of the apps, settings, and security configurations needed to protect any iOS, macOS, Android and Windows 10 
endpoint across your digital workplace. 
MobileIron’s zero trust approach ensures that only authorized users, devices, apps, and services can access business resources.
 Users enjoy a seamless and productive experience during enrollment and the single console enables IT administrators 
 to reduce the complexity and cost of managing a fleet of endpoints.

##### Platform compatibility

This MobileIron UEM content pack contains the integration with both UEM platforms that MobileIron offers:
- **MobileIron Core** - an On-Premise solution
- **MobileIron Cloud** - a SAAS offering for device management

The pack contains the corresponding custom MobileIron UEM incident fields, mappers and layouts to facilitate analyst investigation.

##### Requesting a trial
Anyone interested on trying the MobileIron platform and this integration can request a **free trial** through the [mobileiron website](https://mobileiron.com)

#### What does this pack provide?

- commands to fetch device data based on certain common attributes such as wifi mac address, device UUID, serial number and ip address
- an option to fetch device data based on custom queries based on the MobileIron API Query DSL for the respective platform
- commands to execute device specific actions such as retire, wipe, send message etc.. 
- ability to fetch and create incidents based on device data contained within MobileIron 
- sample playbooks demonstrating how remediation actions can be set-up to respond to device incidents
- custom layout and incident mapper to better show the relevant data when using fetch incidents

More information on the different ways to query the API can be found inside the platform specific API documentation:
- [Documentation for MobileIron Core](https://help.mobileiron.com/s/mil-productdoclistpage?Label=Core&Id=a1s3400000240gaAAA&Name=MobileIron+Core)
- [Documentation for MobileIron Cloud](https://help.mobileiron.com/s/mil-productdoclistpage?Label=Cloud&Id=a1s3400000240gfAAA&Name=MobileIron+Cloud)

This integration also focuses on providing a very similar set of functionalities between Core and Cloud 
as to ease the work needed when the customer moves from one MobileIron UEM platform to the other.  