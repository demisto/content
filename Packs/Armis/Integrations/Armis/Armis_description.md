## Armis
Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies
threats, and takes action automatically to protect critical information and systems.  

---------------------------------

##Configuring the Armis Instance  

 - Allocate a unique name for the instance
 - Choose fetch instances (for automatic ingestion of alerts from Armis into XSOAR).  
 - Ensure classifier is initialised with Armis classifier provided.
 - Ensure mapper is initialised with Armis mapper provided
 - In Server Url type in the URL your Armis platform URL – for example – acme.armis.com/api/v1 
 - Choose what type of Armis alerts XSOAR will fetch from the options provided 
 - Generate an API KEY via the Armis platform (please refer below for further help tip).
 - Trust any certificate
 - Fetch Alerts AQL – see below for further help tip. 

 

##Obtaining an API key from Armis: 

 - Log into Armis platform and browse to Settings by clicking on your account icon on the top right-hand side of the screen.
 - Choose Settings API Management.
 - Press the “Create” button and copy the generated key (please make sure not to share it nor leave a non-encrypted copy of it). 

 

##Fetch Alert using an AQL 

 - Armis uses AQL syntax to query its database when presenting to the user meaningful information.
 - As you navigate through the Armis GUI you will notice that at the top search bar an AQL string is created for each page displayed. By modifying the filters the AQL changes accordingly.
 - AQL syntax allows you to granularly choose sub types of Armis alerts to ingest.
 - If you have a desired fine-tuned alert you wish XSOAR to ingest through Fetch you can type here the AQL syntax

