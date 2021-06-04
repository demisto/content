In order to create the API Key go to:

  Settings -> API Key -> Add api key
  
  Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
  
- The ***proofpoint-tr-ingest-alert*** command requires some JSON format arguments. Please make sure the inputed JSONs have uniqe characters (such as `"`) escaped before entering them (e.g. `\"`).
- For more information regarding the JSON objects, please see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
- If the **fetch-incidents** result in timeout, please consider changing **fetch-delta** and **fetch-limit** parameters 
which will limit the api calls and the result.