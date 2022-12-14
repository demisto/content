This content pack contains a long running integration that runs a simple configurable webserver that can generate predictable URLs to share with users. The URL clicks are captured and responses are stored to the integration context. The commands take as input HTML templates(with place holders) and inserts the URLs. The final html can be emailed to the users or in the case of an form submission, the link can be copied from the context data and can be used as a tradional data collection task. The advantage is that, you can build any template you want.

 As of now, the integration can be used for 2 types of links. 
 1. Simple URLs that can be clicked to register a response (or approve a certain task)
 2. A URL that accepts an HTTP POST to accept a form. 
   
    
The pack also contains an automation that can be used to poll the user's response and two playbooks corresponding to the options above. 

Limitations
Form submissions cannot accept a file upload as of now. To be implemented later
It is not possible to setup multiple data collection jobs simultaneously within the same playbook,  if you want to resend the email to the recipients.