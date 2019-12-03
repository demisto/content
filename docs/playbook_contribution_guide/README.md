
# Playbook Contribution Guide  
## Introduction  
This guide is intended to guide you through the process of contributing playbooks to our content, after they were created through the user interface.   
  
## Guidelines
* For general guidelines on **how to create playbooks**, visit our [Creating Playbooks](https://github.com/demisto/content/tree/master/docs/creating_playbooks) article.
* Playbooks can be be divided into 2 categories depending on their usage. Technically, they are the same, but usage-wise, there are some differences. "Parent" playbooks are playbooks that run as the main playbook of an incident. The other type is "sub-playbooks", which are just playbooks that are being called by another playbook. 
Examples of parent playbooks can be `Phishing Investigation - Generic v2`, or `Endpoint Malware Investigation - Generic` because an incident starts with them. 
Examples of sub-playbooks are `IP Enrichment - Generic v2` or `Retrieve File From Endpoint - Generic`, because they are steps we take as part of the bigger investigation.
What one needs to consider is that since sub-playbooks are used as part of a bigger investigation, **they should have inputs and outputs.** Make sure that data you want to get from a sub-playbook, is defined in the outputs of it, so it can be used outside of that playbook. Since sub-playbooks are building blocks that will preferably be usable in other playbooks and use-cases, you should define **generic inputs** for them as explained in our [context standards](https://github.com/demisto/content/tree/master/docs/context_standards) article.
* Test playbooks can be used for testing integration commands individually (checking that they work and return the right inputs/outputs), but in the sense of playbooks - test playbooks should test a **certain scenario** of the investigation. For example, the test of `Phishing Investigation - Generic v2` creates an incident and attaches and email, and then makes sure that the URL contained in the email was found malicious (as it should be).

## Exporting playbooks  
- Your playbooks contain playbook and task descriptions by now and they should be able to run smoothly.  
- In order to contribute your newly created playbooks, they have to be exported via the "Export" button in playbook view mode:  
![image](https://user-images.githubusercontent.com/43602124/69058801-07d5c180-0a1d-11ea-8bd0-9dfd874b51b5.png)  
 - The playbook will be exported as a YML file. Run the script `update_playbook.py` against the YML file. The script is located in `content\Utils\update_playbook.py`. The script will modify some fields in the file to normalize it with the rest of the playbooks in our content, and will output a file with the prefix `playbook-` in the filename. That is the file you have to use from now on.  
 - If your playbook has a test playbook, copy the name of the test playbook and declare it as the test playbook of your playbook, like so:  
![image](https://user-images.githubusercontent.com/43602124/70059047-b61a6300-15e8-11ea-93a7-448f463c6613.png)

 - Add your test in the `conf.json` file, located in `content\Tests\conf.json`. You should add an entry that specifies the integrations needed for your test playbook, as well as specify a timeout in seconds if your test is taking a long time to complete and fails due to timeout (usually not needed). Also, specify the minimum version for your test here (fromversion: 5.0.0).  
- For layouts, you will also need to create a changelog file:  
![image](https://user-images.githubusercontent.com/43602124/69060394-f0e49e80-0a1f-11ea-8714-437420706633.png)  
if a changelog file already exists, just add your release-notes to the "Unreleased" part of the file.  
  

 ## Pull Request  
- Remember to include all files relevant to your use-case in the PR. That includes scripts, incident fields, layouts, incident types (if any were created and are used), integrations, playbooks and test playbooks.  
- Your playbooks will only be reviewed after finalizing the code-review stage.  
- We will review your playbooks and comment for any needed changes.  
  
  
We value your time and willingness to contribute. Thank you for contributing to our content!