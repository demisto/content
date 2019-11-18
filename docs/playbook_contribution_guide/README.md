# Playbook Contribution Guide
## Introduction
This guide is intended to guide you through the process of contributing playbooks to our content, after they were created through the user interface. 

## Exporting playbooks
- Your playbooks contain playbook and task descriptions by now and they should be able to run smoothly.
- In order to contribute your newly created playbooks, they have to be exported via the "Export" button in playbook view mode:
![image](https://user-images.githubusercontent.com/43602124/69058801-07d5c180-0a1d-11ea-8bd0-9dfd874b51b5.png)
 - The playbook will be exported as a YML file. Run the script `update_playbook.py` against the YML file. The script is located in `content\Utils\update_playbook.py`. The script will modify some fields in the file to normalize it with the rest of the playbooks in our content, and will output a file with the prefix `playbook-` in the filename. That is the file you have to use from now on.
 - If your playbook has a test playbook, copy the name of the test playbook and declare it as the test playbook if your playbook, like so:
![image](https://user-images.githubusercontent.com/43602124/69059395-1cff2000-0a1e-11ea-8517-dca2046b9ec7.png)
 in this case there were 2 test playbooks, but there will usually be only one.
 - Add your test in the `conf.json` file, located in `content\Tests\conf.json`. You should add an entry that specifies the integrations needed for your test playbook, as well as specify a timeout in seconds if your test is taking a long time to complete and fails due to timeout (usually not needed). Also, specify the minimum version for your test here (fromversion: 5.0.0).
- For layouts, you will also need to create a changelog file:
![image](https://user-images.githubusercontent.com/43602124/69060394-f0e49e80-0a1f-11ea-8714-437420706633.png)
if a changelog file already exists, just add your release-notes to the "Unreleased" part of the file.

 ## Pull Request
-   Remember to include all files relevant to your use-case in the PR. That includes incident fields, layouts, incident types (if any were created and are used), integrations, playbooks and test playbooks.
- Your playbooks will only be reviewed after finalizing the code-review stage.
- We will review your playbooks and comment for any needed changes.
- After your playbooks have been reviewed, the last review stage will begin, which is the technical writer review.


Thank you for contributing to our content!