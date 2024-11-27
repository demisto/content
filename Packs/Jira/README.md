This pack enables you to manage issues in Jira and exchange information between Jira and Cortex XSOAR.

## What does this pack do?

This pack enables you to

- Create, edit, delete, and query Jira issues.
- Add information to Jira issues in the form of links, comments, and attachments.
- Get information concerning boards, and sprints.
- Create Cortex XSOAR incidents from Jira issues.
- Mirror information from Jira to Cortex XSOAR and vice versa.

The pack includes the **Atlassian Jira v2**, and **Atlassian Jira v3** integration, the **Jira Incident**, and **JiraV3 Incident** incident type, incident fields, incident layouts to display all of the Jira information, and 6 scripts:

- **JiraCreateIssue-example**: Simplifies the process of creating a new issue in Jira.
- **JIRAPrintIssue**: Prints a Jira issue in the War Room.
- **script-JiraChangeTransition**: Gets the new Jira status and updates the Cortex XSOAR incident status by applying a transition.
- **script-JiraListTransition**: Lists all possible transitions for a given issue.
- **script-JiraChangeStatus**: Gets the new Jira status and updates the Cortex XSOAR incident status by choosing a specific status.
- **script-JiraListStatus**: Lists all possible statuses for a given issue.

## How does this pack work?

Create an instance of the **Atlassian Jira v2**, or **Atlassian Jira v3** integration and start fetching and ingesting incidents.
