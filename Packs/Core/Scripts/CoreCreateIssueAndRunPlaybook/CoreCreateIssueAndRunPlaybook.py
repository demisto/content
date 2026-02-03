import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from time import sleep

def main():
    try:
        args = demisto.args()
        create_issue_res = demisto.executeCommand("core-create-issue", args)
        if is_error(create_issue_res):
            return_error(f"Failed to create issue: {get_error(create_issue_res)}")
        
        if not create_issue_res or len(create_issue_res) < 1:
            return_error("Failed to create issue.")
            
        external_id = create_issue_res[0].get('Contents', {}).get('reply', {}).get('external_id')
        # 2. Get Issue ID using external_id
        sleep(4)
        get_issues_res = demisto.executeCommand("core-get-issues", {'external_id': external_id})
        if is_error(get_issues_res) or not get_issues_res or len(get_issues_res) < 1:
            return_error(f"Failed to get issue details: {get_error(get_issues_res)}")
            
        # Assuming the first issue is the correct one as external_id should be unique
        issues = get_issues_res[0].get('Contents', {}).get('alerts')
        if not issues:
             return_error(f"No issue found for external_id: {external_id}")
             
        # Handle if issues is a list or a single dict
        if isinstance(issues, list):
            issue_id = issues[0].get('alert_fields', {}).get('internal_id')
        else:
            issue_id = issues.get('alert_fields', {}).get('internal_id')
            
        if not issue_id:
            return_error(f"Could not find internal_id for issue with external_id: {external_id}")

        # 3. Run Playbook
        playbook_id = args.get('playbook_id')
        run_playbook_res = demisto.executeCommand("core-run-playbook", {'issue_ids': issue_id, 'playbook_id': playbook_id})
        if is_error(run_playbook_res):
            return_error(f"Failed to run playbook: {get_error(run_playbook_res)}")
            
        urls = demisto.demistoUrls()
        server_url = urls.get('server')
        issue_link = f"{server_url}/issue-view/{issue_id}"
        readable_output = f"### Issue Created and Playbook Run Successfully\nIssue Link: [{issue_link}]({issue_link})"
        return_results(CommandResults(
            outputs={"issue_link": issue_link},
            outputs_prefix="Core.CreatedIssueLink",
            readable_output=readable_output
        ))

    except Exception as e:
        return_error(f'Failed to execute CoreCreateIssueAndRunPlaybook. Error: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
