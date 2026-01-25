import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

import requests  # noqa: E402
import time  # noqa: E402


def get_graph_token(tenant_id, client_id, client_secret):
    """קבלת Access Token ל-Graph API עם לוגים"""
    print(f"Attempting to get Graph API token for Tenant: {tenant_id}")
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        'client_id': client_id,
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': client_secret,
        'grant_type': 'client_credentials',
    }

    try:
        res = requests.post(auth_url, data=payload)
        res.raise_for_status()
        print("Graph API token obtained successfully.")
        return res.json().get('access_token')
    except Exception as e:
        print(f"Failed to obtain token. Error: {str(e)}")
        raise

def get_internal_catalog_id(token, external_id):
    """מתרגם Client ID ל-Teams Catalog ID (מונע שגיאת NotFound)"""
    print(f"Step 3: Searching Catalog ID for External ID: {external_id}")
    headers = {'Authorization': f'Bearer {token}'}
    # סינון הקטלוג לפי ה-Client ID מ-Azure
    catalog_url = f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps?$filter=externalId eq '{external_id}'"
    
    res = requests.get(catalog_url, headers=headers)
    res.raise_for_status()
    apps = res.json().get('value', [])
    
    if not apps:
        raise Exception(f"App with Client ID {external_id} not found in Teams Catalog. Verify it's published in Teams Admin Center.")
    
    internal_id = apps[0]['id']
    print(f"Mapping successful: External {external_id} -> Internal {internal_id}")
    return internal_id

def refresh_bot_installation(token, team_id, external_id):
    """מנהל את מחזור החיים של הבוט בתוך הצוות"""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # 1. חיפוש התקנה קיימת
    print(f"Step 2: Checking if bot is already installed in team: {team_id}")
    list_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps?$expand=teamsApp"
    res = requests.get(list_url, headers=headers)
    res.raise_for_status()
    
    installation_id = None
    for app in res.json().get('value', []):
        if app.get('teamsApp', {}).get('externalId') == external_id:
            installation_id = app.get('id')
            break

    # 2. הסרה אם קיים
    if installation_id:
        print(f"Found existing installation (ID: {installation_id}). Removing it...")
        delete_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps/{installation_id}"
        requests.delete(delete_url, headers=headers)
        print("Bot removed. Waiting 5 seconds for sync...")
        time.sleep(5)
    else:
        print("Bot not found in team. Proceeding to fresh installation.")

    # 3. מציאת ה-ID הקטלוגי
    catalog_id = get_internal_catalog_id(token, external_id)

    # 4. התקנה מחדש
    print(f"Step 4: Installing bot in team using Catalog ID: {catalog_id}")
    add_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps"
    #upgrade_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps/{installation_id}/upgrade"
    payload = {
    "teamsApp@odata.bind": f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{catalog_id}",
    "consentedPermissionSet": {
        "resourceSpecificPermissions": [
            {
                "permissionValue": "ChannelMessage.Read.Group",
                "permissionType": "application"
            }
        ]
    }
}

    add_res = requests.post(add_url, headers=headers, json=payload)
    if add_res.status_code == 201:
        print("Bot installed successfully via Graph API.")
    else:
        print(f"Installation failed. Response: {add_res.text}")
        add_res.raise_for_status()


def main():
    args = demisto.args()
    tenant_id = args.get('tenant_id')
    client_id = args.get('client_id')
    client_secret = args.get('client_secret')
    team_id = args.get('team_id')
    bot_app_id = args.get('bot_app_id')
    instance_name = args.get('instance_name', 'MS_Teams_Instance')


    print("Starting configuration script...")

    try:
        # שלב 1: רענון הבוט ב-Teams
        token = get_graph_token(tenant_id, client_id, client_secret)
        refresh_bot_installation(token, team_id, bot_app_id)

        # שלב 2: הגדרת האינטגרציה בתוך XSOAR
        print(f"Preparing to execute setIntegration for: {instance_name}")
        integration_params = {
            "tenant_id": tenant_id,
            "auth_id": client_id,
            "enc_key": client_secret,
            "is_all_redirect_url": True,
            "confirm_auth": True
        }

        # הרצת הפקודה הפנימית
        res = demisto.executeCommand("setIntegration", {
            "name": "ms-teams",
            "instance_name": instance_name,
            "configuration": integration_params,
            "enabled": "true"
        })

        if is_error(res):
            error_msg = get_error(res)
            print(f"setIntegration failed: {error_msg}")
            return_error(f"Error setting integration: {error_msg}")

        print("setIntegration executed successfully.")
        return_results(f"Successfully refreshed Bot in team {team_id} and configured instance {instance_name}")

    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return_error(f"Failed to complete configuration: {str(e)}")


if __name__ == "builtins":
    main()
