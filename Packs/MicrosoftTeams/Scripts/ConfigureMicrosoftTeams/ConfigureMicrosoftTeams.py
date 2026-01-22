import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

import requests  # noqa: E402
import time  # noqa: E402


def get_graph_token(tenant_id, client_id, client_secret):
    """קבלת Access Token ל-Graph API עם לוגים"""
    demisto.debug(f"Attempting to get Graph API token for Tenant: {tenant_id}")
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        'client_id': client_id,
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': client_secret,
        'grant_type': 'client_credentials'
    }

    try:
        res = requests.post(auth_url, data=payload)
        res.raise_for_status()
        demisto.debug("Graph API token obtained successfully.")
        return res.json().get('access_token')
    except Exception as e:
        demisto.debug(f"Failed to obtain token. Error: {str(e)}")
        raise


def refresh_bot_installation(token, team_id, bot_app_id):
    """ניהול הבוט: חיפוש, הסרה והתקנה מחדש"""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # 1. חיפוש האפליקציה
    demisto.debug(f"Searching for bot {bot_app_id} in team {team_id}...")
    list_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps?$expand=teamsApp"

    res = requests.get(list_url, headers=headers)
    res.raise_for_status()
    installed_apps = res.json()

    installation_id = None
    for app in installed_apps.get('value', []):
        if app.get('teamsApp', {}).get('id') == bot_app_id:
            installation_id = app.get('id')
            break

    # 2. הסרה אם נמצאה התקנה קודמת
    if installation_id:
        demisto.debug(f"Found existing installation (ID: {installation_id}). Removing it...")
        delete_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps/{installation_id}"
        requests.delete(delete_url, headers=headers)

        demisto.debug("Waiting 5 seconds for Microsoft synchronization...")
        time.sleep(5)
    else:
        demisto.debug("Bot was not found in the team. Proceeding to fresh installation.")

    # 3. הוספה מחדש
    demisto.debug(f"Installing bot {bot_app_id} to team {team_id}...")
    add_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/installedApps"
    payload = {
        "teamsApp@odata.bind": f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{bot_app_id}"
    }
    add_res = requests.post(add_url, headers=headers, json=payload)

    if add_res.status_code == 201:
        demisto.debug("Bot installed successfully via Graph API.")
    else:
        demisto.debug(f"Installation response: {add_res.text}")
        add_res.raise_for_status()


def main():
    args = demisto.args()
    tenant_id = args.get('tenant_id')
    client_id = args.get('client_id')
    client_secret = args.get('client_secret')
    team_id = args.get('team_id')
    bot_app_id = args.get('bot_app_id')
    instance_name = args.get('instance_name', 'MS_Teams_Instance')

    demisto.debug("Starting configuration script...")

    try:
        # שלב 1: רענון הבוט ב-Teams
        token = get_graph_token(tenant_id, client_id, client_secret)
        refresh_bot_installation(token, team_id, bot_app_id)

        # שלב 2: הגדרת האינטגרציה בתוך XSOAR
        demisto.debug(f"Preparing to execute setIntegration for: {instance_name}")
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
            demisto.debug(f"setIntegration failed: {error_msg}")
            return_error(f"Error setting integration: {error_msg}")

        demisto.debug("setIntegration executed successfully.")
        return_results(f"Successfully refreshed Bot in team {team_id} and configured instance {instance_name}")

    except Exception as e:
        demisto.debug(f"Exception occurred: {str(e)}")
        return_error(f"Failed to complete configuration: {str(e)}")


if __name__ == "builtins":
    main()
