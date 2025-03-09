import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
from MicrosoftGraphMailApiModule import *  # noqa: E402


# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class MsGraphListenerClient(MsGraphMailBaseClient):
    """
    MsGraphListenerClient enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, **kwargs):
        super().__init__(grant_type=AUTHORIZATION_CODE, **kwargs)

    @staticmethod
    def _get_next_run_time(fetched_emails, start_time):
        """
        Returns received time of last email if exist, else utc time that was passed as start_time.

        The elements in fetched emails are ordered by modified time in ascending order,
        meaning the last element has the latest received time.

        :type fetched_emails: ``list``
        :param fetched_emails: List of fetched emails

        :type start_time: ``str``
        :param start_time: utc string of format Y-m-dTH:M:SZ

        :return: Returns str date of format Y-m-dTH:M:SZ
        :rtype: `str`
        """
        return fetched_emails[-1].get("receivedDateTime") if fetched_emails else start_time

    @logger
    def fetch_incidents(self, last_run):
        """
        Fetches emails from office 365 mailbox and creates incidents of parsed emails.

        :type last_run: ``dict``
        :param last_run:
            Previous fetch run data that holds the fetch time in utc Y-m-dTH:M:SZ format,
            ids of fetched emails, id and path of folder to fetch incidents from

        :return: Next run data and parsed fetched incidents
        :rtype: ``dict`` and ``list``
        """
        last_fetch = last_run.get("LAST_RUN_TIME")
        exclude_ids = last_run.get("LAST_RUN_IDS", [])
        last_run_folder_path = last_run.get("LAST_RUN_FOLDER_PATH")
        folder_path_changed = last_run_folder_path != self._folder_to_fetch
        demisto.debug("MicrosoftGraphMail - Start fetching")
        demisto.debug(f"MicrosoftGraphMail - Last run: {json.dumps(last_run)}")

        if folder_path_changed:
            # detected folder path change, get new folder id
            folder_id = self._get_folder_by_path(
                self._mailbox_to_fetch, self._folder_to_fetch, overwrite_rate_limit_retry=True
            ).get("id")
            demisto.info("detected file path change, ignored last run.")
        else:
            # LAST_RUN_FOLDER_ID is stored in order to avoid calling _get_folder_by_path method in each fetch
            folder_id = last_run.get("LAST_RUN_FOLDER_ID")

        if not last_fetch or folder_path_changed:  # initialized fetch
            last_fetch, _ = parse_date_range(self._first_fetch_interval, date_format=DATE_FORMAT, utc=True)
            demisto.info(f"initialize fetch and pull emails from date :{last_fetch}")

        fetched_emails, exclude_ids = self._fetch_last_emails(folder_id=folder_id, last_fetch=last_fetch, exclude_ids=exclude_ids)

        incidents = [self._parse_email_as_incident(email, True) for email in fetched_emails]

        next_run_time = self._get_next_run_time(fetched_emails, last_fetch)

        next_run = {
            "LAST_RUN_TIME": next_run_time,
            "LAST_RUN_IDS": exclude_ids,
            "LAST_RUN_FOLDER_ID": folder_id,
            "LAST_RUN_FOLDER_PATH": self._folder_to_fetch,
        }

        demisto.debug(f"MicrosoftGraphMail - Next run after incidents fetching: {json.dumps(next_run)}")
        demisto.debug(f"MicrosoftGraphMail - Number of incidents before filtering: {len(fetched_emails)}")
        demisto.debug(f"MicrosoftGraphMail - Number of incidents after filtering: {len(incidents)}")
        demisto.debug(f"MicrosoftGraphMail - Number of incidents skipped: {len(fetched_emails)-len(incidents)}")

        """
        The below pop is here to maintain parity between this (single-user) version of
        the graph mail integration and the application-permission version. It is output
        by the ApiModule but does not provide any functionaltiy and consideration should be given
        in the future to either removing it's
        addition in the Api module.
        """
        for incident in incidents:  # remove the ID from the incidents, they are used only for look-back.
            incident.pop("ID", None)

        demisto.info(f"fetched {len(incidents)} incidents")
        demisto.debug(f"{next_run=}")

        return next_run, incidents


def main():  # pragma: no cover
    """COMMANDS MANAGER / SWITCH PANEL"""
    params = demisto.params()
    # params related to common instance configuration
    base_url = "https://graph.microsoft.com/v1.0/"
    use_ssl = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    ok_codes = (200, 201, 202)
    refresh_token = params.get("creds_refresh_token", {}).get("password") or params.get("refresh_token", "")
    auth_and_token_url = params.get("creds_auth_id", {}).get("password") or params.get("auth_id", "")
    enc_key = params.get("creds_enc_key", {}).get("password") or params.get("enc_key", "")
    certificate_thumbprint = params.get("creds_certificate", {}).get("identifier") or params.get("certificate_thumbprint")
    private_key = replace_spaces_in_credential(params.get("creds_certificate", {}).get("password")) or params.get("private_key")
    auth_code = params.get("creds_auth_code", {}).get("password") or params.get("auth_code", "")
    app_name = "ms-graph-mail-listener"
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed = params.get("self_deployed", False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException(
                "Key must be provided. For further information see "
                "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
            )
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException("Key or Certificate Thumbprint and Private Key must be provided.")

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get("mailbox_to_fetch", "")
    folder_to_fetch = params.get("folder_to_fetch", "Inbox")
    first_fetch_interval = params.get("first_fetch", "15 minutes")
    emails_fetch_limit = int(params.get("fetch_limit", "50"))
    display_full_email_body = argToBoolean(params.get("display_full_email_body", "false"))
    mark_fetched_read = argToBoolean(params.get("mark_fetched_read", "false"))
    fetch_html_formatting = argToBoolean(params.get("fetch_html_formatting", "false"))
    legacy_name = argToBoolean(params.get("legacy_name", False))

    # params related to self deployed
    tenant_id = refresh_token if self_deployed else ""

    # params related to oproxy
    # In case the script is running for the first time, refresh token is retrieved from integration parameters,
    # in other case it's retrieved from integration context.
    refresh_token = get_integration_context().get("current_refresh_token") or refresh_token

    client = MsGraphListenerClient(
        self_deployed=self_deployed,
        tenant_id=tenant_id,
        auth_id=auth_and_token_url,
        enc_key=enc_key,
        app_name=app_name,
        base_url=base_url,
        verify=use_ssl,
        proxy=proxy,
        ok_codes=ok_codes,
        mailbox_to_fetch=mailbox_to_fetch,
        folder_to_fetch=folder_to_fetch,
        first_fetch_interval=first_fetch_interval,
        emails_fetch_limit=emails_fetch_limit,
        fetch_html_formatting=fetch_html_formatting,
        legacy_name=legacy_name,
        refresh_token=refresh_token,
        auth_code=auth_code,
        private_key=private_key,
        display_full_email_body=display_full_email_body,
        mark_fetched_read=mark_fetched_read,
        redirect_uri=params.get("redirect_uri", ""),
        certificate_thumbprint=certificate_thumbprint,
        managed_identities_client_id=managed_identities_client_id,
    )
    try:
        args = demisto.args()
        command = demisto.command()
        LOG(f"Command being called is {command}")

        if command == "test-module":
            if managed_identities_client_id:
                return_results(client.test_connection())
            else:
                # cannot use test module due to the lack of ability to set refresh token to integration context
                raise Exception("Please use !msgraph-mail-test instead")
        if command == "msgraph-mail-test":
            client.test_connection()
            return_results(CommandResults(readable_output="```✅ Success!```"))
        if command == "msgraph-mail-auth-reset":
            return_results(reset_auth())
        if command == "fetch-incidents":
            next_run, incidents = client.fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "msgraph-mail-list-emails":
            return_results(list_mails_command(client, args))
        elif command == "msgraph-mail-create-draft":
            return_results(create_draft_command(client, args))
        elif command == "msgraph-mail-reply-to":
            return_results(reply_to_command(client, args))
        elif command == "msgraph-mail-list-attachments":
            return_results(list_attachments_command(client, args))
        elif command == "msgraph-mail-get-attachment":
            return_results(get_attachment_command(client, args))
        elif command == "msgraph-mail-create-folder":
            return_results(create_folder_command(client, args))
        elif command == "msgraph-mail-get-email-as-eml":
            return_results(get_email_as_eml_command(client, args))
        elif command == "msgraph-mail-move-email":
            return_results(move_email_command(client, args))
        elif command == "msgraph-mail-list-folders":
            return_results(list_folders_command(client, args))
        elif command == "msgraph-mail-list-child-folders":
            return_results(list_child_folders_command(client, args))
        elif command == "msgraph-mail-send-draft":
            return_results(send_draft_command(client, args))  # pylint: disable=E1123
        elif command == "msgraph-update-email-status":
            return_results(update_email_status_command(client, args))
        elif command == "reply-mail":
            return_results(reply_email_command(client, args))
        elif command == "send-mail":
            return_results(send_email_command(client, args))
        elif command == "msgraph-mail-generate-login-url":
            return_results(generate_login_url(client))
        elif command in ["msgraph-mail-get-rule", "msgraph-mail-list-rules"]:
            return_results(list_rule_action_command(client, args))
        elif command == "msgraph-mail-delete-rule":
            return_results(delete_rule_command(client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
