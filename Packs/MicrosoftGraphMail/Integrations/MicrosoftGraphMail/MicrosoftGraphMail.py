import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

import urllib3
from MicrosoftGraphMailApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()


class MsGraphMailClient(MsGraphMailBaseClient):
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
        if "time" not in last_run and (last_run_time := last_run.get("LAST_RUN_TIME")):
            last_run["time"] = last_run_time.replace("Z", "")

        if "time" in last_run:
            last_run["time"] = last_run["time"].replace("Z", "")
        demisto.debug("MicrosoftGraphMail - Start fetching")
        demisto.debug(f"MicrosoftGraphMail - Last run: {json.dumps(last_run)}")

        start_fetch_time, end_fetch_time = get_fetch_run_time_range(
            last_run=last_run, first_fetch=self._first_fetch_interval, look_back=self._look_back, date_format=API_DATE_FORMAT
        )

        demisto.debug(f"{start_fetch_time=}, {end_fetch_time=}")

        exclude_ids = list(set(last_run.get("LAST_RUN_IDS", [])))  # remove any possible duplicates

        last_run_folder_path = last_run.get("LAST_RUN_FOLDER_PATH")
        folder_path_changed = last_run_folder_path != self._folder_to_fetch

        last_run_account = last_run.get("LAST_RUN_ACCOUNT")
        mailbox_to_fetch_changed = last_run_account != self._mailbox_to_fetch

        if folder_path_changed or mailbox_to_fetch_changed:
            # detected folder path change, get new folder id
            folder_id = self._get_folder_by_path(
                self._mailbox_to_fetch, self._folder_to_fetch, overwrite_rate_limit_retry=True
            ).get("id")
            demisto.info("detected file path change, ignored LAST_RUN_FOLDER_ID from last run.")
        else:
            # LAST_RUN_FOLDER_ID is stored in order to avoid calling _get_folder_by_path method in each fetch
            folder_id = last_run.get("LAST_RUN_FOLDER_ID")

        fetched_emails, exclude_ids = self._fetch_last_emails(
            folder_id=folder_id, last_fetch=start_fetch_time, exclude_ids=exclude_ids
        )

        demisto.debug(f'fetched email IDs before removing duplications - {[email.get("id") for email in fetched_emails]}')

        # remove duplicate incidents which were already fetched
        incidents = filter_incidents_by_duplicates_and_limit(
            incidents_res=[self._parse_email_as_incident(email, True) for email in fetched_emails],
            last_run=last_run,
            fetch_limit=self._emails_fetch_limit,
            id_field="ID",
        )

        demisto.debug(f'fetched email IDs after removing duplications - {[email.get("ID") for email in incidents]}')

        next_run = update_last_run_object(
            last_run=last_run,
            incidents=incidents,
            fetch_limit=self._emails_fetch_limit,
            start_fetch_time=start_fetch_time,
            end_fetch_time=end_fetch_time,
            look_back=self._look_back,
            created_time_field="occurred",
            id_field="ID",
            date_format=API_DATE_FORMAT,
            increase_last_run_time=True,
        )

        next_run.update(
            {
                "LAST_RUN_IDS": exclude_ids,
                "LAST_RUN_FOLDER_ID": folder_id,
                "LAST_RUN_FOLDER_PATH": self._folder_to_fetch,
                "LAST_RUN_ACCOUNT": self._mailbox_to_fetch,
            }
        )
        demisto.debug(f"MicrosoftGraphMail - Next run after incidents fetching: {json.dumps(last_run)}")

        demisto.debug(f"MicrosoftGraphMail - Number of incidents before filtering: {len(fetched_emails)}")
        demisto.debug(f"MicrosoftGraphMail - Number of incidents after filtering: {len(incidents)}")
        demisto.debug(f"MicrosoftGraphMail - Number of incidents skipped: {len(fetched_emails)-len(incidents)}")
        for incident in incidents:  # remove the ID from the incidents, they are used only for look-back.
            incident.pop("ID", None)

        demisto.info(f"fetched {len(incidents)} incidents")
        demisto.debug(f"{next_run=}")

        return next_run, incidents


def main():  # pragma: no cover
    try:
        """ COMMANDS MANAGER / SWITCH PANEL """
        args: dict = demisto.args()
        params: dict = demisto.params()
        # There're several options for tenant_id & auth_and_token_url due to the recent credentials set supoort enhancment.
        tenant_id: str = (
            params.get("creds_tenant_id", {}).get("password", "") or params.get("_tenant_id", "") or params.get("tenant_id", "")
        )
        auth_and_token_url: str = (
            params.get("creds_auth_id", {}).get("password", "") or params.get("_auth_id", "") or params.get("auth_id", "")
        )
        enc_key: str = (params.get("credentials") or {}).get("password", "") or params.get("enc_key", "")
        server = params.get("url", "")
        base_url: str = urljoin(server, "/v1.0")
        endpoint = GRAPH_BASE_ENDPOINTS.get(server, "com")
        app_name: str = "ms-graph-mail"
        ok_codes: tuple = (200, 201, 202, 204)
        use_ssl: bool = not argToBoolean(params.get("insecure", False))
        proxy: bool = params.get("proxy", False)
        certificate_thumbprint: str = params.get("creds_certificate", {}).get("identifier", "") or params.get(
            "certificate_thumbprint", ""
        )
        private_key: str = replace_spaces_in_credential(params.get("creds_certificate", {}).get("password", "")) or params.get(
            "private_key", ""
        )
        managed_identities_client_id: str | None = get_azure_managed_identities_client_id(params)
        self_deployed: bool = params.get("self_deployed", False) or managed_identities_client_id is not None

        if not managed_identities_client_id:
            if not self_deployed and not enc_key:
                raise DemistoException(
                    "Key must be provided. For further information see "
                    "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
                )
            elif not enc_key and not (certificate_thumbprint and private_key):
                raise DemistoException("Key or Certificate Thumbprint and Private Key must be provided.")
            if not auth_and_token_url:
                raise Exception("ID must be provided.")
            if not tenant_id:
                raise Exception("Token must be provided.")

        # params related to mailbox to fetch incidents
        mailbox_to_fetch = params.get("mailbox_to_fetch", "")
        folder_to_fetch = params.get("folder_to_fetch", "Inbox")
        first_fetch_interval = params.get("first_fetch", "15 minutes")
        emails_fetch_limit = int(params.get("fetch_limit", "50"))
        timeout = arg_to_number(params.get("timeout", "10") or "10")
        display_full_email_body = argToBoolean(params.get("display_full_email_body", False))
        mark_fetched_read = argToBoolean(params.get("mark_fetched_read", "false"))
        look_back = arg_to_number(params.get("look_back", 0))
        legacy_name = argToBoolean(params.get("legacy_name", False))

        client: MsGraphMailClient = MsGraphMailClient(
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
            legacy_name=legacy_name,
            timeout=timeout,
            endpoint=endpoint,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            display_full_email_body=display_full_email_body,
            mark_fetched_read=mark_fetched_read,
            look_back=look_back,
            managed_identities_client_id=managed_identities_client_id,
        )

        command = demisto.command()
        LOG(f"Command being called is {command}")

        if command == "test-module":
            client.test_connection()
            return_results("ok")
        if command == "fetch-incidents":
            next_run, incidents = client.fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in ("msgraph-mail-list-emails", "msgraph-mail-search-email"):
            return_results(list_mails_command(client, args))
        elif command == "msgraph-mail-create-draft":
            return_results(create_draft_command(client, args))
        elif command == "msgraph-mail-reply-to":
            return_results(reply_to_command(client, args))  # pylint: disable=E1123
        elif command == "msgraph-mail-get-email":
            return_results(get_message_command(client, args))
        elif command == "msgraph-mail-delete-email":
            return_results(delete_mail_command(client, args))
        elif command == "msgraph-mail-list-attachments":
            return_results(list_attachments_command(client, args))
        elif command == "msgraph-mail-get-attachment":
            return_results(get_attachment_command(client, args))
        elif command == "msgraph-mail-create-folder":
            return_results(create_folder_command(client, args))
        elif command == "msgraph-mail-list-folders":
            return_results(list_folders_command(client, args))
        elif command == "msgraph-mail-update-folder":
            return_results(update_folder_command(client, args))
        elif command == "msgraph-mail-list-child-folders":
            return_results(list_child_folders_command(client, args))
        elif command == "msgraph-mail-delete-folder":
            return_results(delete_folder_command(client, args))
        elif command == "msgraph-mail-move-email":
            return_results(move_email_command(client, args))
        elif command == "msgraph-mail-get-email-as-eml":
            return_results(get_email_as_eml_command(client, args))
        elif command == "msgraph-mail-send-draft":
            return_results(send_draft_command(client, args))  # pylint: disable=E1123
        elif command == "msgraph-mail-update-email-status":
            return_results(update_email_status_command(client, args))
        elif command == "reply-mail":
            return_results(reply_email_command(client, args))
        elif command == "send-mail":
            return_results(send_email_command(client, args))
        elif command == "msgraph-mail-auth-reset":
            return_results(reset_auth())
        elif command in ["msgraph-mail-get-rule", "msgraph-mail-list-rules"]:
            return_results(list_rule_action_command(client, args))
        elif command == "msgraph-mail-delete-rule":
            return_results(delete_rule_command(client, args))

    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
