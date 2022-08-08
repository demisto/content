import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

no_entries_message = """<!DOCTYPE html>
<html>
<body>
<h3>This Incident does not contain any email threads yet.</h3>
</body>
</html>
"""


def fetch_email_threads(incident_id):
    """Fetch all Email Threads stored in the current incident context
    Args:
        incident_id (str): The incident ID
    Returns:
        list of dicts. List of email thread entries
    """
    # Get current email threads from context if any are present
    try:
        incident_context = demisto.executeCommand("getContext", {'id': incident_id})
        threads = dict_safe_get(incident_context[0], ['Contents', 'context', 'EmailThreads'])

        if not threads:
            return None

        # Return a list of dicts, even if there is only one thread entry and the context item is a list
        threads = [threads] if isinstance(threads, dict) else threads

        return threads

    except Exception as e:
        return_error(f'An exception occurred while fetching email threads: {e}')


def format_threads(email_threads):
    """Process list of email thread context entries and return a table in MD format
    Args:
        email_threads (list of dicts): List of email thread entry dictionaries
    Returns:
        md (str): Markdown formatted table
    """
    try:
        thread_summary_rows: Dict = {}
        for thread_entry in email_threads:
            # Loop through thread entries.
            # Trim off thread ID code for readability
            thread_number = int(thread_entry['EmailCommsThreadNumber'])
            email_original_subject = thread_entry['EmailSubject'].split('<')[-1].split('>')[1].strip()
            cc_addresses = thread_entry['EmailCC']
            bcc_addresses = thread_entry['EmailBCC']
            recipients = thread_entry['EmailTo']

            if thread_number in thread_summary_rows:
                # Table row already exists for this thread - just append recipients, if needed
                thread_recipients = thread_summary_rows[thread_number]['Recipients']
                thread_cc = thread_summary_rows[thread_number]['CC']
                thread_bcc = thread_summary_rows[thread_number]['BCC']

                for recipient in recipients.split(","):
                    if recipient not in thread_recipients:
                        thread_summary_rows[thread_number]['Recipients'] += f', {recipient}'

                if cc_addresses and len(cc_addresses) > 0:
                    for cc_address in cc_addresses.split(","):
                        if cc_address not in thread_cc and len(thread_cc) == 0:
                            thread_summary_rows[thread_number]['CC'] = cc_address
                        elif cc_address not in thread_cc:
                            thread_summary_rows[thread_number]['CC'] += f', {cc_address}'

                if bcc_addresses and len(bcc_addresses) > 0:
                    for bcc_address in bcc_addresses.split(","):
                        if bcc_address not in thread_bcc and len(thread_bcc) == 0:
                            thread_summary_rows[thread_number]['BCC'] = bcc_address
                        elif bcc_address not in thread_bcc:
                            thread_summary_rows[thread_number]['BCC'] += f', {bcc_address}'
            else:
                table_row = {
                    'Thread Number': thread_number,
                    'Subject': email_original_subject,
                    'Recipients': recipients,
                    'CC': cc_addresses,
                    'BCC': bcc_addresses
                }
                thread_summary_rows[thread_number] = table_row

        # Convert dict of dict into list of dicts for MD formatting
        thread_summary_table = [entry for entry in thread_summary_rows.values()]

        table_name = 'Email Thread List'
        table_headers = ['Thread Number', 'Subject', 'Recipients', 'CC', 'BCC']
        md = tableToMarkdown(name=table_name, t=thread_summary_table, headers=table_headers)
        return md

    except Exception as e:
        return_error(f'An exception occurred while generating the thread summary table: {e}')


def main():
    incident = demisto.incident()
    incident_id = incident.get('id')

    email_threads = fetch_email_threads(incident_id)
    if email_threads:
        thread_summary_rows = format_threads(email_threads)
    else:
        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': no_entries_message
        })
        return None

    demisto.results({
        'ContentsFormat': EntryFormat.TABLE,
        'Type': EntryType.NOTE,
        'Contents': thread_summary_rows,
        'HumanReadable': thread_summary_rows
    })


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
