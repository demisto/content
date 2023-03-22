import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Dict
from datetime import datetime
import requests
import smtplib
import zipfile
import tempfile
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from requests.exceptions import ConnectTimeout


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')

''' HELPER FUNCTIONS '''


def sendemail(reason, create_ts, email, email_server, email_user, email_pwd, txtfile=None):

    if txtfile != None:
        zf = tempfile.TemporaryFile(prefix='EDL monitor results', suffix='.zip')
        zip = zipfile.ZipFile(zf, 'a')
        zip.write(txtfile)
        zip.close()
        zf.seek(0)

        # Create the message
        themsg = MIMEMultipart()
        if reason == "test":
            themsg['Subject'] = f'Test success, EDL contents at {create_ts}! Instance- {instance_name}'
        else:
            themsg['Subject'] = 'EDL monitor and Checker results for %s' % instance_name
        themsg['To'] = email
        sender = "noreply@demisto.com"
        themsg['From'] = sender
        themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
        msg = MIMEBase('application', 'zip')
        msg.set_payload(zf.read())
        encoders.encode_base64(msg)
        msg.add_header('Content-Disposition', 'attachment',
                       filename="EDL monitor Results" + '.zip')
        themsg.attach(msg)
    else:
        # An availability email only

        # Email current EDL to user
        sender = "noreply@demisto.com"
        receivers = [email]
        demisto.debug(f'EDL monitor availability email send to - ' + email)

        # Create the message
        themsg = MIMEMultipart()
        themsg['Subject'] = f'EDL down at {create_ts}! Instance- {instance_name}'
        themsg['To'] = email
        sender = "noreply@demisto.com"
        themsg['From'] = sender
        set_integration_context(None)

        #part1 = MIMEText(text, 'plain')

        # themsg = f"""Subject: EDLmonitor content for {EDL}
        # EDL contents as of {pull_time}:
        # {linebreak.join(results)}
        # """
    themsg = themsg.as_string()
    try:
        # Enable additional smtplib logs
        #smtplib.SMTP.debuglevel = 1
        SERVER = smtplib.SMTP(email_server, 587)
        SERVER.ehlo()  # type: ignore
        # if TLS is True or TLS == 'STARTTLS' or str(TLS).lower() == 'true':
        SERVER.starttls()  # type: ignore
        if email_user != "":
            demisto.debug('EDL monitor Email AUTHING')
            # demisto.debug(f'EDL monitor Email - ' + email_user + " " + email_pwd)  ## CAREFUL with this line for debugging only!!!!
            SERVER.login(email_user, email_pwd)

        SERVER.sendmail(sender, email, themsg)
        # SERVER.sendmail(FROM, to + cc + bcc, str_msg)  # type: ignore[union-attr]
        SERVER.quit()
        demisto.debug('EDL monitor Successfully sent email')
    except Exception as err:
        raise ValueError("Failed to send email: " + str(err))


''' COMMAND FUNCTIONS '''


def test_module(EDL, edl_user, edl_pwd, verify_certificate, pull_time, email, email_server, email_user, email_pwd, timeout) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the EDL is accessible and if email credentials are valid and email can be sent with EDL current contents
    """
    try:
        if edl_pwd is None:
            try:
                response = requests.get(EDL, verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                raise ValueError(f"EDL timeout after {timeout} seconds")
        else:
            # Auth on EDL
            demisto.debug('EDL monitor auth to EDL')
            try:
                response = requests.get(EDL, auth=HTTPBasicAuth(edl_user, edl_pwd),
                                        headers=headers, verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                raise ValueError(f"EDL timeout after {timeout} seconds")
        # return f"Successfully connected to EDL at- {EDL}"
        if response.status_code != 200:
            raise ValueError("Non-200 response for EDL, check that EDL URL is correct.   MSG=" + response.text)
        results = sorted(response.text.split('\n'))
        # Open file to write for attachment
        filename = "EDL-" + instance_name + " as of " + pull_time + ".txt"
        res_file = open(filename, "w")
        # Write to file
        res_file.write('\n'.join(results))
        res_file.close()
        sendemail("test", pull_time, email, email_server, email_user, email_pwd, filename)
    except DemistoException as e:
        raise e

    return 'ok'


def fetch_incidents(start_time, EDL, edl_user, edl_pwd, verify_certificate, email, email_server, email_user, email_pwd, timeout, mon_contents):
    try:
        results = {}
        cur_time = ""

        demisto.debug(f'Start time {start_time}')
        demisto.debug(f'Cur time {datetime.now()}')

        if edl_pwd is None:
            # No auth on EDL
            demisto.debug('EDL monitor no auth to EDL')
            #response = requests.post(EDL, headers=headers)
            try:
                response = requests.get(EDL, verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
                sendemail("regular", pull_time, email, email_server, email_user, email_pwd)
        else:
            # Auth on EDL
            demisto.debug('EDL monitor auth to EDL')
            try:
                response = requests.get(EDL, auth=HTTPBasicAuth(edl_user, edl_pwd),
                                        headers=headers, verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
                sendemail("regular", pull_time, email, email_server, email_user, email_pwd)

        #demisto.debug(f'EDL monitor EDL text contents:\n{response.text}')

        pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
        # Monitoring for contents or just availability?
        if response.status_code != 200:
            sendemail("regular", pull_time, email, email_server, email_user, email_pwd)
            raise ValueError("Non-200 response for EDL, email sent")

        # Check for auth failure message from XSOAR EDL
        if response.text[:28] == "Basic authentication failed.":
            raise ValueError("Authentication failed- do you need user and password?")

        if mon_contents:
            results = sorted(response.text.split('\n'))
            demisto.debug(f'EDL monitor EDL LIST:\n{results}')
            demisto.debug(f'EDL monitor context data:\n{get_integration_context()}')
            if get_integration_context() is not None and get_integration_context() != {}:
                prev_result = list(get_integration_context().values())[0]
                prev_timestamp = list(get_integration_context().keys())[0]
            else:
                prev_result = None
                prev_timestamp = None
            demisto.debug(f'Integration context prev_result: {prev_result}')
            demisto.debug(f'Integration context prev_timestamp: {prev_timestamp}')
            #demisto.debug(f'Integration context values: {list(prev_result.values())[0]}')
            # Sort and check for diff
            if prev_result:
                demisto.debug('Found previous run data from integration context')
                count = 0
                diff = False
                for v in results:
                    #demisto.debug(f'Cur key: {count}')
                    #demisto.debug(f'Cur value: {v}')
                    if prev_result[count] != v:
                        diff = True
                        # Found diff between last EDL and current!
                        demisto.debug(f'Found difference at pulltime {pull_time}')
                        # Open file to write for attachment
                        filename = "EDL-" + instance_name + " as of " + pull_time + ".txt"
                        res_file = open(filename, "w")
                        # Write to file
                        res_file.write('\n'.join(results))
                        res_file.close()
                        # with open("EDLmonitor-" + instance_name + ".txt",'rb') as f:
                        #    demisto.debug(f'EDL monitor file contents:\n{f.read()}')
                        sendemail(pull_time, instance_name, email, email_server, email_user, email_pwd, filename)

                        # Save results and timestamp to context for next check of EDL
                        set_integration_context({pull_time: results})
                        break
                    count += 1
                demisto.debug(f'Found any diff? {diff}')
            else:
                # No previous run data from integration context
                demisto.debug('No previous run data from integration context')
                # Open file to write for attachment
                filename = "EDL-" + instance_name + " as of " + pull_time + ".txt"
                res_file = open(filename, "w")
                # Write to file
                res_file.write('\n'.join(results))
                res_file.close()
                # with open("EDLmonitor-" + instance_name + ".txt",'rb') as f:
                #    demisto.debug(f'EDL monitor file contents:\n{f.read()}')
                sendemail("regular", pull_time, email, email_server, email_user, email_pwd, filename)
                # Save results and timestamp to context for next check of EDL
                set_integration_context({pull_time: results})
        else:
            # Monitoring availability only, clear instance context
            set_integration_context(None)
    except DemistoException as e:
        raise e
    incidents: List[Dict[str, Any]] = []
    return incidents


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    edl_user = params.get('credentials', {}).get('identifier')
    edl_pwd = params.get('credentials', {}).get('password')
    email = params.get('emailTo')
    email_server = params.get('emailServer')
    email_user = params.get('emailCredentials', {}).get('identifier')
    email_pwd = params.get('emailCredentials', {}).get('password')
    mon_contents = params.get('monitor-contents')

    EDL = params.get('EDL')
    demisto.debug(f'EDL monitor checking EDL {EDL}')
    if timeout_str := params.get('timeout') is not None:
        timeout = int(timeout_str)
    else:
        timeout = 180
    start_time = datetime.now()

    #headers = {"Content-Type": "application/json"}

    verify_certificate = not params.get('insecure', False)
    #proxy = params.get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    try:
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
            result = test_module(EDL, edl_user, edl_pwd, verify_certificate, pull_time,
                                 email, email_server, email_user, email_pwd, timeout)
            return_results(result)
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(start_time, EDL, edl_user, edl_pwd, verify_certificate, email,
                                        email_server, email_user, email_pwd, timeout, mon_contents)
            demisto.debug('Finishing up...')
            demisto.incidents([])
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('EDLmonitor', 'end', __line__())
