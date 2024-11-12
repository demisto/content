import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime
import requests
import smtplib
import zipfile
import tempfile
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from requests.exceptions import ConnectTimeout
from requests.auth import HTTPBasicAuth


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')

''' HELPER FUNCTIONS '''


def sendemail(reason, create_ts, email, email_server, email_user, email_pwd, txtfile=None):

    sender = "noreply@demisto.com"
    if txtfile is not None:
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
            themsg['Subject'] = f'EDL monitor and Checker results for {instance_name}'
        themsg['To'] = email
        themsg['From'] = sender
        themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
        msg = MIMEBase('application', 'zip')
        msg.set_payload(zf.read())
        encoders.encode_base64(msg)
        msg.add_header('Content-Disposition', 'attachment',
                       filename="EDL Monitor Results.zip")
        themsg.attach(msg)
    else:
        demisto.debug(f'EDL monitor availability email send to - {email}')

        # Create the message
        themsg = MIMEMultipart()
        if reason == "timeout":
            themsg['Subject'] = f'EDL timeout at {create_ts}! Instance- {instance_name}'
        else:
            themsg['Subject'] = f'EDL down at {create_ts}! Instance- {instance_name}'
        themsg['To'] = email
        sender = "noreply@demisto.com"
        themsg['From'] = sender
    themsg_str = themsg.as_string()
    try:
        # Enable additional smtplib logs
        # smtplib.SMTP.debuglevel = 1
        SERVER = smtplib.SMTP(email_server, 587)
        SERVER.ehlo()  # type: ignore
        # if TLS is True or TLS == 'STARTTLS' or str(TLS).lower() == 'true':
        SERVER.starttls()  # type: ignore
        if email_user != "":
            demisto.debug('EDL monitor Email AUTHING')
            # WARNING: the following line is for debugging only.
            # demisto.debug(f'EDL monitor Email - {email_user} {email_pwd}')
            SERVER.login(email_user, email_pwd)

        SERVER.sendmail(sender, email, themsg_str)
        # SERVER.sendmail(FROM, to + cc + bcc, str_msg)  # type: ignore[union-attr]
        SERVER.quit()
        demisto.debug('EDL monitor Successfully sent email')
    except Exception as err:
        raise ValueError(f"Failed to send email: {str(err)}")


''' COMMAND FUNCTIONS '''


def test_module(email, email_server, email_user, email_pwd) -> str:
    """
    Tests server email (for sending email) connectivity and authentication'
    When 'ok' is returned it indicates the email server is accessible and if email credentials are valid
    """
    try:
        # Enable additional smtplib logs
        # smtplib.SMTP.debuglevel = 1
        SERVER = smtplib.SMTP(email_server, 587)
        SERVER.ehlo()  # type: ignore
        # if TLS is True or TLS == 'STARTTLS' or str(TLS).lower() == 'true':
        SERVER.starttls()  # type: ignore
        if email_user != "":
            demisto.debug('EDL monitor Email AUTHING')
            # WARNING: the following line is for debugging only.
            # demisto.debug(f'EDL monitor Email - {email_user} {email_pwd}')
            SERVER.login(email_user, email_pwd)

        SERVER.quit()
    except DemistoException as e:
        raise e

    return 'ok'


def check_edl(cmd, start_time, EDL, edl_user, edl_pwd, verify_certificate, email, email_server, email_user,
              email_pwd, timeout, mon_contents):
    try:
        demisto.debug(f'Start time {start_time}')
        demisto.debug(f'Cur time {datetime.now()}')
        demisto.debug(f'Parameters: {start_time}, {EDL}, {edl_user}, {verify_certificate}, {email}, \
        {email_server}, {email_user}, {timeout}, {mon_contents}')

        if edl_pwd is None:
            # No auth on EDL
            demisto.debug('EDL monitor no auth to EDL')
            try:
                response = requests.get(EDL, verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
                if email is not None:
                    sendemail("timeout", pull_time, email, email_server, email_user, email_pwd)
                return "timeout!"
        else:
            # Auth on EDL
            demisto.debug('EDL monitor auth to EDL')
            try:
                response = requests.get(EDL, auth=HTTPBasicAuth(edl_user, edl_pwd), verify=verify_certificate, timeout=timeout)
            except ConnectTimeout:
                # Timeout!
                pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
                if email is not None:
                    sendemail("timeout", pull_time, email, email_server, email_user, email_pwd)
                return "timeout!"

        # demisto.debug(f'EDL monitor EDL text contents:\n{response.text}')

        pull_time = datetime.now().strftime('%m-%d-%Y %H:%M:%S')
        # Monitoring for contents or just availability?
        if response.status_code != 200:
            if email is not None:
                sendemail("regular", pull_time, email, email_server, email_user, email_pwd)
            return response.status_code

        # Check for auth failure message from XSOAR EDL
        if response.text[:28] == "Basic authentication failed.":
            raise ValueError("Authentication failed- do you need user and password?")

        if mon_contents:
            results = sorted(response.text.split('\n'))
            demisto.debug(f'EDL monitor EDL LIST:\n{results}')

            filename = f"{EDL} as of {pull_time}.txt"
            with open(filename, "w") as res_file:
                # Write to file
                csv_string = '\n'.join(results)
                res_file.write(csv_string)
            # with open("EDLmonitor-" + instance_name + ".txt",'rb') as f:
            #    demisto.debug(f'EDL monitor file contents:\n{f.read()}')
            if email is not None:
                sendemail(pull_time, instance_name, email, email_server, email_user, email_pwd, filename)

    except DemistoException as e:
        raise e
    if cmd == "check-status":
        return [200]
    elif cmd == "email-edl-contents":
        return ["Success"]
    elif cmd == "get-edl-contents":
        return [csv_string, pull_time]
    return None


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    email_server = params.get('emailServer')
    email_user = params.get('emailCredentials', {}).get('identifier')
    email_pwd = params.get('emailCredentials', {}).get('password')

    email = args.get('Email')
    EDL = args.get('EDL')
    edl_user = args.get('EDL_user')
    edl_pwd = args.get('EDL_password')
    demisto.debug(f'EDL monitor checking EDL {EDL}')
    if (timeout_str := params.get('timeout')) is not None:
        # if params.get('timeout') is not None:
        # timeout = int(params.get('timeout'))
        timeout = int(timeout_str)
    else:
        timeout = 120
    start_time = datetime.now()

    verify_certificate = not params.get('insecure', False)
    # proxy = params.get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    try:
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(email, email_server, email_user, email_pwd)
            return_results(result)
        elif command == 'get-edl-contents':
            mon_contents = True
            results = check_edl('get-edl-contents', start_time, EDL, edl_user, edl_pwd, verify_certificate,
                                email, email_server, email_user, email_pwd, timeout, mon_contents)
            demisto.debug('Finishing get-edl-contents...')
            filename = "EDLmonitor_results.csv"
            return_results(fileResult(filename, results[0]))
        elif command == 'email-edl-contents':
            mon_contents = True
            results = check_edl('email-edl-contents', start_time, EDL, edl_user, edl_pwd, verify_certificate,
                                email, email_server, email_user, email_pwd, timeout, mon_contents)
            demisto.debug('Finishing email-edl-contents...')
            demisto.results(results)
        elif command == 'check-status':
            mon_contents = False
            results = check_edl('check-status', start_time, EDL, edl_user, edl_pwd, verify_certificate,
                                email, email_server, email_user, email_pwd, timeout, mon_contents)
            demisto.debug('Finishing check-status...')
            demisto.results(results)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
