import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import time
import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class DemistoLogger:
    """Wrapper class to add a prefix to all logging statements so they can be located more easily in the logs"""

    def __init__(self, d, log_prefix=''):
        self.demisto = d
        self.log_prefix = log_prefix

    def debug(self, msg):
        demisto.debug(self.log_prefix + msg)

    def error(self, msg):
        demisto.error(self.log_prefix + msg)


class DemistoDataStore:
    """Convenience class to persist and retrieve data between plugin calls"""

    class DataStoreMethod:
        """Enum class describing ways data can be persisted"""
        def __init__(self):
            pass
        CONTEXT = 1
        LAST_RUN = 2

    def __init__(self, d):
        self.demisto = d
        self.last_run = demisto.getLastRun() if demisto.getLastRun() is not None else {}
        self.context = demisto.context() if demisto.context() is not None else {}

        if demisto.command() == 'fetch-incidents':
            self.data_store_method = self.DataStoreMethod.LAST_RUN
        elif demisto.command() != 'test-module':
            self.data_store_method = self.DataStoreMethod.CONTEXT
        else:
            self.data_store_method = None

    def set_context(self, key, value, msg=''):
        demisto.results({
            'Type': 1,
            'Contents': msg,
            'ContentsFormat': 'text',
            'EntryContext': {key: [value]}
        })

    def set_last_run(self, key, value):
        self.last_run[key] = value

    def get_last_run(self):
        return self.last_run

    def get(self, key):
        if self.data_store_method == self.DataStoreMethod.LAST_RUN:
            return self.last_run.get(key)
        elif self.data_store_method == self.DataStoreMethod.CONTEXT:
            return self.context.get(key)
        else:
            return None

    def flush(self):
        demisto.setLastRun(self.last_run)


'''Custom exception types'''


class HttpException(Exception):
    pass


class IronDefense:
    """Main class for performing plugin actions"""

    def __init__(self, session, host, port, credentials, logger, data_store, request_timeout=60.0):
        self.session = session
        self.host = host
        self.base_url = 'https://{}:{}/IronApi'.format(host, port)
        self.credentials = credentials
        self.request_timeout = request_timeout
        self.logger = logger
        self.data_store = data_store

        self.session.headers.update({'Content-Type': 'application/json'})
        self._configure_session_auth(data_store.get('IronDefense'))

    ''' HELPER FUNCTIONS '''
    def _get_jwt(self, context):
        if context is None:
            return None

        try:
            return context['Sessions']['JWT']
        except KeyError:
            return None

    def _configure_session_auth(self, data):
        self.logger.debug('Getting jwt...')

        jwt = self._get_jwt(data)
        if jwt:
            # set the auth token if it exists
            self.session.headers.update({'Authorization': 'Bearer ' + jwt})

    def _http_request(self, method, uri, body='{}', headers={}, params={}, auth=None, files=None):
        # Makes an API call with the given arguments
        resp = self.session.request(
            method,
            self.base_url + uri,
            data=body,
            headers=headers,
            verify=False,
            params=params,
            files=files,
            timeout=self.request_timeout,
            auth=auth,
        )
        if resp.status_code == 401:
            if auth is not None:
                # incorrect creds have been provided
                return resp

            # the session has expired so we need to log in again
            self.logger.debug('Login required!')

            username = self.credentials.get('identifier')
            password = self.credentials.get('password')

            # retry the original request with basic auth credentials
            return self._http_request(method, uri,
                                      body=body,
                                      params=params,
                                      files=files,
                                      auth=(username, password))
        elif resp.status_code >= 500:
            self.logger.error('A server error has occurred. The response is: ' + json.dumps(resp.json()))

        if auth is not None:
            # persist the jwt
            jwt = resp.headers.get('auth-token')
            # save the jwt
            if self.data_store.data_store_method is DemistoDataStore.DataStoreMethod.LAST_RUN:
                # the context does not exist which means we are running 'fetch-incidents'
                # save the jwt in last run so we can retrieve it later
                self.data_store.set_last_run('IronDefense', {
                    'Sessions': {
                        'Host': self.host,
                        'JWT': jwt
                    }
                })
            elif self.data_store.data_store_method is DemistoDataStore.DataStoreMethod.CONTEXT:
                context_entry = {
                    'Host': self.host,
                    'JWT': jwt
                }
                # save the jwt in the context so we can retrieve it later
                self.data_store.set_context('IronDefense.Sessions(obj.Host===val.Host)', context_entry,
                                            msg='Successfully logged in')

        return resp

    def _get_error_msg_from_response(self, resp):
        err_msg = resp.json().get('msg')
        if err_msg is None:
            err_msg = resp.text
        return err_msg

    '''MAIN FUNCTIONS'''

    def fetch_incidents(self):
        last_run = self.data_store.get_last_run()
        now = time.time()
        # update the last run time
        self.data_store.set_last_run('last_run_time', now)
        self.logger.debug('Fetching incidents...')

        last_run_time = last_run.get('last_run_time')
        self.logger.debug('Last run time was: ' + str(last_run.get('last_run_time')))

        if last_run_time:
            self.logger.debug('No new incidents')
            # we already ran. This is for testing only so the integration does not flood demisto with test incidents.
            # In the near future this block will be removed.
            return []
        else:
            resp = self._http_request('GET', '/Alert')
            if resp.status_code == 200:
                self.logger.debug('json response is: ' + json.dumps(resp.json()))
                alert = {
                    'name': '',
                    'details': '',
                    'occurred': '',
                    'rawJSON': json.dumps(resp.json())
                }
                self.logger.debug('1 incident fetched')
                return [alert]
            else:
                raise Exception('Fetch failed. Status code was ' + str(resp.status_code))

    def test_module(self):
        self.logger.debug('Testing module...')
        username = self.credentials.get('identifier')
        password = self.credentials.get('password')
        resp = self._http_request('POST', '/Login', auth=(username, password))
        if resp.status_code == 200:
            self.logger.debug('Success!')
            return 'ok'
        else:
            return 'Test failed ({}): {}'.format(str(resp.status_code), resp.json()['msg'])

    def update_analyst_ratings(self, alert_id, severity='SEVERITY_UNDECIDED', expectation='EXP_UNKNOWN', comments='',
                               share_irondome=False):
        self.logger.debug('Submitting analyst rating: Alert ID={} Severity={} Expected={} Comments={} Share '
                          'w/IronDome={}'.format(alert_id, severity, expectation, comments, share_irondome))

        req_body = {
            'alert_id': alert_id,
            'analyst_severity': 'SEVERITY_' + severity.upper(),
            'analyst_expectation': 'EXP_' + expectation.upper(),
            'comment': comments,
            'share_comment_with_irondome': share_irondome
        }
        response = self._http_request('POST', '/RateAlert', body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error('Failed to rate alert ({}). The response failed with status code {}. The response was: '
                              '{}'.format(alert_id, response.status_code, response.text))
            raise HttpException('Failed to rate alert {} ({}): {}'.format(alert_id, response.status_code, err_msg))
        else:
            self.logger.debug('Successfully submitted rating for alert ({})'.format(alert_id))
            return 'Submitted analyst rating to IronDefense!'

    def add_comment_to_alert(self, alert_id, comment='', share_irondome=False):
        self.logger.debug('Submitting comment: Alert ID={} Comment={} Share '
                          'w/IronDome={}'.format(alert_id, comment, share_irondome))

        req_body = {
            'alert_id': alert_id,
            'comment': comment,
            'share_comment_with_irondome': share_irondome
        }
        response = self._http_request('POST', '/CommentOnAlert', body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error('Failed to add comment to alert ({}). The response failed with status code {}. The '
                              'response was: {}'.format(alert_id, response.status_code, response.text))
            raise HttpException('Failed to add comment to alert {} ({}): {}'.format(alert_id, response.status_code,
                                err_msg))
        else:
            self.logger.debug('Successfully added comment to alert ({})'.format(alert_id))
            return 'Submitted comment to IronDefense!'

    def set_alert_status(self, alert_id, status='STATUS_NONE', comments='', share_irondome=False):
        self.logger.debug('Submitting status: Alert ID={} Status={} Comments={} Share '
                          'w/IronDome={}'.format(alert_id, status, comments, share_irondome))

        req_body = {
            'alert_id': alert_id,
            'status': 'STATUS_' + status.upper().replace(" ", "_"),
            'comment': comments,
            'share_comment_with_irondome': share_irondome
        }
        response = self._http_request('POST', '/SetAlertStatus', body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error('Failed to set status for alert ({}). The response failed with status code {}. The '
                              'response was: {}'.format(alert_id, response.status_code, response.text))
            raise HttpException('Failed to set status for alert {} ({}): {}'.format(alert_id, response.status_code,
                                err_msg))
        else:
            self.logger.debug('Successfully submitted status for alert ({})'.format(alert_id))
            return 'Submitted status to IronDefense!'


''' COMMANDS MANAGER / SWITCH PANEL '''


def fetch_incidents_command():
    incidents = IRON_DEFENSE.fetch_incidents()
    demisto.incidents(incidents)


def test_module_command():
    results = IRON_DEFENSE.test_module()
    demisto.results(results)


def update_analyst_ratings_command():
    alert_id = demisto.getArg('alert_id')
    severity = demisto.getArg('severity')
    expectation = demisto.getArg('expectation')
    comments = demisto.getArg('comments')
    share_irondome_arg = demisto.getArg('share_comment_with_irondome')
    share_irondome = True if share_irondome_arg.lower() == 'true' else False
    results = IRON_DEFENSE.update_analyst_ratings(alert_id, severity=severity, expectation=expectation, comments=comments,
                                                  share_irondome=share_irondome)
    demisto.results(results)


def add_comment_to_alert_command():
    alert_id = demisto.getArg('alert_id')
    comment = demisto.getArg('comment')
    share_irondome_arg = demisto.getArg('share_comment_with_irondome')
    share_irondome = True if share_irondome_arg.lower() == 'true' else False
    results = IRON_DEFENSE.add_comment_to_alert(alert_id, comment=comment, share_irondome=share_irondome)
    demisto.results(results)


def set_alert_status_command():
    alert_id = demisto.getArg('alert_id')
    status = demisto.getArg('status')
    comments = demisto.getArg('comments')
    share_irondome_arg = demisto.getArg('share_comment_with_irondome')
    share_irondome = True if share_irondome_arg.lower() == 'true' else False
    results = IRON_DEFENSE.set_alert_status(alert_id, status=status, comments=comments,
                                            share_irondome=share_irondome)
    demisto.results(results)


COMMANDS = {
    'test-module': test_module_command,
    # For now, we will not support fetching of incidents
    # 'fetch-incidents': fetch_incidents_command,
    'irondefense-rate-alert': update_analyst_ratings_command,
    'irondefense-comment-alert': add_comment_to_alert_command,
    'irondefense-set-alert-status': set_alert_status_command
}
COOKIE_KEY = 'user_sid'
LOG_PREFIX = 'IronDefense Integration: '

'''EXECUTION'''

if __name__ == '__builtin__':
    try:
        # Globals
        PARAMS = demisto.params()
        CREDENTIALS = PARAMS.get('credentials')
        HOST = PARAMS.get('ironAPIHost', 'localhost')
        PORT = PARAMS.get('ironAPIPort', 443)
        REQUEST_TIMEOUT = float(PARAMS.get('requestTimeout', 60))
        DATA_STORE = DemistoDataStore(demisto)
        LOGGER = DemistoLogger(demisto, LOG_PREFIX)

        # initialize the IronDefense object
        IRON_DEFENSE = IronDefense(requests.session(), HOST, PORT, CREDENTIALS, LOGGER,
                                   DATA_STORE, request_timeout=REQUEST_TIMEOUT)

        LOGGER.debug('Invoking integration with Command: ' + demisto.command())
        if demisto.command() in COMMANDS.keys():
            COMMANDS[demisto.command()]()
        else:
            LOGGER.error('Command not found: ' + demisto.command())
            return_error('Command not found: ' + demisto.command())  # type: ignore[name-defined]

        DATA_STORE.flush()

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(str(e))  # type: ignore[name-defined]
