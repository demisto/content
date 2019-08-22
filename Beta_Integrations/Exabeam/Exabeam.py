import demistomock as demisto
from CommonServerUserPython import *

from CommonServerPython import *

''' IMPORTS '''
import requests
from datetime import datetime

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBALS '''
URL = demisto.params()['url']
if URL[-1] != '/':
    URL += '/'
URL_LOGIN = URL + 'api/'
URL_UBA = URL + 'uba/api/'
SESSION = requests.session()
SESSION.headers.update({'Accept': 'application/json'})
if demisto.params()['insecure']:
    SESSION.verify = False

''' HELPERS '''


def convert_unix_to_date(d):
    ''' Convert millise since epoch to date formatted MM/DD/YYYY HH:MI:SS '''
    if d:
        dt = datetime.utcfromtimestamp(d / 1000)
        return dt.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


def convert_date_to_unix(d):
    ''' Convert a given date to millis since epoch '''
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def login():
    ''' Login using the credentials and store the cookie '''
    http_request('POST', URL_LOGIN + 'auth/login', data={
        'username': demisto.params()['credentials']['identifier'],
        'password': demisto.params()['credentials']['password']
    })


def logout():
    ''' Logout from the session '''
    http_request('GET', URL_LOGIN + 'auth/logout', None)


def http_request(method, path, data):
    ''' Do the actual HTTP request '''
    if method == 'GET':
        respone = SESSION.get(path, params=data)
    else:
        respone = SESSION.post(path, data=data)
    if respone.status_code != requests.codes.ok:
        text = respone.text
        if text:
            try:
                res = respone.json()
                text = 'Code: [%s], Error: [%s]' % (res.get('_apiErrorCode'), res.get('internalError'))
            except Exception:
                pass
        return_error('Error in API call to Exabeam [%d] - %s' % (respone.status_code, text))
    if not respone.text:
        return {}
    return respone.json()


def get_watchlist_id():
    ''' Return watchlist id based on given parameters '''
    if not demisto().args['id'] and not demisto.args()['title']:
        logout()
        return_error('Please provide either ID or title')
    wid = demisto.args()['id']
    if not wid:
        watchlist = http_request('GET', URL_UBA + 'watchlist', None)
        for item in watchlist:
            if item.get('title').lower() == demisto.args()['title'].lower():
                watchlist_id = item.get('watchlistId')
                break
    if not watchlist_id:
        logout()
        return_error('Unable to find watchlist with the given title')
    return watchlist


''' FUNCTIONS '''


def exabeam_users():
    ''' Return user statistics '''
    res = http_request('GET', URL_UBA + 'kpi/count/users', None)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('User statistics', [res], ['highRisk', 'recent', 'total'])
    })


def exabeam_assets():
    ''' Return asset statistics '''
    res = http_request('GET', URL_UBA + 'kpi/count/assets', None)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Asset statistics', [res], ['highRisk', 'recent', 'total'])
    })


def exabeam_sessions():
    ''' Return session statistics '''
    res = http_request('GET', URL_UBA + 'kpi/count/sessions', None)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Session statistics', [res], ['highRisk', 'recent', 'total'])
    })


def exabeam_events():
    ''' Return event statistics '''
    res = http_request('GET', URL_UBA + 'kpi/count/events', None)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Event statistics', [res], ['recent', 'total'])
    })


def exabeam_anomalies():
    res = http_request('GET', URL_UBA + 'kpi/count/anomalies', None)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Anomalies statistics', [res], ['recent', 'total'])
    })


def exabeam_notable():
    ''' Return notable users in a specific period of time '''
    res = http_request(
        'GET',
        URL_UBA + 'users/notable',
        {
            'numberOfResults': demisto.args()['number-of-results'],
            'unit': demisto.args()['unit'],
            'num': demisto.args()['num']
        }
    )

    if res.get('users'):
        users = [{
            'Highest': u['highestRiskScore'],
            'Name': u['userFullName'],
            'Username': demisto.get(u, 'user.username'),
            'Email': demisto.get(u, 'user.info.email'),
            'Department': demisto.get(u, 'user.info.department'),
            'DN': demisto.get(u, 'user.info.dn'),
            'RiskScore': demisto.get(u, 'user.riskScore'),
            'NotableSessionIDs': u.get('notableSessionIds', [])
        } for u in res['users']]

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'HumanReadable': tableToMarkdown('Notables', users,
                                             ['Name', 'Username', 'Email', 'Department', 'DN', 'RiskScore', 'Highest',
                                              'NotableSessionIDs']),
            'EntryContext': {'Exabeam.Notable': res['users']}
        })

    else:
        demisto.results('No notable users found in the requested period')


def exabeam_lockouts():
    ''' Return lockouts '''
    res = http_request(
        'GET',
        URL_UBA + 'lockouts/accountLockouts',
        {
            'numberOfResults': demisto.getArg('number-of-results'),
            'unit': demisto.getArg('unit'),
            'num': demisto.getArg('num')
        })
    if res.get('lockouts'):
        lockouts = [{
            'Name': demisto.get(l, 'user.info.fullName'),
            'Username': demisto.get(l, 'user.username'),
            'Email': demisto.get(l, 'user.info.email'),
            'Department': demisto.get(l, 'user.info.department'),
            'DN': demisto.get(l, 'user.info.dn'),
            'Title': demisto.get(l, 'user.info.title'),
            'RiskScore': demisto.get(l, 'user.riskScore'),
            'Executive': demisto.get(l, 'isUserExecutive'),
            'LockoutTime': convert_unix_to_date(demisto.get(l, 'firstLockoutEvent.time')),
            'Host': demisto.get(l, 'firstLockoutEvent.host'),
            'LockoutRisk': demisto.get(l, 'lockoutInfo.riskScore'),
            'LoginHost': demisto.get(l, 'lockoutInfo.loginHost')
        } for l in res['lockouts']]

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'HumanReadable': tableToMarkdown('Lockouts', lockouts,
                                             ['User', 'Username', 'Email', 'Department', 'DN', 'Title', 'RiskScore',
                                              'Executive', 'LockoutTime', 'Host', 'LockoutRisk', 'LoginHost']),
            'EntryContext': {'Exabeam.Lockout': res['lockouts']}
        })
    else:
        demisto.results('No lockouts found in the requested period')


def exabeam_timeline():
    ''' Returns session, triggered rules and events of a user '''
    res = http_request('GET', URL_UBA + 'user/%s/timeline/entities/all' % demisto.args()['username'], None)
    risk_score = 0
    session = ''
    for entity in res.get('entities', []):
        if entity.get('tp') == 'session' and entity.get('rs', 0) > risk_score:
            risk_score = entity.get('rs', 0)
            session = entity.get('id')
    if session:
        session_info = http_request('GET', URL_UBA + 'session/%s/info' % session, None)
        si = session_info.get('sessionInfo')
        if not si:
            return_error('Unable to find session info')
        session_data = {
            'Username': si.get('username'),
            'RiskScore': si.get('riskScore'),
            'InitialRiskScore': si.get('initialRiskScore'),
            'NumOfReasons': si.get('numOfReasons'),
            'LoginHost': si.get('loginHost'),
            'Zones': ','.join(si.get('zones', [])),
            'Assets': si.get('numOfAssets'),
            'Events': si.get('numOfEvents'),
            'SecurityEvents': si.get('numOfSecurityEvents')
        }
        md = tableToMarkdown(
            'Session %s from %s to %s' % (session, convert_unix_to_date(si.get('startTime')),
                                          convert_unix_to_date(si.get('endTime'))), [session_data],
            ['Username', 'RiskScore', 'InitialRiskScore', 'NumOfReasons', 'LoginHost', 'Zones', 'Assets', 'Events',
             'SecurityEvents'])

        triggered_rules_data = [{
            'ID': tr.get('ruleId'),
            'Type': tr.get('ruleType'),
            'Name': demisto.get(session_info, 'rules.%s.ruleName' % (tr.get('ruleId'))),
            'EventID': tr.get('eventId'),
            'SessionID': tr.get('sessionId'),
            'Source': demisto.get(session_info, 'triggeredRuleEvents.%s.fields.source' % (tr.get('eventId'))),
            'Domain': demisto.get(session_info, 'triggeredRuleEvents.%s.fields.domain' % (tr.get('eventId'))),
            'Host': demisto.get(session_info, 'triggeredRuleEvents.%s.fields.host' % (tr.get('eventId'))),
            'DestIP': demisto.get(session_info, 'triggeredRuleEvents.%s.fields.dest_ip' % (tr.get('eventId'))),
            'EventType': demisto.get(session_info, 'triggeredRuleEvents.%s.fields.event_type' % (tr.get('eventId')))
        } for tr in session_info.get('triggeredRules')]

        md += '\n' + tableToMarkdown('Triggered Rules',
                                     triggered_rules_data,
                                     ['ID', 'Type', 'Name', 'EventID', 'SessionID', 'EventType', 'Source', 'Domain',
                                      'Host', 'DestIP'])
        session_data['TriggeredRules'] = triggered_rules_data
        events = http_request(
            'GET',
            URL_UBA + 'timeline/events/start',
            {
                'username': demisto.args()['username'],
                'sequenceTypes': 'session',
                'startSequenceType': 'session',
                'startSequenceId': session,
                'preferredNumberOfEvents': 200
            }
        )

        events_data = [{
            'Type': ev.get('tp'),
            'Count': ev.get('c'),
            'Start': convert_unix_to_date(ev.get('ts')),
            'End': convert_unix_to_date(ev.get('te')),
            'Sources': [es.get('fields', {}).get('source') for es in ev.get('es')]
        } for ev in events.get('aggregatedEvents', [])]

        md += '\n' + tableToMarkdown('Timeline', events_data, ['Type', 'Count', 'Start', 'End'])
        session_data['Events'] = events_data

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': events,
            'HumanReadable': md,
            'EntryContext': {'Exabeam.Timeline': session_data}
        })
    else:
        demisto.results('No risk score exists for the given user')


def exabeam_session_entities():
    ''' Returns session entities for a given user, can be filtered by container-type, container-id '''
    res = http_request(
        'GET',
        URL_UBA + 'user/%s/timeline/entities' % demisto.args()['username'],
        {
            'numberOfResults': demisto.args()['number-of-results'],
            'unit': demisto.args()['unit'],
            'num': demisto.args()['num'],
            'endContainerType': demisto.args()['container-type'],
            'endContainerId': demisto.args()['container-id']
        }
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res
    })


def exabeam_user_info():
    ''' Returns user info '''
    username = demisto.args()['username']
    res = http_request('GET', URL_UBA + 'user/%s/info' % username, None)
    if res.get('username'):
        u = {
            'Username': res['username'],
            'AccountNames': ','.join(res.get('accountNames', [])),
            'Executive': res['isExecutive'],
            'WatchList': res['isOnWatchlist'],
            'Name': demisto.get(res, 'userInfo.info.fullName'),
            'ID': demisto.get(res, 'userInfo.info.accountId'),
            'Department': demisto.get(res, 'userInfo.info.department'),
            'DN': demisto.get(res, 'userInfo.info.dn'),
            'Email': demisto.get(res, 'userInfo.info.email'),
            'Type': demisto.get(res, 'userInfo.info.employeeType'),
            'Groups': demisto.get(res, 'userInfo.info.group'),
            'SID': demisto.get(res, 'userInfo.info.sid'),
            'Title': demisto.get(res, 'userInfo.info.title'),
            'RiskScore': demisto.get(res, 'userInfo.riskScore'),
            'AverageRiskScore': demisto.get(res, 'userInfo.averageRiskScore'),
            'Labels': demisto.get(res, 'userInfo.labels'),
            'FirstSeen': convert_unix_to_date(demisto.get(res, 'userInfo.firstSeen')),
            'LastSeen': convert_unix_to_date(demisto.get(res, 'userInfo.lastSeen')),
            'LastSessionID': demisto.get(res, 'userInfo.lastSessionId'),
            'PastScores': ','.join(map(str, demisto.get(res, 'userInfo.pastScores')))
        }

        md = tableToMarkdown('User info', [u], ['Name', 'Username', 'Email', 'Department', 'DN', 'Groups',
                                                'Title', 'RiskScore', 'AverageRiskScore', 'Executive', 'WatchList',
                                                'AccountNames', 'ID',
                                                'Type', 'SID', 'Labels', 'FirstSeen', 'LastSeen', 'LastSessionID',
                                                'PastScores'])

        if demisto.get(res, 'userInfo.info.photo'):
            md += '\n![Photo](data:image/png;base64,' + demisto.get(res, 'userInfo.info.photo') + ')\n'

        # Let's get the sessions as well
        notable_res = http_request(
            'GET',
            URL_UBA + 'users/notable',
            {
                'numberOfResults': 100,
                'unit': 'd',
                'num': 7
            }
        )
        if notable_res.get('users'):
            for un in notable_res['users']:
                if demisto.get(un, 'user.username') == username:
                    u['NotableList'] = True
                    md += '\n## User is on the notable list\n'
                    notable_session_ids = un.get('notableSessionIds', [])
                    if notable_session_ids:
                        u['NoteableSessionIDs'] = notable_session_ids
                        session_res = http_request(
                            'GET',
                            URL_UBA + 'user/%s/riskTimeline/data' % username,
                            {
                                'unit': 'd',
                                'num': 7,
                                'endTimeSequenceType': 'session',
                                'endTimeSequenceId': notable_session_ids[0]
                            }
                        )
                        if session_res.get('sessions'):
                            md += '\n' + tableToMarkdown('Sessions', session_res['sessions'])

                            demisto.results({
                                'Type': entryTypes['note'],
                                'ContentsFormat': formats['json'],
                                'Contents': res,
                                'HumanReadable': md,
                                'EntryContext': {
                                    'Account(val.Email && val.Email === obj.Email || val.ID && val.ID === obj.ID ||'
                                    ' val.Username && val.Username === obj.Username)': u}
                            })

                        else:
                            demisto.results('No username with [' + username + '] found')


def exabeam_triggered_rules():
    ''' Return triggered rules for a given container '''
    res = http_request(
        'GET',
        URL_UBA + 'triggeredRules',
        {
            'containerType': demisto.args()['container-type'],
            'containerId': demisto.args()['container-id']
        }
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res
    })


def exabeam_watchlists():
    ''' Retrieve current list of watchlists '''
    res = http_request('GET', URL_UBA + 'watchlist', None)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown('Watchlists', res, ['title', 'watchlistId']),
        'EntryContext': {'Exabeam.Watchlists': res}
    })


def exabeam_watchlist():
    watchlist_id = get_watchlist_id()
    res = http_request('GET', URL_UBA + 'watchlist/%s/' % watchlist_id, {'numberOfResults': demisto.args()['num']})

    users = [{
        'Name': demisto.get(u, 'user.info.fullName'),
        'Department': demisto.get(u, 'user.info.department'),
        'Username': u.get('username'),
        'RiskScore': demisto.get(u, 'user.riskScore'),
        'IsExecutive': u.get('isExecutive')
    } for u in res.get('users', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': tableToMarkdown(
            'Watchlist %s [%s] - %d users' % (res.get('title'), res.get('category'), res.get('totalNumberOfUsers')),
            users,
            ['Name', 'Department', 'Username', 'RiskScore', 'IsExecutive']),
        'EntryContext': {'Exabeam.Watchlist.%s' % res.get('title'): users}
    })


def exabeam_watchlist_add():
    ''' Adds a user to a given watchlist '''
    watchlist_id = get_watchlist_id()
    username = demisto.args()['username']
    res = http_request(
        'PUT',
        URL_UBA + 'watchlist/%s/add' % watchlist_id,
        {
            'items[]': username,
            'category': 'Users'
        }
    )

    if res.get('numberAdded') == 1:
        md = 'User %s added to watchlist %s' % (username, res.get('title'))
    else:
        md = 'User %s was already on watchlist %s' % (username, res.get('title'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': md
    })


def exabeam_watchlist_remove():
    watchlist_id = get_watchlist_id()
    username = demisto.args()['username']
    res = http_request('PUT', URL_UBA + 'watchlist/%s/remove' % watchlist_id, {
        'items[]': username,
        'category': 'Users',
        'watchlistId': watchlist_id
    })
    if res.get('numberRemoved') == 1:
        md = 'User %s removed from watchlist %s' % (username, res.get('title'))
    else:
        md = 'User %s was not on watchlist %s' % (username, res.get('title'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': md
    })


''' EXECUTION '''
login()

LOG('command is %s' % (demisto.command(),))

try:
    if demisto.command() == 'test-module':
        demisto.results('ok')

    elif demisto.command() == 'xb-users':
        exabeam_users()

    elif demisto.command() == 'xb-assets':
        exabeam_assets()

    elif demisto.command() == 'xb-sessions':
        exabeam_sessions()

    elif demisto.command() == 'xb-events':
        exabeam_events()

    elif demisto.command() == 'xb-anomalies':
        exabeam_anomalies()

    elif demisto.command() == 'xb-notable':
        exabeam_notable()

    elif demisto.command() == 'xb-lockouts':
        exabeam_lockouts()

    elif demisto.command() == 'xb-timeline':
        exabeam_timeline()

    elif demisto.command() == 'xb-session-entities':
        exabeam_session_entities()

    # elif demisto.command() == 'xb-userinfo':
    #     exabeam_userinfo()

    # elif demisto.command() == 'xb-triggered-rules':
    #     exabeam_triggerred_rules()

    elif demisto.command() == 'xb-watchlists':
        exabeam_watchlists()

    elif demisto.command() == 'xb-watchlist':
        exabeam_watchlist()

    elif demisto.command() == 'xb-watchlist-add':
        exabeam_watchlist_add()

    elif demisto.command() == 'xb-watchlist-remove':
        exabeam_watchlist_remove()

    else:
        logout()
        return_error('Unrecognized command: ' + demisto.command())


except Exception, e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)

logout()
