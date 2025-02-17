import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import textwrap
from CommonServerUserPython import *
from string import Template


def find_additional_incident_info(incident: dict) -> dict:
    additional_info = {}

    if incident.get('labels'):
        for label in incident['labels']:
            if label['type'] == 'Email/from':
                additional_info['employee_email'] = label['value'].lower()

        if incident.get('name'):
            additional_info['incident_subject'] = incident['name']

        if incident.get('details'):
            additional_info['employee_request'] = incident['details']

    return additional_info


def find_additional_ad_info(email: str, manager_attribute: str) -> dict:
    additional_info = {}

    filter_str = fr'(&(objectClass=user)(mail={email}))'
    response = demisto.executeCommand('ad-search', {'filter': filter_str,
                                                    'attributes': 'displayName,' + manager_attribute})

    if response and isError(response[0]):
        demisto.results(response)
        sys.exit(0)

    if not (type(response) is list and type(response[0].get('Contents')) is list
            and type(response[0]['Contents'][0]) is dict):
        demisto.results('Unable to find manager email.')
        sys.exit(0)

    data = response[0]['Contents'][0]

    if data.get('manager_attribute') and type(data['manager_attribute']) is list:
        additional_info['manager_dn'] = data[manager_attribute][0]

    # This was added as the json structure returned from the AD search during testing
    # seems to be different from the original.
    elif data.get('attributes') and data['attributes'].get(manager_attribute) \
            and type(data['attributes'][manager_attribute]) is list:
        additional_info['manager_dn'] = data['attributes'][manager_attribute][0]

    else:
        demisto.results('Unable to find manager email.')
        sys.exit(0)

    if data.get('displayName') and type(data['displayName']) is list:
        additional_info['employee_name'] = data['displayName'][0]

    # This was added as the json structure returned from the AD search during testing
    # seems to be different from the original.
    elif data.get('attributes') and data['attributes'].get('displayName') \
            and type(data['attributes']['displayName']) is list:
        additional_info['employee_name'] = data['attributes']['displayName'][0]

    filter_str = fr'(&(objectClass=User)(distinguishedName={additional_info["manager_dn"]}))'
    response = demisto.executeCommand('ad-search', {'filter': filter_str, 'attributes': 'displayName,mail'})

    if response and isError(response[0]):
        demisto.results(response)
        sys.exit(0)

    if type(response) is list and type(response[0].get('Contents')) is list and \
            type(response[0]['Contents'][0]) is dict:

        data = response[0]['Contents'][0]

        if data.get('mail') and type(data['mail']) is list:
            additional_info['manager_email'] = data['mail'][0]

        # This was added as the json structure returned from the AD search during testing
        # seems to be different from the original.
        elif data.get('attributes') and data['attributes'].get('mail') \
                and type(data['attributes']['mail']) is list:
            additional_info['manager_email'] = data['attributes']['mail'][0]

        if data.get('displayName') and type(data['displayName']) is list:
            additional_info['manager_name'] = data['displayName'][0]

        # This was added as the json structure returned from the AD search during testing
        # seems to be different from the original.
        elif data.get('attributes') and data['attributes'].get('displayName') \
                and type(data['attributes']['displayName']) is list:
            additional_info['manager_name'] = data['attributes']['displayName'][0]

    return additional_info


def generate_mail_subject(incident_subject: str, investigation_id: str, allow_reply: bool,
                          persistent: Optional[bool] = None, reply_entries_tag: Optional[str] = None) -> str:
    subject = incident_subject + f' - #{investigation_id}'

    if allow_reply:
        params = {}

        if persistent is not None:
            persistent_str = str(persistent).lower()
            params['persistent'] = persistent_str

        if reply_entries_tag is not None:
            params['replyEntriesTag'] = reply_entries_tag

        response = demisto.executeCommand('addEntitlement', params)

        if response and isError(response[0]):
            demisto.results(response)
            sys.exit(0)

        entitlement = demisto.get(response[0], 'Contents')

        if not entitlement:
            demisto.results('Unable to get entitlement')
            sys.exit(0)

        subject += ' ' + entitlement

    return subject


def generate_mail_body(manager_name: str, employee_name: str, employee_request: str) -> str:
    body = """
    Hi $manager_name,
    We've received the following request below from $employee_name. \
    Please reply to this email with either "approve" or "deny".
    Cheers,
    Your friendly security team
    """

    body_template = Template(body)
    result_body = body_template.safe_substitute(manager_name=manager_name, employee_name=employee_name)
    result_body = textwrap.dedent(result_body)
    return result_body + '\n----------' + employee_request


def main():  # pragma: no cover
    args = demisto.args()
    email = args.get('email')
    manager_attribute = args.get('manager', 'manager')
    allow_reply = argToBoolean(args.get('allowReply'))
    mail_body = args.get('body')
    employee_request = args.get('request')
    reply_entries_tag = args.get('replyEntriesTag')
    persistent = argToBoolean(args.get('persistent'))

    last_incident = demisto.incidents()[0]

    additional_info = find_additional_incident_info(last_incident)

    if not email:
        if additional_info.get('employee_email'):
            email = additional_info.get('employee_email')

        else:
            demisto.results('Could not find employee email.')

    additional_info.update(find_additional_ad_info(email=email, manager_attribute=manager_attribute))

    if not employee_request:
        employee_request = additional_info.get('employee_request')

    if not mail_body:
        mail_body = generate_mail_body(
            manager_name=additional_info['manager_name'],
            employee_name=additional_info['employee_name'],
            employee_request=employee_request
        )

    demisto.results(
        demisto.executeCommand('send-mail', {
            'to': additional_info['manager_email'],
            'subject': generate_mail_subject(
                incident_subject=additional_info['incident_subject'],
                investigation_id=demisto.investigation().get('id'),
                allow_reply=allow_reply,
                persistent=persistent,
                reply_entries_tag=reply_entries_tag
            ),
            'body': mail_body,
        }))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
