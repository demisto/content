import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import requests
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import urllib3
from dateutil.parser import parse

# Disable insecure warnings
urllib3.disable_warnings()


class WithSecureClient:
    """WithSecure Elements API Client"""

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 scope: str, verify: bool = True, proxy: bool = False):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.verify = verify
        self.proxy = proxy
        self.access_token = None
        self.session = requests.Session()

        if proxy:
            self.session.proxies = {
                'http': os.environ.get('HTTP_PROXY', ''),
                'https': os.environ.get('HTTPS_PROXY', '')
            }

        self.session.verify = verify

    def authenticate(self) -> str:
        """Get OAuth2 access token"""
        auth_url = f"{self.base_url}/as/token.oauth2"

        headers = {
            'User-Agent': 'XSOAR-WithSecure-Integration/1.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        data = {
            'grant_type': 'client_credentials',
            'scope': self.scope
        }

        auth = (self.client_id, self.client_secret)

        response = self.session.post(auth_url, headers=headers, data=data, auth=auth)

        if response.status_code != 200:
            raise DemistoException(f"Authentication failed: {response.text}")

        token_data = response.json()
        self.access_token = token_data.get('access_token')

        return self.access_token

    def _http_request(self, method: str, url_suffix: str, params: Dict = None,
                      json_data: Dict = None, data: Dict = None,
                      ok_codes: List[int] = None) -> Dict:
        """Execute HTTP request with authentication"""

        if not self.access_token:
            self.authenticate()

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'User-Agent': 'XSOAR-WithSecure-Integration/1.0'
        }

        if json_data:
            headers['Content-Type'] = 'application/json'
        elif data:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        url = f"{self.base_url}{url_suffix}"

        response = self.session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_data,
            data=data
        )

        if ok_codes is None:
            ok_codes = [200, 201, 202, 204, 207]

        if response.status_code not in ok_codes:
            # Try to re-authenticate if token expired
            if response.status_code == 401:
                self.authenticate()
                headers['Authorization'] = f'Bearer {self.access_token}'
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    data=data
                )

            if response.status_code not in ok_codes:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', response.text)
                except:
                    error_msg = response.text
                raise DemistoException(f"API Error ({response.status_code}): {error_msg}")

        try:
            return response.json() if response.content else {}
        except:
            return {}

    def whoami(self) -> Dict:
        """Get current user information"""
        return self._http_request('GET', '/whoami/v1/whoami')

    def get_security_events(self, organization_id: str = None, engine_group: str = None,
                            persistence_timestamp_start: str = None,
                            persistence_timestamp_end: str = None,
                            engine: List[str] = None, severity: List[str] = None,
                            limit: int = 200, anchor: str = None) -> Dict:
        """Query security events"""
        # This endpoint requires form-urlencoded data for its POST request.
        data = {}

        if organization_id:
            data['organizationId'] = organization_id
        if engine_group:
            data['engineGroup'] = engine_group
        if persistence_timestamp_start:
            data['persistenceTimestampStart'] = persistence_timestamp_start
        if persistence_timestamp_end:
            data['persistenceTimestampEnd'] = persistence_timestamp_end
        if engine:
            # Pass the list directly; 'requests' will correctly format it
            # for form-encoding (e.g., engine=epp&engine=edr).
            data['engine'] = engine
        if severity:
            # Same for severity.
            data['severity'] = severity
        if limit:
            data['limit'] = limit
        if anchor:
            data['anchor'] = anchor

        # The _http_request helper will set the Content-Type to
        # application/x-www-form-urlencoded when the 'data' parameter is used.
        return self._http_request('POST', '/security-events/v1/security-events', data=data)

    def get_incidents(self, organization_id: str = None, anchor: str = None,
                      created_timestamp_start: str = None, created_timestamp_end: str = None,
                      status: List[str] = None, resolution: List[str] = None,
                      risk_level: List[str] = None, archived: bool = None,
                      limit: int = 20, order: str = 'desc', source: List[str] = None) -> Dict:
        """List Broad Context Detections (BCDs)"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if anchor:
            params['anchor'] = anchor
        if created_timestamp_start:
            params['createdTimestampStart'] = created_timestamp_start
        if created_timestamp_end:
            params['createdTimestampEnd'] = created_timestamp_end
        if status:
            for s in status:
                params['status'] = s
        if resolution:
            for r in resolution:
                params['resolution'] = r
        if risk_level:
            for rl in risk_level:
                params['riskLevel'] = rl
        if archived is not None:
            params['archived'] = str(archived).lower()
        if limit:
            params['limit'] = limit
        if order:
            params['order'] = order
        if source:
            for src in source:
                params['source'] = src

        return self._http_request('GET', '/incidents/v1/incidents', params=params)

    def update_incident_status(self, incident_ids: List[str], status: str,
                               resolution: str = None) -> Dict:
        """Update status of BCDs"""

        json_data = {
            'targets': incident_ids,
            'status': status
        }

        if resolution:
            json_data['resolution'] = resolution

        return self._http_request('PATCH', '/incidents/v1/incidents', json_data=json_data)

    def add_comment_to_incident(self, incident_ids: List[str], comment: str) -> Dict:
        """Add comment to BCDs"""

        json_data = {
            'targets': incident_ids,
            'comment': comment
        }

        return self._http_request('POST', '/incidents/v1/comments', json_data=json_data)

    def get_detections(self, organization_id: str = None, incident_id: str = None,
                       anchor: str = None, created_timestamp_start: str = None,
                       created_timestamp_end: str = None, limit: int = 100) -> Dict:
        """List detections for given BCD"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if incident_id:
            params['incidentId'] = incident_id
        if anchor:
            params['anchor'] = anchor
        if created_timestamp_start:
            params['createdTimestampStart'] = created_timestamp_start
        if created_timestamp_end:
            params['createdTimestampEnd'] = created_timestamp_end
        if limit:
            params['limit'] = limit

        return self._http_request('GET', '/incidents/v1/detections', params=params)

    def get_devices(self, organization_id: str = None, device_id: str = None,
                    device_type: str = None, state: str = None, name: str = None,
                    online: bool = None, limit: int = 200, anchor: str = None,
                    protection_status_overview: str = None,
                    patch_overall_state: str = None) -> Dict:
        """Query devices"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if device_id:
            params['deviceId'] = device_id
        if device_type:
            params['type'] = device_type
        if state:
            params['state'] = state
        if name:
            params['name'] = name
        if online is not None:
            params['online'] = str(online).lower()
        if protection_status_overview:
            params['protectionStatusOverview'] = protection_status_overview
        if patch_overall_state:
            params['patchOverallState'] = patch_overall_state
        if limit:
            params['limit'] = limit
        if anchor:
            params['anchor'] = anchor

        return self._http_request('GET', '/devices/v1/devices', params=params)

    def update_device_state(self, device_ids: List[str], state: str) -> Dict:
        """Update device state"""

        json_data = {
            'targets': device_ids,
            'state': state
        }

        return self._http_request('PATCH', '/devices/v1/devices', json_data=json_data)

    def trigger_device_operation(self, organization_id: str, operation: str,
                                 device_ids: List[str], parameters: Dict = None,
                                 comment: str = None) -> Dict:
        """Trigger remote operation on devices"""

        json_data = {
            'organizationId': organization_id,
            'operation': operation,
            'targets': device_ids
        }

        if parameters:
            json_data['parameters'] = parameters
        if comment:
            json_data['comment'] = comment

        return self._http_request('POST', '/devices/v1/operations', json_data=json_data)

    def get_device_operations(self, device_id: str) -> Dict:
        """List device operations"""

        params = {'deviceId': device_id}
        return self._http_request('GET', '/devices/v1/operations', params=params)

    def get_organizations(self, organization_id: str = None, anchor: str = None,
                          org_type: str = 'company', limit: int = 200) -> Dict:
        """List organizations"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if anchor:
            params['anchor'] = anchor
        if org_type:
            params['type'] = org_type
        if limit:
            params['limit'] = limit

        return self._http_request('GET', '/organizations/v1/organizations', params=params)

    def get_invitations(self, organization_id: str = None, anchor: str = None,
                        limit: int = 200) -> Dict:
        """List device invitations"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if anchor:
            params['anchor'] = anchor
        if limit:
            params['limit'] = limit

        return self._http_request('GET', '/invitations/v1/invitations', params=params)

    def create_invitation(self, email: str, subscription_key: str, language_code: str = "en") -> dict:
        url_suffix = f"/identity-protection/v1/partners/subscriptions/{subscription_key}/users/invitations"
        data = {
            "email": email,
            "language_code": language_code
        }
        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=data
        )
        return response

    def delete_invitation(self, invitation_id: str) -> Dict:
        """Delete device invitation"""

        return self._http_request('DELETE', f'/invitations/v1/invitations/{invitation_id}')

    def get_profiles(self, organization_id: str = None, profile_type: str = None) -> Dict:
        """List security profiles"""

        params = {}

        if organization_id:
            params['organizationId'] = organization_id
        if profile_type:
            params['type'] = profile_type

        return self._http_request('GET', '/profiles/v1/profiles', params=params)


def test_module(client: WithSecureClient) -> str:
    """Test module connectivity"""
    try:
        result = client.whoami()
        if result.get('clientId'):
            return 'ok'
        else:
            return 'Authentication successful but no client info returned'
    except Exception as e:
        return f'Test failed: {str(e)}'


def whoami_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get current user information"""

    result = client.whoami()

    outputs = {
        'WithSecure.Whoami': result
    }

    readable_output = tableToMarkdown(
        'WithSecure User Information',
        result,
        headers=['clientId', 'organizationId']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_security_events_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get security events"""

    # API requires a time range and an engine/engineGroup.
    if not args.get('persistence_timestamp_start') and not args.get('persistence_timestamp_end'):
        raise ValueError(
            "API Error: A time range is required. Please provide the 'persistence_timestamp_start' or 'persistence_timestamp_end' argument.")

    if not args.get('engine') and not args.get('engine_group'):
        raise ValueError("API Error: An engine scope is required. Please provide the 'engine' or 'engine_group' argument.")

    organization_id = args.get('organization_id')
    engine_group = args.get('engine_group')
    persistence_timestamp_start = args.get('persistence_timestamp_start')
    persistence_timestamp_end = args.get('persistence_timestamp_end')
    engine = argToList(args.get('engine'))
    severity = argToList(args.get('severity'))
    limit = arg_to_number(args.get('limit', 200))
    anchor = args.get('anchor')

    result = client.get_security_events(
        organization_id=organization_id,
        engine_group=engine_group,
        persistence_timestamp_start=persistence_timestamp_start,
        persistence_timestamp_end=persistence_timestamp_end,
        engine=engine,
        severity=severity,
        limit=limit,
        anchor=anchor
    )

    events = result.get('items', [])

    outputs = {
        'WithSecure.SecurityEvent(val.id && val.id == obj.id)': events
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.SecurityEvent.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Security Events',
        events,
        headers=['id', 'severity', 'engine', 'action', 'serverTimestamp', 'organization.name']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_incidents_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get Broad Context Detections (incidents)"""

    organization_id = args.get('organization_id')
    anchor = args.get('anchor')
    created_timestamp_start = args.get('created_timestamp_start')
    created_timestamp_end = args.get('created_timestamp_end')
    status = argToList(args.get('status'))
    resolution = argToList(args.get('resolution'))
    risk_level = argToList(args.get('risk_level'))

    archived_arg = args.get('archived')
    if archived_arg is not None:
        if isinstance(archived_arg, bool):
            archived = archived_arg
        elif isinstance(archived_arg, str) and archived_arg.lower() in ['true', 'false']:
            archived = archived_arg.lower() == 'true'
        else:
            raise DemistoException(f"Invalid value for 'archived': {archived_arg}. Must be 'true' or 'false'.")
    else:
        archived = None

    limit = arg_to_number(args.get('limit', 20))
    order = args.get('order', 'desc')
    source = argToList(args.get('source'))

    result = client.get_incidents(
        organization_id=organization_id,
        anchor=anchor,
        created_timestamp_start=created_timestamp_start,
        created_timestamp_end=created_timestamp_end,
        status=status,
        resolution=resolution,
        risk_level=risk_level,
        archived=archived,
        limit=limit,
        order=order,
        source=source
    )

    incidents = result.get('items', [])

    outputs = {
        'WithSecure.Incident(val.incidentId && val.incidentId == obj.incidentId)': incidents
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Incident.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Incidents (BCDs)',
        incidents,
        headers=['incidentId', 'incidentPublicId', 'name', 'status', 'severity', 'riskLevel', 'createdTimestamp']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )

    organization_id = args.get('organization_id')
    anchor = args.get('anchor')
    created_timestamp_start = args.get('created_timestamp_start')
    created_timestamp_end = args.get('created_timestamp_end')
    status = argToList(args.get('status'))
    resolution = argToList(args.get('resolution'))
    risk_level = argToList(args.get('risk_level'))
    archived = argToBoolean(args.get('archived'))
    limit = arg_to_number(args.get('limit', 20))
    order = args.get('order', 'desc')
    source = argToList(args.get('source'))

    result = client.get_incidents(
        organization_id=organization_id,
        anchor=anchor,
        created_timestamp_start=created_timestamp_start,
        created_timestamp_end=created_timestamp_end,
        status=status,
        resolution=resolution,
        risk_level=risk_level,
        archived=archived,
        limit=limit,
        order=order,
        source=source
    )

    incidents = result.get('items', [])

    outputs = {
        'WithSecure.Incident(val.incidentId && val.incidentId == obj.incidentId)': incidents
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Incident.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Incidents (BCDs)',
        incidents,
        headers=['incidentId', 'incidentPublicId', 'name', 'status', 'severity', 'riskLevel', 'createdTimestamp']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def update_incident_status_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Update incident status"""

    incident_ids = argToList(args.get('incident_ids', []))
    status = args.get('status')
    resolution = args.get('resolution')

    if not incident_ids:
        raise DemistoException('incident_ids is required')
    if not status:
        raise DemistoException('status is required')

    result = client.update_incident_status(incident_ids, status, resolution)

    multistatus = result.get('multistatus', [])

    outputs = {
        'WithSecure.IncidentUpdate': multistatus
    }

    readable_output = tableToMarkdown(
        'WithSecure Incident Update Results',
        multistatus,
        headers=['target', 'status', 'details']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def add_comment_to_incident_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Add comment to incident"""

    incident_ids = argToList(args.get('incident_ids', []))
    comment = args.get('comment')

    if not incident_ids:
        raise DemistoException('incident_ids is required')
    if not comment:
        raise DemistoException('comment is required')

    result = client.add_comment_to_incident(incident_ids, comment)

    items = result.get('items', [])

    outputs = {
        'WithSecure.IncidentComment': items
    }

    readable_output = tableToMarkdown(
        'WithSecure Incident Comments Added',
        items,
        headers=['incidentId', 'comment']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_detections_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get detections for incident"""

    organization_id = args.get('organization_id')
    incident_id = args.get('incident_id')
    anchor = args.get('anchor')
    created_timestamp_start = args.get('created_timestamp_start')
    created_timestamp_end = args.get('created_timestamp_end')
    limit = arg_to_number(args.get('limit', 100))

    if not incident_id:
        raise DemistoException('incident_id is required')

    result = client.get_detections(
        organization_id=organization_id,
        incident_id=incident_id,
        anchor=anchor,
        created_timestamp_start=created_timestamp_start,
        created_timestamp_end=created_timestamp_end,
        limit=limit
    )

    detections = result.get('items', [])

    outputs = {
        'WithSecure.Detection(val.detectionId && val.detectionId == obj.detectionId)': detections
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Detection.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Detections',
        detections,
        headers=['detectionId', 'incidentId', 'deviceId', 'name', 'severity', 'createdTimestamp']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_devices_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get devices"""

    organization_id = args.get('organization_id')
    device_id = args.get('device_id')
    device_type = args.get('type')
    state = args.get('state')
    name = args.get('name')
    online_arg = args.get('online')
    online = argToBoolean(online_arg) if online_arg is not None else None
    protection_status_overview = args.get('protection_status_overview')
    patch_overall_state = args.get('patch_overall_state')
    limit = arg_to_number(args.get('limit', 200))
    anchor = args.get('anchor')

    result = client.get_devices(
        organization_id=organization_id,
        device_id=device_id,
        device_type=device_type,
        state=state,
        name=name,
        online=online,
        protection_status_overview=protection_status_overview,
        patch_overall_state=patch_overall_state,
        limit=limit,
        anchor=anchor
    )

    devices = result.get('items', [])

    outputs = {
        'WithSecure.Device(val.id && val.id == obj.id)': devices
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Device.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Devices',
        devices,
        headers=['id', 'name', 'type', 'state', 'online', 'protectionStatus', 'company.name']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def update_device_state_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Update device state"""

    device_ids = argToList(args.get('device_ids', []))
    state = args.get('state')

    if not device_ids:
        raise DemistoException('device_ids is required')
    if not state:
        raise DemistoException('state is required')

    result = client.update_device_state(device_ids, state)

    multistatus = result.get('multistatus', [])

    outputs = {
        'WithSecure.DeviceUpdate': multistatus
    }

    readable_output = tableToMarkdown(
        'WithSecure Device State Update Results',
        multistatus,
        headers=['target', 'status', 'details']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def trigger_device_operation_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Trigger device operation"""

    organization_id = args.get('organization_id')
    operation = args.get('operation')
    device_ids = argToList(args.get('device_ids', []))
    parameters = args.get('parameters')
    comment = args.get('comment')

    if not organization_id:
        raise DemistoException('organization_id is required')
    if not operation:
        raise DemistoException('operation is required')
    if not device_ids:
        raise DemistoException('device_ids is required')

    # Parse parameters if provided as JSON string
    if parameters and isinstance(parameters, str):
        try:
            parameters = json.loads(parameters)
        except json.JSONDecodeError:
            raise DemistoException('parameters must be valid JSON')

    result = client.trigger_device_operation(
        organization_id=organization_id,
        operation=operation,
        device_ids=device_ids,
        parameters=parameters,
        comment=comment
    )

    multistatus = result.get('multistatus', [])

    outputs = {
        'WithSecure.DeviceOperation': multistatus
    }

    readable_output = tableToMarkdown(
        'WithSecure Device Operation Results',
        multistatus,
        headers=['target', 'status', 'operationId', 'details']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_device_operations_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get device operations"""

    device_id = args.get('device_id')

    if not device_id:
        raise DemistoException('device_id is required')

    result = client.get_device_operations(device_id)

    operations = result.get('items', [])

    outputs = {
        'WithSecure.DeviceOperationStatus(val.id && val.id == obj.id)': operations
    }

    readable_output = tableToMarkdown(
        'WithSecure Device Operations',
        operations,
        headers=['id', 'status', 'operationName', 'startedTimestamp', 'lastUpdatedTimestamp']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_organizations_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get organizations"""

    organization_id = args.get('organization_id')
    anchor = args.get('anchor')
    org_type = args.get('type', 'company')
    limit = arg_to_number(args.get('limit', 200))

    result = client.get_organizations(
        organization_id=organization_id,
        anchor=anchor,
        org_type=org_type,
        limit=limit
    )

    organizations = result.get('items', [])

    outputs = {
        'WithSecure.Organization(val.id && val.id == obj.id)': organizations
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Organization.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Organizations',
        organizations,
        headers=['id', 'name', 'type']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def get_invitations_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Get device invitations"""

    organization_id = args.get('organization_id')
    anchor = args.get('anchor')
    limit = arg_to_number(args.get('limit', 200))

    result = client.get_invitations(
        organization_id=organization_id,
        anchor=anchor,
        limit=limit
    )

    invitations = result.get('items', [])

    outputs = {
        'WithSecure.Invitation(val.id && val.id == obj.id)': invitations
    }

    if result.get('nextAnchor'):
        outputs['WithSecure.Invitation.NextAnchor'] = result.get('nextAnchor')

    readable_output = tableToMarkdown(
        'WithSecure Device Invitations',
        invitations,
        headers=['id', 'email', 'deviceType', 'status', 'createdTimestamp']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def create_invitation_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get("email")
    subscription_key = args.get("subscription_key")
    language_code = args.get("language_code", "en")

    result = client.create_invitation(email, subscription_key, language_code)

    return CommandResults(
        outputs_prefix="WithSecure.Invitation",
        outputs_key_field="email",
        outputs=result,
        readable_output=tableToMarkdown("WithSecure Invitation Result", result),
        raw_response=result,
    )


def delete_invitation_command(client: WithSecureClient, args: Dict[str, Any]) -> CommandResults:
    """Delete device invitation"""

    invitation_id = args.get('invitation_id')

    if not invitation_id:
        raise DemistoException('invitation_id is required')

    result = client.delete_invitation(invitation_id)

    readable_output = f"WithSecure invitation {invitation_id} deleted successfully"

    return CommandResults(
        readable_output=readable_output,
        raw_response=result
    )

    organization_id = args.get('organization_id')
    profile_type = args.get('profile_type')

    try:
        result = client.get_profiles(
            organization_id=organization_id,
            profile_type=profile_type
        )
    except DemistoException as e:
        if '404' in str(e):
            return CommandResults(
                readable_output=f"No profiles found for organization_id: {organization_id}",
                outputs={},
                raw_response={}
            )
        raise

    profiles = result.get('items', [])

    outputs = {
        'WithSecure.Profile(val.id && val.id == obj.id)': profiles
    }

    readable_output = tableToMarkdown(
        'WithSecure Security Profiles',
        profiles,
        headers=['id', 'name', 'type', 'description']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )

    organization_id = args.get('organization_id')
    profile_type = args.get('profile_type')

    result = client.get_profiles(
        organization_id=organization_id,
        profile_type=profile_type
    )

    profiles = result.get('items', [])

    outputs = {
        'WithSecure.Profile(val.id && val.id == obj.id)': profiles
    }

    readable_output = tableToMarkdown(
        'WithSecure Security Profiles',
        profiles,
        headers=['id', 'name', 'type', 'description']
    )

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def fetch_incidents(client: WithSecureClient, params: Dict[str, Any]) -> List[Dict]:
    """Fetch incidents for XSOAR"""

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch')

    # Calculate first fetch time
    if not last_fetch:
        first_fetch_time = params.get('fetch_time', '3 days')
        first_fetch_time = dateparser.parse(f'{first_fetch_time} ago')
        last_fetch = first_fetch_time.isoformat() + 'Z'

    fetch_type = params.get('fetch_type', 'security-events')
    engine_group = params.get('engine_group', 'epp')
    fetch_limit = int(params.get('fetch_limit', 50))

    incidents = []
    current_time = datetime.utcnow().isoformat() + 'Z'

    try:
        if fetch_type in ['security-events', 'both']:
            # Fetch security events
            events_response = client.get_security_events(
                engine_group=engine_group,
                persistence_timestamp_start=last_fetch,
                persistence_timestamp_end=current_time,
                limit=fetch_limit
            )

            for event in events_response.get('items', []):
                incident = {
                    'name': f"WithSecure Security Event - {event.get('engine', 'Unknown')}",
                    'occurred': event.get('persistenceTimestamp'),
                    'severity': convert_severity(event.get('severity')),
                    'rawJSON': json.dumps(event),
                    'type': 'WithSecure Security Event'
                }
                incidents.append(incident)

        if fetch_type in ['incidents', 'both']:
            # Fetch BCDs
            incidents_response = client.get_incidents(
                created_timestamp_start=last_fetch,
                created_timestamp_end=current_time,
                archived=False,
                limit=fetch_limit
            )

            for bcd in incidents_response.get('items', []):
                incident = {
                    'name': f"WithSecure BCD - {bcd.get('name', 'Unknown')}",
                    'occurred': bcd.get('createdTimestamp'),
                    'severity': convert_risk_level(bcd.get('riskLevel')),
                    'rawJSON': json.dumps(bcd),
                    'type': 'WithSecure Incident'
                }
                incidents.append(incident)

    except Exception as e:
        demisto.error(f"Error fetching incidents: {str(e)}")
        return []

    # Update last run
    demisto.setLastRun({'last_fetch': current_time})

    return incidents


def convert_severity(severity: str) -> int:
    """Convert WithSecure severity to XSOAR severity"""
    severity_map = {
        'critical': 4,
        'warning': 3,
        'info': 1
    }
    return severity_map.get(severity.lower(), 2)


def convert_risk_level(risk_level: str) -> int:
    """Convert WithSecure risk level to XSOAR severity"""
    risk_map = {
        'severe': 4,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }
    return risk_map.get(risk_level.lower(), 2)


def main():
    """Main execution function"""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get('url', 'https://api.connect.withsecure.com')
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    scope = params.get('scope', 'connect.api.read connect.api.write')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')

    try:
        client = WithSecureClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            verify=verify,
            proxy=proxy
        )

        commands = {
            'test-module': lambda: test_module(client),
            'withsecure-whoami': lambda: whoami_command(client, args),
            'withsecure-get-security-events': lambda: get_security_events_command(client, args),
            'withsecure-get-incidents': lambda: get_incidents_command(client, args),
            'withsecure-update-incident-status': lambda: update_incident_status_command(client, args),
            'withsecure-add-comment-to-incident': lambda: add_comment_to_incident_command(client, args),
            'withsecure-get-detections': lambda: get_detections_command(client, args),
            'withsecure-get-devices': lambda: get_devices_command(client, args),
            'withsecure-update-device-state': lambda: update_device_state_command(client, args),
            'withsecure-trigger-device-operation': lambda: trigger_device_operation_command(client, args),
            'withsecure-get-device-operations': lambda: get_device_operations_command(client, args),
            'withsecure-get-organizations': lambda: get_organizations_command(client, args),
            'withsecure-get-invitations': lambda: get_invitations_command(client, args),
            'withsecure-create-invitation': lambda: create_invitation_command(client, args),
            'withsecure-delete-invitation': lambda: delete_invitation_command(client, args),
            'withsecure-get-profiles': lambda: get_profiles_command(client, args),
            'fetch-incidents': lambda: fetch_incidents(client, params)
        }

        if command == 'fetch-incidents':
            incidents = commands[command]()
            demisto.incidents(incidents)
        elif command in commands:
            result = commands[command]()
            if isinstance(result, str):
                demisto.results(result)
            else:
                return_results(result)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        demisto.error(f'Failed to execute {command} command. Error: {str(e)}')
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
