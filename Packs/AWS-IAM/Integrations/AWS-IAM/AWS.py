''' IMPORTS '''
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SCIM_EXTENSION_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
USER_NOT_FOUND = "User not found"
userUri = '/scim/v2/Users/'
groupUri = '/scim/v2/Groups/'
'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the aws API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, version, verify=True, proxy=False, headers=None, auth=None):
        self.base_url = base_url
        self.verify = verify
        self.version = version
        self.headers = headers
        self.auth = auth
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            headers=self.headers
        )
        return res

    def get_user(self, data):
        uri = '/' + userUri
        params = {
            'filter': data
        }
        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params

        )

    def create_user(self, data):
        uri = '/' + userUri

        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data

        )

    def update_user(self, data, user_id):
        uri = '/' + userUri + user_id

        return self.http_request(
            method='PATCH',
            url_suffix=uri,
            data=data

        )

    def search_group(self, group_name):
        uri = '/' + groupUri
        params = {
            'filter': f'displayName eq "{group_name}"'
        }
        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=params
        )

    def get_group_by_id(self, group_id):
        uri = '/' + groupUri + group_id
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def create_group(self, data):
        uri = '/' + groupUri
        return self.http_request(
            method="POST",
            url_suffix=uri,
            data=data
        )

    def update_group(self, group_id, data):

        uri = '/' + groupUri + group_id
        return self.http_request(
            method="PATCH",
            url_suffix=uri,
            data=data
        )

    def delete_group(self, group_id):
        uri = '/' + groupUri + group_id
        return self.http_request(
            method="DELETE",
            url_suffix=uri
        )

    def build_aws_user_profile(self, args, scim, custom_mapping):

        aws_user = {

        }

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get('urn:scim:schemas:extension:custom:1.0:user')
        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                if extension_schema.get(key):
                    aws_user[value] = extension_schema.get(key)

        return aws_user

    def update_aws_user_profile(self, args, scim, custom_mapping):
        parsed_scim_data = map_scim(scim)

        aws_user = {
            "userName": parsed_scim_data.get('userName'),
            "externalId": parsed_scim_data.get('externalId'),
            "displayName": parsed_scim_data.get('displayName'),
            "profileUrl": parsed_scim_data.get('profileUrl'),
            "userType": parsed_scim_data.get('userType'),
            "preferredLanguage": parsed_scim_data.get('preferredLanguage'),
            "locale": parsed_scim_data.get('locale'),
            "timezone": parsed_scim_data.get('timezone'),
            "name.givenName": parsed_scim_data.get('first_name'),
            "name.familyName": parsed_scim_data.get('last_name'),
            "name.formatted": parsed_scim_data.get('nameFormatted'),
            "name.middleName": parsed_scim_data.get('middleName'),
            "name.honorificPrefix": parsed_scim_data.get('honorificPrefix'),
            "name.honorificSuffix": parsed_scim_data.get('honorificSuffix'),
            "emails.value": parsed_scim_data.get('email'),
            "title": parsed_scim_data.get('title'),
            "addresses.locality": parsed_scim_data.get('city')[0] if (parsed_scim_data.get('city')) else None,
            "phoneNumbers.value": parsed_scim_data.get('phone_work')[0] if (
                parsed_scim_data.get('phone_work')) else None,
            "addresses.region": parsed_scim_data.get('state')[0] if (parsed_scim_data.get('state')) else None,
            "addresses.streetAddress": parsed_scim_data.get('address_one')[0] if (
                parsed_scim_data.get('address_one')) else None,
            "addresses.postalCode": parsed_scim_data.get('zip')[0] if (parsed_scim_data.get('zip')) else None,
            "addresses.country": parsed_scim_data.get('country')[0] if (parsed_scim_data.get('country')) else None,
            "addresses.formatted": parsed_scim_data.get('formatted')[0] if (parsed_scim_data.get('formatted')) else None
        }

        if args.get('customMapping'):
            custom_mapping = json.loads(args.get('customMapping'))
        elif custom_mapping:
            custom_mapping = json.loads(custom_mapping)

        extension_schema = scim.get('urn:scim:schemas:extension:custom:1.0:user')

        if custom_mapping and extension_schema:
            for key, value in custom_mapping.items():
                # key is the attribute name in input scim. value is the attribute name of app profile
                if extension_schema.get(key):
                    aws_user[SCIM_EXTENSION_SCHEMA + "." + value] = extension_schema.get(key)

        return aws_user


class OutputContext:
    """
        Class to build a generic output and context.
    """

    def __init__(self, success=None, active=None, id=None, iden=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None, displayName=None, members=None):
        self.instanceName = demisto.callingContext['context']['IntegrationInstance']
        self.brand = demisto.callingContext['context']['IntegrationBrand']
        self.command = demisto.command().replace('-', '_').title().replace('_', '')
        self.success = success
        self.active = active
        self.id = id
        self.iden = iden
        self.username = username
        self.email = email
        self.errorCode = errorCode
        self.errorMessage = errorMessage
        self.details = details
        self.displayName = displayName  # Used in group
        self.members = members  # Used in group
        self.data = {
            "brand": self.brand,
            "instanceName": self.instanceName,
            "success": success,
            "active": active,
            "id": iden,
            "username": username,
            "email": email,
            "errorCode": errorCode,
            "errorMessage": errorMessage,
            "details": details,
            "displayName": displayName,
            "members": members
        }


'''HELPER FUNCTIONS'''


def verify_and_load_scim_data(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception("SCIM data is not a valid JSON")
    return scim


def map_scim(scim):
    try:
        scim = json.loads(scim)
    except Exception:
        pass
    if type(scim) != dict:
        raise Exception('Provided client data is not JSON compatible')
    mapping = {
        "userName": "userName",
        "displayName": "displayName",
        "externalId": "externalId",
        "email": "emails(val.primary && val.primary==true).[0].value",
        "first_name": "name.givenName",
        "last_name": "name.familyName",
        "nameFormatted": "name.formatted",
        "middleName": "name.middleName",
        "honorificPrefix": "name.honorificPrefix",
        "honorificSuffix": "name.honorificSuffix",
        "active": "active",
        "id": "id",
        "preferredLanguage": "preferredLanguage",
        "locale": "locale",
        "timezone": "timezone",
        "profileUrl": "profileUrl",
        "address_one": "addresses(val.primary && val.primary==true).streetAddress",
        "address_two": "addresses( !val.primary ).formatted",
        "city": "addresses(val.primary && val.primary==true).locality",
        "country": "addresses(val.primary && val.primary==true).country",
        "phone_home": "phoneNumbers(val.type && val.type=='home').value",
        "phone_mobile": "phoneNumbers(val.type && val.type=='mobile').value",
        "phone_work": "phoneNumbers(val.type && val.type=='work').value",
        "state": "addresses(val.primary && val.primary==true).region",
        "formatted": "addresses(val.primary && val.primary==true).formatted",
        'title': "title",
        "zip": "addresses(val.primary && val.primary==true).postalCode",
    }

    parsed_scim = dict()
    for k, v in mapping.items():
        try:
            parsed_scim[k] = demisto.dt(scim, v)
        except Exception:
            parsed_scim[k] = None
    return parsed_scim


'''COMMAND FUNCTIONS'''


def test_module(client, args):
    uri = '/' + userUri
    params = {
        "version": client.version
    }
    res = client.http_request('get', uri, params=params)

    if res.status_code == 200:
        demisto.results('ok')
    else:
        return_error('Error testing [%d] - %s' % (res.status_code, res.text))


def get_user_command(client, args):
    """
        Returning user GET details and status of response.

        Args:   demisto command line argument
        client: AWS client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCode, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim_data = map_scim(scim)
    user_id = parsed_scim_data.get('id')
    username = parsed_scim_data.get('userName')
    email = parsed_scim_data.get('email')

    if not (user_id or username or email):
        raise Exception('You must provide either the id or the username of the user')

    if user_id:
        data = f'id eq "{user_id}"'
        res = client.get_user(data)
    elif email:
        data = f'userName eq "{email}"'
        res = client.get_user(data)
    else:
        data = f'userName eq "{username}"'
        res = client.get_user(data)

    res_json = res.json()
    generic_iam_context_data_list = []
    if res.status_code == 200:
        result = res_json
        if result['totalResults'] > 0:

            generic_iam_context = OutputContext(success=True,
                                                iden=result['Resources'][0]['id'] if result['Resources'][0][
                                                    'id'] else None,
                                                email=result['Resources'][0]['emails'][0]['value'] if
                                                result['Resources'][0]['emails'][0]['value']
                                                else None,
                                                username=result['Resources'][0]['userName'] if result['Resources'][0][
                                                    'userName'] else None, details=result,
                                                active=result['Resources'][0]['active'])

            generic_iam_context_data_list.append(generic_iam_context.data)
        else:
            generic_iam_context = OutputContext(success=False, iden=user_id, username=None, errorCode=404,
                                                email=None,
                                                errorMessage=USER_NOT_FOUND)
            generic_iam_context_data_list.append(generic_iam_context.data)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, username=None, email=None,
                                            errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)
        generic_iam_context_data_list.append(generic_iam_context.data)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context_data_list
    }
    readable_output = tableToMarkdown(name='Get AWS User:',
                                      t=generic_iam_context_data_list,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context_data_list
    )


def create_user_command(client, args):
    """
        Create user using POST to AWS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: AWS Client

        Returns:
            success : success=True, id, email, login as username, details, active status
            fail : success=False, id, login as username, errorCod, errorMessage, details
    """

    scim = verify_and_load_scim_data(args.get('scim'))
    custom_mapping = demisto.params().get('customMappingCreateUser')
    custom_aws_user = client.build_aws_user_profile(args, scim, custom_mapping)

    if not scim["emails"][0]['value']:
        raise Exception('You must provide a value for the email.')

    scim['userName'] = scim["emails"][0]['value']
    # Removes variables that don't contain any data.
    if scim:
        delete = []
        for key, val in scim.items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim[i]
    # Removes address variables that don't contain any data.
    if 'addresses' in scim:
        delete = []
        for key, val in scim['addresses'][0].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim['addresses'][0][i]
    # Removes name variables that don't contain any data.
    if 'name' in scim:
        delete = []
        for key, val in scim['name'].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim['name'][i]

    if 'phoneNumbers' in scim:
        for i in range(len(scim['phoneNumbers'])):
            if scim['phoneNumbers'][i]['type'] is not 'work':
                del scim['phoneNumbers'][i]
                break

    if 'title' in scim:
        if ':' in scim['title']:
            scim['title'] = scim['title'].replace(":", " ")

    if custom_aws_user:
        del scim['urn:scim:schemas:extension:custom:1.0:user']
        scim[SCIM_EXTENSION_SCHEMA] = custom_aws_user

        if 'manager' in scim[SCIM_EXTENSION_SCHEMA]:

            scim[SCIM_EXTENSION_SCHEMA]['manager'] = {"value": scim[SCIM_EXTENSION_SCHEMA]['manager']}

        else:
            scim[SCIM_EXTENSION_SCHEMA]['manager'] = {"value": "Empty"}

    res = client.create_user(scim)
    res_json = res.json()

    if res.status_code == 201:

        # property_value_map = res_json.get('property_value_map')
        active = res_json.get('active')
        user_id = res_json.get('id')
        email = res_json['emails'][0]['value'] if res_json['emails'][0]['value'] else None
        username = res_json.get('userName')

        generic_iam_context = OutputContext(success=True, iden=user_id, email=email,
                                            username=username, details=scim, active=active)
    else:
        generic_iam_context = OutputContext(success=False, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Create AWS User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_user_command(client, args):
    """
        Update user using PUT to AWS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: AWS Client

        Returns:
            success : success=True, id, details
            fail : success=False, id, errorCod, errorMessage, details
    """
    old_scim = verify_and_load_scim_data(args.get('oldScim'))
    new_scim = verify_and_load_scim_data(args.get('newScim'))
    custom_mapping = demisto.params().get('customMappingUpdateUser')

    parsed_old_scim = map_scim(old_scim)
    user_id = parsed_old_scim.get('id')

    if not user_id:
        raise Exception('You must provide id of the user')

    # Removes variables that don't contain any data.
    if new_scim:
        delete = []
        for key, val in new_scim.items():
            if val == '':
                delete.append(key)

        for i in delete:
            del new_scim[i]
        # Removes address variables that don't contain any data.
    if 'addresses' in new_scim:
        delete = []
        for key, val in new_scim['addresses'][0].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del new_scim['addresses'][0][i]

    # Removes name variables that don't contain any data.
    if 'name' in new_scim:
        delete = []
        for key, val in new_scim['name'].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del new_scim['name'][i]

    if 'title' in new_scim:
        if ':' in new_scim['title']:
            new_scim['title'] = new_scim['title'].replace(":", " ")

    aws_user = client.update_aws_user_profile(args, new_scim, custom_mapping)

    new_aws_user = {
        "schemas": [
            patchSchema
        ], "Operations": []}
    for key, value in aws_user.items():
        if not (value is None):
            operation = {
                "op": "add",
                "path": key,
                "value": value
            }
            new_aws_user["Operations"].append(operation)

    res = client.update_user(new_aws_user, user_id)
    res_json = res.json()
    data = f'id eq "{user_id}"'
    res1 = client.get_user(data)
    res_json1 = res1.json()
    if res.status_code == 200:
        result = res_json

        generic_iam_context = OutputContext(success=True, iden=user_id, email=None,
                                            username=None, details=result, active=res_json1['Resources'][0]['active'])
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json,
                                            active=True)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Update AWS User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",

                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def disable_user_command(client, args):
    """
        Disable user using PATCH to AWS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: AWS Client

        Returns:
            success : success=True, id, details, active status
            fail : success=False, id, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    parsed_scim_data = map_scim(scim)
    user_id = parsed_scim_data.get('id')

    if not user_id:
        raise Exception('You must provide sys id of the user')
    new_aws_user = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ], "Operations": []}

    operation = {
        "op": "add",
        "path": "active",
        "value": False
    }
    new_aws_user["Operations"].append(operation)

    res = client.update_user(new_aws_user, user_id)
    res_json = res.json()

    if res.status_code == 200:
        result = res_json
        active = False

        generic_iam_context = OutputContext(success=True, iden=user_id, email=None,
                                            username=None, details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Disable AWS User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def enable_user_command(client, args):
    """
        Enable user using PUT to AWS API , if Connection to the service is successful.

        Args:   demisto command line argument
        client: AWS Client

        Returns:
            success : success=True, id, details, active status
            fail : success=False, id, errorCod, errorMessage, details
    """
    scim = verify_and_load_scim_data(args.get('scim'))
    custom_mapping = demisto.params().get('customMappingUpdateUser')
    parsed_scim = map_scim(scim)
    user_id = parsed_scim.get('id')

    if not user_id:
        raise Exception('You must provide id of the user')
    # Removes variables that don't contain any data.
    if scim:
        delete = []
        for key, val in scim.items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim[i]
    # Removes address variables that don't contain any data.
    if 'addresses' in scim:
        delete = []
        for key, val in scim['addresses'][0].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim['addresses'][0][i]

    # Removes name variables that don't contain any data.
    if 'name' in scim:
        delete = []
        for key, val in scim['name'].items():
            if val == '':
                delete.append(key)

        for i in delete:
            del scim['name'][i]

    aws_user = client.update_aws_user_profile(args, scim, custom_mapping)

    new_aws_user = {
        "schemas": [
            patchSchema
        ], "Operations": []}
    for key, value in aws_user.items():
        if not (value is None):
            operation = {
                "op": "add",
                "path": key,
                "value": value
            }
            new_aws_user["Operations"].append(operation)
    usertoTrue = {
        "op": "add",
        "path": "active",
        "value": True
    }
    new_aws_user["Operations"].append(usertoTrue)
    res = client.update_user(new_aws_user, user_id)
    res_json = res.json()
    if res.status_code == 200:
        result = res_json
        active = True

        generic_iam_context = OutputContext(success=True, iden=user_id,
                                            email=result['emails'][0]['value'] if result['emails'][0][
                                                'value'] else None,
                                            username=result.get('userName'), details=result, active=active)
    else:
        generic_iam_context = OutputContext(success=False, iden=user_id, errorCode=res.status_code,
                                            errorMessage=res_json.get('error', {}).get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }
    readable_output = tableToMarkdown('Enable AWS User:', t=generic_iam_context.data,
                                      headers=["brand", "instanceName", "success", "active", "id", "username", "email",
                                               "errorCode", "errorMessage", "details"],
                                      removeNull=True
                                      )
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def get_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')
    if not (group_id or group_name):
        return_error("You must supply either 'id' or 'displayName' in the scim data")
    if not group_id:
        res = client.search_group(group_name)
        res_json = res.json()

        if res.status_code == 200:
            if res_json.get('totalResults') < 1:
                generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=404,
                                                    errorMessage="Group Not Found", details=res_json)
                generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
                outputs = {
                    generic_iam_context_dt: generic_iam_context.data
                }

                readable_output = tableToMarkdown(f'AWS Get Group:', generic_iam_context.data, removeNull=True)
                return (
                    readable_output,
                    outputs,
                    generic_iam_context.data
                )
            else:
                group_id = res_json['Resources'][0].get('id')
                group_name = res_json['Resources'][0].get('displayName')
                generic_iam_context = OutputContext(success=True, iden=group_id,
                                                    displayName=group_name, details=res_json)
                readable_output = tableToMarkdown(f'AWS Get Group:', generic_iam_context.data, removeNull=True)
                generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
                outputs = {
                    generic_iam_context_dt: generic_iam_context.data
                }
                return (
                    readable_output,
                    outputs,
                    generic_iam_context.data
                )
        else:
            generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id,
                                                errorCode=res_json.get('code'),
                                                errorMessage=res_json.get('message'), details=res_json)
            generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
            outputs = {
                generic_iam_context_dt: generic_iam_context.data
            }

            readable_output = tableToMarkdown(f'AWS Get Group:', generic_iam_context.data, removeNull=True)
            return (
                readable_output,
                outputs,
                generic_iam_context.data
            )

    res = client.get_group_by_id(group_id)
    res_json = res.json()

    if res.status_code == 200:
        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'),
                                            displayName=res_json.get('displayName'), details=res_json)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id, errorCode=404,
                                            errorMessage="Group Not Found", details=res_json)
    else:
        generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'AWS Get Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def create_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    group_name = scim.get('displayName')

    if not group_name:
        return_error("You must supply 'displayName' of the group in the scim data")

    res = client.create_group(scim)
    res_json = res.json()

    if res.status_code == 201:

        generic_iam_context = OutputContext(success=True, iden=res_json.get('id'),
                                            displayName=res_json.get('displayName'), details=res_json)
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'AWS Create Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def update_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))

    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        return_error("You must supply 'id' in the scim data")

    member_ids_to_add = args.get('memberIdsToAdd')
    member_ids_to_delete = args.get('memberIdsToDelete')

    if member_ids_to_add:
        if type(member_ids_to_add) is not list:
            member_ids_to_add = json.loads(member_ids_to_add)

        for member_id in member_ids_to_add:
            operation = {
                "op": "add",
                "path": "members",
                "value": [{"value": member_id}]
            }
            group_input = {}
            group_input['schemas'] = [patchSchema]
            group_input['Operations'] = [operation]
            res = client.update_group(group_id, group_input)
            if res.status_code is not 204:
                res_json = res.json()
                generic_iam_context = OutputContext(success=False, displayName=group_name, iden=member_id,
                                                    errorCode=res_json.get('code'),
                                                    errorMessage=res_json.get('message'), details=res_json)

                generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
                outputs = {
                    generic_iam_context_dt: generic_iam_context.data
                }

                readable_output = tableToMarkdown(f'AWS Update Group:', generic_iam_context.data, removeNull=True)
                return (
                    readable_output,
                    outputs,
                    generic_iam_context.data
                )
    if member_ids_to_delete:
        if type(member_ids_to_delete) is not list:
            member_ids_to_delete = json.loads(member_ids_to_delete)
        for member_id in member_ids_to_delete:
            operation = {
                "op": "remove",
                "path": "members",
                "value": [{"value": member_id}]
            }
            group_input = {}
            group_input['schemas'] = [patchSchema]
            group_input['Operations'] = [operation]
            res = client.update_group(group_id, group_input)
            if res.status_code is not 204:
                res_json = res.json()
                generic_iam_context = OutputContext(success=False, displayName=group_name, iden=member_id,
                                                    errorCode=res_json.get('code'),
                                                    errorMessage=res_json.get('message'), details=res_json)

                generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
                outputs = {
                    generic_iam_context_dt: generic_iam_context.data
                }

                readable_output = tableToMarkdown(f'AWS Update Group:', generic_iam_context.data, removeNull=True)
                return (
                    readable_output,
                    outputs,
                    generic_iam_context.data
                )
    if res.status_code == 204:
        res_json = res.headers
        generic_iam_context = OutputContext(success=True, iden=group_id, displayName=group_name, details=str(res_json))
    elif res.status_code == 404:

        generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name, errorCode=404,
                                            errorMessage="Group/User Not Found or User not a member of group",
                                            details=res.json())
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'AWS Update Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def delete_group_command(client, args):
    scim = verify_and_load_scim_data(args.get('scim'))
    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not group_id:
        return_error("The group id needs to be provided.")

    res = client.delete_group(group_id)
    if res.status_code == 204:
        res_json = res.headers
        generic_iam_context = OutputContext(success=True, iden=group_id, displayName=group_name, details=str(res_json))
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, iden=group_id, displayName=group_name, errorCode=404,
                                            errorMessage="Group Not Found", details=res.json())
    else:
        res_json = res.json()
        generic_iam_context = OutputContext(success=False, displayName=group_name, iden=group_id,
                                            errorCode=res_json.get('code'),
                                            errorMessage=res_json.get('message'), details=res_json)

    generic_iam_context_dt = f'{generic_iam_context.command}(val.id == obj.id && val.instanceName == obj.instanceName)'
    outputs = {
        generic_iam_context_dt: generic_iam_context.data
    }

    readable_output = tableToMarkdown(f'AWS Delete Group:', generic_iam_context.data, removeNull=True)
    return (
        readable_output,
        outputs,
        generic_iam_context.data
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    api_version = params.get('api_version', None)

    # get the aws API url
    base_url = urljoin(params.get('url').strip('/'))
    tenant_id = params.get('tenant_id')
    url_with_tenant = base_url + '/' + tenant_id
    authentication_token = params.get('authentication_token')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'disable-user': disable_user_command,
        'enable-user': enable_user_command,
        'get-group': get_group_command,
        'create-group': create_group_command,
        'update-group': update_group_command,
        'delete-group': delete_group_command
    }

    client = Client(
        base_url=url_with_tenant,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + authentication_token

        },
        version=api_version,
        proxy=proxy)

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
