import requests
from requests.models import Response
import demistomock as demisto
import Salesforce_IT_Admin as salesforce_it_admin

res = Response()
token_res = Response()
token_res._content = b'{ "access_token" : "123"}'
demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def test_get_user_command(mocker):
    # Positive scenario 1
    inp_args = {"scim": {"id": "12345"}}
    res.status_code = 200
    res._content = b'{ "access_token" : "123", "Id":"12345"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = salesforce_it_admin.get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(get_user).get('id') == '12345'

    # Positive scenario 2
    inp_args = {"scim": {"userName": "TestID@paloaltonetworks.com"}}
    res.status_code = 200
    res._content = b'{ "access_token" : "123", "Id":"12345", "searchRecords":[{"id":"12345"}]}'
    map_scim = {"email": "TestID@paloaltonetworks.com"}

    mocker.patch.object(salesforce_it_admin, 'map_scim', return_value=map_scim)

    _, outputs, _ = salesforce_it_admin.get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(get_user).get('id') == '12345'

    # Negative scenario - User not found
    res.status_code = 400
    res._content = b'[{"Email":"TestID@paloaltonetworks.com", "message": "Mock message"}]'

    _, outputs, _ = salesforce_it_admin.get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 404
    assert outputs.get(get_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    _, outputs, _ = salesforce_it_admin.get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 500
    assert outputs.get(get_user).get('errorMessage') == 'Mock message'


def test_create_user_command(mocker):
    # Positive scenario
    inp_args = {
        "scim": {"emails": [{"type": "work", "primary": True, "value": "TestID@paloaltonetworks.com"}],
                 "urn:scim:schemas:extension:custom:1.0:user": {"Department": "IT"}},
        "customMapping": b'{"Department":"Department"}'}
    res.status_code = 201
    res._content = b'{ "access_token" : "123", "id":"12345", "email":"TestID@paloaltonetworks.com"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = salesforce_it_admin.create_user_command(client, inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('id') == '12345'

    # Negative scenario - Duplicate User
    res.status_code = 400
    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"email":"TestID@paloaltonetworks.com"}]'
    _, outputs, _ = salesforce_it_admin.create_user_command(client, inp_args)

    assert outputs.get(create_user).get('errorCode') == 400
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'


def test_update_user_command(mocker):
    # Positive scenario
    inp_args = {"oldScim": {"id": "TestID@paloaltonetworks.com"},
                "newScim": {"emails": [{"type": "work", "primary": True, "value": "TestID@paloaltonetworks.com"}],
                            "urn:scim:schemas:extension:custom:1.0:user": {"Department": "IT"}},
                "customMapping": b'{"Department":"Department"}'}
    res.status_code = 204
    res._content = b'{ "access_token" : "123", "id":"12345", "email":"TestID@paloaltonetworks.com",' \
                   b' "message": "Mock message"}'

    mocker.patch.object(requests, 'request', return_value=res)

    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = salesforce_it_admin.update_user_command(client, inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"email":"TestID@paloaltonetworks.com", "message": "Mock message"}]'
    _, outputs, _ = salesforce_it_admin.update_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 400
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'

    # Negative scenario - User not found
    res.status_code = 404
    _, outputs, _ = salesforce_it_admin.update_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'


def test_disable_user_command(mocker):
    # Positive scenario
    inp_args = {"scim": {"id": "12345",
                         "urn:scim:schemas:extension:custom:1.0:user": {"Terminate_Date__c": "2020-01-01"}},
                "customMapping": b'{"Terminate_Date__c":"Terminate_Date__c"}'}
    res.status_code = 204
    res._content = b'{ "access_token" : "123", "id":"12345", "email":"TestID@paloaltonetworks.com",' \
                   b' "message": "Mock message"}'

    mocker.patch.object(requests, 'request', return_value=res)

    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='disable-user')

    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    update_user = 'DisableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"email":"TestID@paloaltonetworks.com", "message": "Mock message"}]'
    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 400
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'

    # Negative scenario - User not found
    res.status_code = 404
    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'


def test_enable_user_command(mocker):
    # Positive scenario
    inp_args = {"scim": {"id": "12345",
                         "urn:scim:schemas:extension:custom:1.0:user": {"SOX_Notes__c": "Enabled by XSOAR"}},
                "customMapping": b'{"SOX_Notes__c":"SOX_Notes__c"}'}
    res.status_code = 204
    res._content = b'{ "access_token" : "123", "id":"12345", "email":"TestID@paloaltonetworks.com",' \
                   b' "message": "Mock message"}'

    mocker.patch.object(requests, 'request', return_value=res)

    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='enable-user')

    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    update_user = 'EnableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"email":"TestID@paloaltonetworks.com", "message": "Mock message"}]'
    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 400
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'

    # Negative scenario - User not found
    res.status_code = 404
    _, outputs, _ = salesforce_it_admin.enable_disable_user_command(client, inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'Mock message'


def test_assign_permission_set_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123",
                "permission_set_id": "abc"}
    res.status_code = 201
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-assign-permission-set')

    _, outputs, _ = salesforce_it_admin.assign_permission_set_command(client, inp_args)

    command = 'SalesforceAssignPermissionSet'
    assert outputs.get(command).get('PermissionSetAssign') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.assign_permission_set_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_get_assigned_permission_set_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123"}
    res.status_code = 200
    res._content = b'{"access_token": "123", "records":{"id": "12345"}}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-get-assigned-permission-set')

    _, outputs, _ = salesforce_it_admin.get_assigned_permission_set_command(client, inp_args)

    command = 'SalesforceGetAssignedPermissionSet'
    assert outputs.get(command).get('PermissionSetAssignments') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.get_assigned_permission_set_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_delete_assigned_permission_set_command(mocker):
    # Positive scenario
    inp_args = {"permission_set_assignment_id": "123"}
    res.status_code = 204
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-delete-assigned-permission-set')

    _, outputs, _ = salesforce_it_admin.delete_assigned_permission_set_command(client, inp_args)

    command = 'SalesforceDeleteAssignedPermissionSet'
    assert outputs.get(command).get('success') is True

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.delete_assigned_permission_set_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_assign_permission_set_license_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123",
                "permission_set_license_id": "abc"}
    res.status_code = 201
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-assign-permission-set-license')

    _, outputs, _ = salesforce_it_admin.assign_permission_set_license_command(client, inp_args)

    command = 'SalesforceAssignPermissionSetLicense'
    assert outputs.get(command).get('PermissionSetLicenseAssign') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.assign_permission_set_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_get_assigned_permission_set_license_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123"}
    res.status_code = 200
    res._content = b'{"access_token": "123", "records":{"id": "12345"}}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-get-assigned-permission-set-license')

    _, outputs, _ = salesforce_it_admin.get_assigned_permission_set_license_command(client, inp_args)

    command = 'SalesforceGetAssignedPermissionSetLicense'
    assert outputs.get(command).get('PermissionSetLicenseAssignments') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.get_assigned_permission_set_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_delete_assigned_permission_set_license_command(mocker):
    # Positive scenario
    inp_args = {"permission_set_assignment_license_id": "123"}
    res.status_code = 204
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-delete-assigned-permission-set-license')

    _, outputs, _ = salesforce_it_admin.delete_assigned_permission_set_license_command(client, inp_args)

    command = 'SalesforceDeleteAssignedPermissionSetLicense'
    assert outputs.get(command).get('success') is True

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.delete_assigned_permission_set_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_assign_package_license_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123",
                "package_license_id": "abc"}
    res.status_code = 201
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-assign-package-license')

    _, outputs, _ = salesforce_it_admin.assign_package_license_command(client, inp_args)

    command = 'SalesforceAssignPackageLicense'
    assert outputs.get(command).get('PackageLicenseAssign') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.assign_package_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_get_assigned_package_license_command(mocker):
    # Positive scenario
    inp_args = {"user_id": "123"}
    res.status_code = 200
    res._content = b'{"access_token": "123", "records":{"id": "12345"}}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-get-assigned-package-license')

    _, outputs, _ = salesforce_it_admin.get_assigned_package_license_command(client, inp_args)

    command = 'SalesforceGetAssignedPackageLicense'
    assert outputs.get(command).get('PackageLicenseAssignments') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.get_assigned_package_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_delete_assigned_package_license_command(mocker):
    # Positive scenario
    inp_args = {"user_package_license_id": "123"}
    res.status_code = 204
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-delete-assigned-package-license')

    _, outputs, _ = salesforce_it_admin.delete_assigned_package_license_command(client, inp_args)

    command = 'SalesforceDeleteAssignedPackageLicense'
    assert outputs.get(command).get('success') is True

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.delete_assigned_package_license_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_unfreeze_user_account(mocker):
    # Positive scenario
    inp_args = {"user_login_id": "123"}
    res.status_code = 204
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-unfreeze-user-account')

    _, outputs, _ = salesforce_it_admin.freeze_unfreeze_user_account_command(client, inp_args)

    command = 'SalesforceUnfreezeUserAccount'
    assert outputs.get(command).get('success') is True

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.freeze_unfreeze_user_account_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_freeze_user_account(mocker):
    # Positive scenario
    inp_args = {"user_login_id": "123"}
    res.status_code = 204
    res._content = b'{"access_token": "123", "id": "12345"}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-freeze-user-account')

    _, outputs, _ = salesforce_it_admin.freeze_unfreeze_user_account_command(client, inp_args)

    command = 'SalesforceFreezeUserAccount'
    assert outputs.get(command).get('success') is True

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.freeze_unfreeze_user_account_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'


def test_get_user_isfrozen_status_command(mocker):
    # Positive scenario
    inp_args = {"user_package_license_id": "123"}
    res.status_code = 200
    res._content = b'{"access_token": "123", "records":{"id": "12345"}}'

    mocker.patch.object(requests, 'request', return_value=res)
    client = salesforce_it_admin.Client(base_url='https://test.com', verify=False, conn_client_id='123',
                                        conn_client_secret='abc', conn_username='test', conn_password='test',
                                        headers={})

    mocker.patch.object(demisto, 'command', return_value='salesforce-get-frozen-user-account-id')

    _, outputs, _ = salesforce_it_admin.get_user_isfrozen_status_command(client, inp_args)

    command = 'SalesforceGetUserIsfrozenStatus'
    assert outputs.get(command).get('UserIsfrozenStatus') == {"id": "12345"}

    # Negative scenario
    res.status_code = 400
    mocker.patch.object(client, 'create_login', return_value=token_res)
    res._content = b'[{"message":"Mock Response"}]'
    _, outputs, _ = salesforce_it_admin.get_user_isfrozen_status_command(client, inp_args)

    assert outputs.get(command).get('errorMessage') == 'Mock Response'
