
import importlib
import demistomock as demisto

AWSIAMIdentityCenter = importlib.import_module("AWSIAMIdentityCenter")

RESPONSE_GROUP_ID = {'GroupId': 'GROUP_ID'}

RESPONSE_USER_ID = {'UserId': 'USER_ID'}

RESPONSE_DELETE = {'ResponseMetadata': {'HTTPStatusCode': 200}}


class Boto3Client:
    def create_user(self):
        pass

    def create_group(self):
        pass

    def list_users(self):
        pass

    def list_groups(self):
        pass

    def describe_user(self):
        pass

    def describe_group(self):
        pass

    def create_group_membership(self):
        pass

    def list_group_memberships_for_member(self):
        pass

    def delete_group_membership(self):
        pass

    def delete_user(self):
        pass

    def delete_group(self):
        pass

    def list_group_memberships(self):
        pass


def test_create_user(mocker):
    """
    Given:
        Arguments for creating a user

    When:
        Creating a user using the create-user command

    Then:
        Verify that the user is created with the correct arguments
    """

    args = {
        'IdentityStoreId': '123456',
        'userName': 'test_user',
        'familyName': 'Doe',
        'givenName': 'John',
        'userEmailAddress': 'john.doe@example.com',
        'displayName': 'John Doe',
        'userEmailAddressPrimary': True
    }
    res = {
        'UserId': 'USER_ID',
        'IdentityStoreId': '123456',
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import create_user
    mocker.patch.object(Boto3Client, "create_user", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    create_user(args, client)
    contents = demisto.results.call_args[0][0]
    assert {'UserId': 'USER_ID', 'IdentityStoreId': '123456'} in contents.get(
        'EntryContext').values()
    assert 'User USER_ID has been successfully created' in contents.get('HumanReadable')


def test_create_group(mocker):
    """
    Given:
        Arguments for creating a group

    When:
        Creating a group using the create-group command

    Then:
        Verify that the group is created with the correct arguments
    """
    args = {
        'displayName': 'Test Group',
        'description': 'Test Description'
    }
    res = {
        'GroupId': '123456',
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import create_group
    mocker.patch.object(Boto3Client, "create_group", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    create_group(args, client)
    contents = demisto.results.call_args[0][0]
    assert {'GroupId': '123456'} in contents.get(
        'EntryContext').values()
    assert 'Group 123456 has been successfully created' in contents.get('HumanReadable')


def test_list_users(mocker):
    """
    Given:
        Arguments for listing users

    When:
        Listing users using the list-users command

    Then:
        Verify that the correct users are listed with the correct details
    """
    args = {
        'IdentityStoreId': '123456',
        'limit': 1,
        'nextToken': 'TOKEN'
    }

    res = {
        'IdentityStoreId': '123456',
        'Users': [
            {
                'UserId': 'USER_ID',
                'UserName': 'test_user',
                'DisplayName': 'Test User',
                'Emails': [{'Value': 'test@example.com'}]
            }
        ],
        'NextToken': 'NEXT_TOKEN'
    }

    from AWSIAMIdentityCenter import list_users
    mocker.patch.object(Boto3Client, "list_users", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    list_users(args, client)
    contents = demisto.results.call_args[0][0]
    assert 'AWS IAM Identity Center Users' in contents.get('HumanReadable')
    assert [{'UserId': 'USER_ID', 'UserName': 'test_user', 'DisplayName': 'Test User', 'Emails': [{'Value': 'test@example.com'}]}] in contents.get(
        'EntryContext').values()
    assert {'UserNextToken': 'NEXT_TOKEN'} in contents.get(
        'EntryContext').values()


def test_list_groups(mocker):
    """
    Given:
        Arguments for listing groups

    When:
        Listing groups using the list-groups command

    Then:
        Verify that the correct groups are listed with the correct details
    """
    args = {}

    res = {
        'Groups': [
            {
                'GroupId': '123',
                'DisplayName': 'Test Group',
                'Description': 'Test Description'
            }
        ],
        'NextToken': None
    }

    from AWSIAMIdentityCenter import list_groups
    mocker.patch.object(Boto3Client, "list_groups", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    list_groups(args, client)
    contents = demisto.results.call_args[0][0]
    assert 'AWS IAM Identity Center Groups' in contents.get('HumanReadable')
    assert [{'GroupId': '123', 'DisplayName': 'Test Group', 'Description': 'Test Description'}] in contents.get(
        'EntryContext').values()
    assert {'GroupNextToken': None} in contents.get(
        'EntryContext').values()


def test_get_user(mocker):
    """
    Given:
        User Name

    When:
        Getting a user using the get-user command

    Then:
        Verify that the correct user is retrieved with the correct details
    """
    args = {
        'userName': 'test_user'
    }

    response_id = {'UserId': 'USER_ID'}

    res = {
        'UserId': 'USER_ID',
        'UserName': 'test_user',
        'DisplayName': 'Test User',
        'Emails': [{'Value': 'test@example.com'}],
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import get_user
    mocker.patch.object(AWSIAMIdentityCenter, "get_userId_by_username", return_value=response_id)
    mocker.patch.object(Boto3Client, "describe_user", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    get_user(args, client)
    contents = demisto.results.call_args[0][0]

    assert {'UserId': 'USER_ID', 'UserName': 'test_user', 'DisplayName': 'Test User', 'Emails': [{'Value': 'test@example.com'}]} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Users' in contents.get('HumanReadable')


def test_get_user_by_email(mocker):
    """
    Given:
        Email address

    When:
        Getting a user using the get-user-by-email command

    Then:
        Verify that the correct user is retrieved with the correct details
    """

    args = {
        'emailAddress': 'test@example.com'
    }

    res = {
        'Users': [
            {
                'UserId': 'USER_ID',
                'UserName': 'test_user',
                'DisplayName': 'Test User',
                'Name': {
                    'FamilyName': 'User',
                    'GivenName': 'Test',
                },
                'Emails': [
                    {'Value': 'test@example.com',
                     'Type': 'work',
                     'Primary': True}
                ],
            }
        ],
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import get_user_by_email
    mocker.patch.object(Boto3Client, "list_users", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    get_user_by_email(args, client)
    contents = demisto.results.call_args[0][0]

    assert {'UserId': 'USER_ID', 'UserName': 'test_user', 'DisplayName': 'Test User', 'Name': {'FamilyName': 'User', 'GivenName': 'Test'}, 'Emails': [{'Value': 'test@example.com', 'Type': 'work', 'Primary': True}]} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Users' in contents.get('HumanReadable')


def test_get_group(mocker):
    """
    Given:
        Arguments for getting a group

    When:
        Getting a group using the get-group command

    Then:
        Verify that the correct group is retrieved with the correct details
    """
    args = {
        'displayName': 'test_group'
    }

    response_id = {'GroupId': '123456'}

    res = {
        'GroupId': 'string',
        'DisplayName': 'test_group',
        'Description': None,
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import get_group
    mocker.patch.object(AWSIAMIdentityCenter, "get_groupId_by_displayName", return_value=response_id)
    mocker.patch.object(Boto3Client, "describe_group", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    get_group(args, client)
    contents = demisto.results.call_args[0][0]

    assert {'GroupId': 'string', 'DisplayName': 'test_group', 'Description': None} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Groups' in contents.get('HumanReadable')


def test_add_user_to_group(mocker):
    """
    Given:
        Arguments for adding a user to a group

    When:
        Adding a user to a group using the add-user-to-group command

    Then:
        Verify that the user is added to the group
    """
    args = {
        'userName': 'test_user',
        'displayName': 'test_group'
    }

    res = {
        'MembershipId': '10203040',
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }

    from AWSIAMIdentityCenter import add_user_to_group
    mocker.patch.object(AWSIAMIdentityCenter, "get_userId_by_username", return_value=RESPONSE_USER_ID)
    mocker.patch.object(AWSIAMIdentityCenter, "get_groupId_by_displayName", return_value=RESPONSE_GROUP_ID)
    mocker.patch.object(Boto3Client, "create_group_membership", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    add_user_to_group(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'The membership id 10203040 has been successfully created.' in contents.get('HumanReadable')


def test_list_groups_for_user(mocker):
    """
    Given:
        Arguments for listing groups for a user

    When:
        Listing groups for a user using the list-groups-for-user command

    Then:
        Verify that the correct groups are listed for the user with the correct details
    """
    args = {
        'userName': 'test_user'
    }

    res = {
        'GroupMemberships': [
            {
                'MemberId': {'UserId': 'USER_ID'},
                'GroupId': 'GROUP_ID',
                'MembershipId': 'MEMBERSHIP_ID'
            }
        ],
        'NextToken': None
    }

    from AWSIAMIdentityCenter import list_groups_for_user
    mocker.patch.object(AWSIAMIdentityCenter, "get_userId_by_username", return_value=RESPONSE_USER_ID)
    mocker.patch.object(Boto3Client, "list_group_memberships_for_member", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    list_groups_for_user(args, client)
    contents = demisto.results.call_args[0][0]

    assert {'GroupMemberships': [{'GroupId': 'GROUP_ID', 'MembershipId': 'MEMBERSHIP_ID'}], 'UserId': 'USER_ID'} in contents.get(
        'EntryContext').values()
    assert {'GroupsUserNextToken': None} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Groups' in contents.get('HumanReadable')


def test_delete_group_membership(mocker):  # add more inputs! empty memberships and membershipId
    """
    Given:
        Arguments for deleting a group membership

    When:
        Deleting a group membership using the delete-group-membership command

    Then:
        Verify that the correct group membership is deleted
    """
    args = {
        'userName': 'test_user'
    }

    res = {
        'GroupMemberships': [
            {
                'MemberId': {'UserId': 'USER_ID'},
                'GroupId': 'GROUP_ID',
                'MembershipId': 'MEMBERSHIP_ID'
            },
            {
                'MemberId': {'UserId': 'USER_ID'},
                'GroupId': 'GROUP_ID2',
                'MembershipId': 'MEMBERSHIP_ID123'
            }
        ],
        'NextToken': None
    }

    from AWSIAMIdentityCenter import delete_group_membership
    mocker.patch.object(AWSIAMIdentityCenter, "get_userId_by_username", return_value=RESPONSE_USER_ID)
    mocker.patch.object(Boto3Client, "list_group_memberships_for_member", return_value=res)
    mocker.patch.object(Boto3Client, "delete_group_membership", return_value=RESPONSE_DELETE)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    delete_group_membership(args, client)
    contents = demisto.results.call_args[0][0]

    assert "The membership with ids ['MEMBERSHIP_ID', 'MEMBERSHIP_ID123'] have been deleted." in contents.get('HumanReadable')


def test_delete_user(mocker):
    """
    Given:
        Arguments for deleting a user

    When:
        Deleting a user using the delete-user command

    Then:
        Verify that the correct user is deleted
    """
    args = {
        'userName': 'test_user'
    }

    from AWSIAMIdentityCenter import delete_user
    mocker.patch.object(AWSIAMIdentityCenter, "get_userId_by_username", return_value=RESPONSE_USER_ID)
    mocker.patch.object(Boto3Client, "delete_user", return_value=RESPONSE_DELETE)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    delete_user(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'The User USER_ID has been removed.' in contents.get('HumanReadable')


def test_delete_group(mocker):
    """
    Given:
        Arguments for deleting a group

    When:
        Deleting a group using the delete-group command

    Then:
        Verify that the correct group is deleted
    """
    args = {
        'displayName': 'test_group'
    }

    from AWSIAMIdentityCenter import delete_group
    mocker.patch.object(AWSIAMIdentityCenter, "get_groupId_by_displayName", return_value=RESPONSE_GROUP_ID)
    mocker.patch.object(Boto3Client, "delete_group", return_value=RESPONSE_DELETE)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    delete_group(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'The Group GROUP_ID has been removed.' in contents.get('HumanReadable')


def test_list_group_memberships(mocker):
    """
    Given:
        Arguments for listing group memberships

    When:
        Listing group memberships using the list-group-memberships command

    Then:
        Verify that the correct group memberships are listed with the correct details
    """
    args = {
        'displayName': 'test_group',
    }

    response = {
        'GroupMemberships': [
            {
                'MembershipId': 'MEMBERSHIP_ID',
                'MemberId': {'UserId': 'USER_ID'}
            }
        ],
        'NextToken': 'NEXT_TOKEN'
    }

    from AWSIAMIdentityCenter import list_group_memberships
    mocker.patch.object(AWSIAMIdentityCenter, "get_groupId_by_displayName", return_value=RESPONSE_GROUP_ID)
    mocker.patch.object(Boto3Client, "list_group_memberships", return_value=response)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
    list_group_memberships(args, client)
    contents = demisto.results.call_args[0][0]

    assert {'GroupId': 'GROUP_ID', 'GroupMemberships': [{'MembershipId': 'MEMBERSHIP_ID', 'UserId': 'USER_ID'}]} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Groups' in contents.get('HumanReadable')
