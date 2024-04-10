
import pytest
import importlib
import demistomock as demisto

AWSIAMIdentityCenter = importlib.import_module("AWSIAMIdentityCenter")

class Boto3Client:
    def create_user(self):
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
        'UserId': '2030405060',
        'IdentityStoreId': '123456',
        'ResponseMetadata': None
    }
    
    from AWSIAMIdentityCenter import create_user
    mocker.patch.object(Boto3Client, "create_user", return_value=res)
    mocker.patch.object(demisto, 'results')
    
    client = Boto3Client()
    create_user(args, client)
    contents = demisto.results.call_args[0][0]
    assert {'UserId': '2030405060', 'IdentityStoreId': '123456'} in contents.get(
        'EntryContext').values()
    assert 'AWS IAM Identity Center Users' in contents.get('HumanReadable')
    
    
    
    
    