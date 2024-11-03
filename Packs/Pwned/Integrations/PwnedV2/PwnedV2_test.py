import sys
from unittest.mock import MagicMock

import pytest

from PwnedV2 import pwned_domain_command, pwned_username_command, pwned_email_command, error_handler
import PwnedV2
import demistomock as demisto

RETURN_ERROR_TARGET = 'PwnedV2.return_error'

username_context = {
    'Domain(val.Name && val.Name == obj.Name)': {
        'Name': 'jondon', 'Pwned-V2': {
            'Compromised': {
                'Vendor': 'Have I Been Pwned? V2', 'Reporters': 'Gawker, hackforums.net'
            }
        }, 'Malicious': {'Vendor': 'Have I Been Pwned? V2', 'Description': 'The domain has been compromised'
                         }
    }, 'DBotScore': {
        'Indicator': 'jondon', 'Type': 'domain', 'Vendor': 'Have I Been Pwned? V2', 'Score': 3,
        'Reliability': 'A - Completely reliable'
    }
}

domain_context = {
    'Domain(val.Name && val.Name == obj.Name)': {
        'Name': 'adobe.com', 'Pwned-V2': {
            'Compromised': {
                'Vendor': 'Have I Been Pwned? V2', 'Reporters': 'Adobe'
            }
        }, 'Malicious': {'Vendor': 'Have I Been Pwned? V2', 'Description': 'The domain has been compromised'
                         }
    }, 'DBotScore': {'Indicator': 'adobe.com', 'Type': 'domain', 'Vendor': 'Have I Been Pwned? V2', 'Score': 3,
                     'Reliability': 'A - Completely reliable'}
}

username_req = [
    {
        'PwnCount': 1247574, 'Domain': 'gawker.com', 'IsSensitive': False, 'Name': 'Gawker', 'Title':
        'Gawker', 'DataClasses': ['Email addresses', 'Passwords', 'Usernames'], 'IsRetired':
        False, 'IsSpamList': False, 'BreachDate': '2010-12-11', 'IsFabricated': False, 'ModifiedDate':
        '2013-12-04T00:00:00Z', 'LogoPath': 'https://haveibeenpwned.com/Content/Images/PwnedLogos/Gawker.png',
        'AddedDate': '2013-12-04T00:00:00Z', 'IsVerified': True, 'Description':
        'In December 2010, Gawker was attacked by the hacker collective &quot;Gnosis&quot; in retaliation for what was'
        ' reported to be a feud between Gawker and 4Chan. Information about Gawkers 1.3M users was published along'
        ' with the data from Gawker\'s other web presences including Gizmodo and Lifehacker. Due to the prevalence of'
        ' password reuse, many victims of the breach <a href="http://www.troyhunt.com/2011/01/why-your-apps-security'
        '-design-could.html" target="_blank" rel="noopener">then had their Twitter accounts compromised to send Acai'
        ' berry spam</a>.'
    },
    {
        'PwnCount': 191540, 'Domain': 'hackforums.net', 'IsSensitive': False, 'Name': 'HackForums', 'Title':
        'hackforums.net', 'DataClasses': ['Dates of birth', 'Email addresses', 'Instant messenger identities',
                                          'IP addresses', 'Passwords', 'Social connections', 'Spoken languages',
                                          'Time zones', 'User website URLs',
                                          'Usernames', 'Website activity'], 'IsRetired': False, 'IsSpamList':
        False, 'BreachDate': '2011-06-25',
        'IsFabricated': False, 'ModifiedDate': '2014-05-11T10:30:43Z', 'LogoPath': 'https://haveibeenpwned.com/'
                                                                                   'Content/Images/PwnedLogos/HackForums.png',
        'AddedDate': '2014-05-11T10:30:43Z', 'IsVerified': True,
        'Description': 'In June 2011, the hacktivist group known as "LulzSec" leaked <a href='
                       '"http://www.forbes.com/sites/andygreenberg/2011/06/25/lulzsec-says-goodbye-'
                       'dumping-nato-att-gamer-data/" target="_blank" rel="noopener">one final large'
                       ' data breach they titled "50 days of lulz"</a>. The compromised data came from'
                       ' sources such as AT&T, Battlefield Heroes and the <a href="http://hackforums.'
                       'net" target="_blank" rel="noopener">hackforums.net website</a>. The leaked '
                       'Hack Forums data included credentials and personal '
                       'information of nearly 200,000 registered forum users.'
    }
]

domain_req = [
    {
        'PwnCount': 152445165, 'Domain': 'adobe.com', 'IsSensitive': False, 'Name': 'Adobe', 'Title':
        'Adobe', 'DataClasses': ['Email addresses', 'Password hints', 'Passwords', 'Usernames'], 'IsRetired':
        False, 'IsSpamList': False, 'BreachDate': '2013-10-04', 'IsFabricated': False, 'ModifiedDate':
        '2013-12-04T00:00:00Z', 'LogoPath': 'https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe'
                                            '.png', 'AddedDate': '2013-12-04T00:00:00Z', 'IsVerified':
        True, 'Description': 'In October 2013, 153 million Adobe accounts were breached with each'
                             ' containing an internal ID, username, email, <em>encrypted</em> password and'
                             ' a password hint in plain text. The password cryptography was poorly done'
                             ' and <a href="http://stricture-group.com/files/adobe-top100.txt" target="_'
                             'blank" rel="noopener">many were quickly resolved back to plain text</a>. '
                             'The unencrypted hints also <a href="http://www.troyhunt.com/2013/11/adobe-'
                             'credentials-and-serious.html" target="_blank" rel="noopener">disclosed much'
                             ' about the passwords</a> adding further to the risk that hundreds of '
                             'millions of Adobe customers already faced.'
    }
]

args1 = {
    'username': "jondon",
    'domain': "adobe.com"
}


@pytest.mark.parametrize('command, args, response, expected_result', [
    (pwned_username_command, args1, username_req, username_context),
    (pwned_domain_command, args1, domain_req, domain_context)
])
def test_pwned_commands(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - command args - e.g username, mail
    - response of the database
    When
    - mock the website result
    Then
    - convert the result to human readable table
    - create the context
    validate the expected_result and the created context
    """
    PwnedV2.API_KEY = 'test'
    mocker.patch.object(demisto, 'params', return_value={
        'integrationReliability': 'A - Completely reliable',
        'credentials_api_key': {"password": "test"}})
    mocker.patch('PwnedV2.http_request', return_value=response)
    md_list, ec_list, api_email_res_list = command(args)
    for _hr, outputs, _raw in zip(md_list, ec_list, api_email_res_list):
        assert expected_result == outputs  # entry context is found in the 2nd place in the result of the command


def test_valid_emails(mocker):
    """
    Given:
    - A list of valid email addresses.

    When:
    - Calling the pwned_email_command function.

    Then:
    - Ensure the function returns the expected output.
    """
    email_list = ['test1@example.com', 'test2@example.com']
    api_email_res_list = [{'Title': 'Breach1', 'Domain': 'example.com', 'PwnCount': 100, 'IsVerified': True,
                           'BreachDate': '2021-01-01T00:00:00Z', 'Description': '<p>Breach description</p>',
                           'DataClasses': ['Emails', 'Passwords']}, None]
    api_paste_res_list = [[{'Source': 'Paste1', 'Title': 'Paste Title', 'Id': '1234', 'Date': '2021-01-01T00:00:00Z',
                            'EmailCount': 10}], []]
    expected_md_list = [
        '### Have I Been Pwned query for email: *test1@example.com*\n'
        '#### Breach1 (example.com): 100 records breached [Verified breach]\n'
        'Date: **2021-01-01**\n\n'
        'Breach description\n'
        'Data breached: **Emails,Passwords**\n'
        '\n'
        'The email address was found in the following "Pastes":\n'
        '| ID | Title | Date | Source | Amount of emails in paste |\n'
        '|----|-------|------|--------|--------------------------|\n'
        '| 1234 | Paste Title | 2021-01-01 | Paste1 | 10 |\n',
        '### Have I Been Pwned query for email: *test2@example.com*\n'
        'No records found'
    ]
    expected_ec_list = [
        {
            'DBotScore': {
                'Indicator': 'test1@example.com',
                'Type': 'email',
                'Vendor': 'HaveIBeenPwned',
                'Score': 3,
                'Reliability': 'B - Usually reliable'
            },
            'email': {
                'Address': 'test1@example.com',
                'Pwned-V2': {
                    'Compromised': {
                        'Vendor': 'HaveIBeenPwned',
                        'Reporters': 'Breach1, Paste1'
                    }
                },
                'Malicious': {
                    'Vendor': 'HaveIBeenPwned',
                    'Description': 'The email has been compromised'
                }
            }
        },
        {
            'DBotScore': {
                'Indicator': 'test2@example.com',
                'Type': 'email',
                'Vendor': 'HaveIBeenPwned',
                'Score': 0,
                'Reliability': 'B - Usually reliable'
            },
            'email': {
                'Address': 'test2@example.com',
                'Pwned-V2': {
                    'Compromised': {
                        'Vendor': 'HaveIBeenPwned',
                        'Reporters': ''
                    }
                }
            }
        }
    ]

    mocker.patch.object(demisto, 'params', return_value={'integrationReliability': 'B - Usually reliable'})
    mocker.patch.object(demisto, 'command', return_value='pwned-email')
    mocker.patch.object(demisto, 'args', return_value={'email': email_list})
    mocker.patch('PwnedV2.pwned_email', return_value=(api_email_res_list, api_paste_res_list))
    mocker.patch('PwnedV2.data_to_markdown', side_effect=expected_md_list)
    mocker.patch('PwnedV2.email_to_entry_context', side_effect=expected_ec_list)

    md_list, ec_list, api_paste_res = pwned_email_command(demisto.args())

    assert md_list == expected_md_list
    assert ec_list == expected_ec_list


def test_error_handler_404():
    # Mock response object with 404 status code
    res = MagicMock()
    res.status_code = 404

    with pytest.raises(Exception) as excinfo:
        error_handler(res)

    assert str(excinfo.value) == "No result found."


def test_error_handler_other_status_code(mocker):
    # Mock response object with non-404 status code
    res = MagicMock()
    res.status_code = 500
    res.text = "Internal Server Error"

    mocker.patch.object(sys, 'exit')
    mocker.patch.object(demisto, 'error')
    mocker.spy(demisto, 'results')

    expected_message = 'Error in API call to Pwned Integration'

    error_handler(res)

    assert expected_message in demisto.results.call_args.args[0].get('Contents')
