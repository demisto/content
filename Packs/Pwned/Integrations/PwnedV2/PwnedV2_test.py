import pytest
from PwnedV2 import pwned_domain_command, pwned_username_command, pwned_email_command
import PwnedV2
from requests_mock import ANY
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
        u'PwnCount': 1247574, u'Domain': u'gawker.com', u'IsSensitive': False, u'Name': u'Gawker', u'Title':
        u'Gawker', u'DataClasses': [u'Email addresses', u'Passwords', u'Usernames'], u'IsRetired':
        False, u'IsSpamList': False, u'BreachDate': u'2010-12-11', u'IsFabricated': False, u'ModifiedDate':
        u'2013-12-04T00:00:00Z', u'LogoPath': u'https://haveibeenpwned.com/Content/Images/PwnedLogos/Gawker.png',
        u'AddedDate': u'2013-12-04T00:00:00Z', u'IsVerified': True, u'Description':
        u'In December 2010, Gawker was attacked by the hacker collective &quot;Gnosis&quot; in retaliation for what was'
        u' reported to be a feud between Gawker and 4Chan. Information about Gawkers 1.3M users was published along'
        u' with the data from Gawker\'s other web presences including Gizmodo and Lifehacker. Due to the prevalence of'
        u' password reuse, many victims of the breach <a href="http://www.troyhunt.com/2011/01/why-your-apps-security'
        u'-design-could.html" target="_blank" rel="noopener">then had their Twitter accounts compromised to send Acai'
        u' berry spam</a>.'
    },
    {
        u'PwnCount': 191540, u'Domain': u'hackforums.net', u'IsSensitive': False, u'Name': 'HackForums', u'Title':
        u'hackforums.net', u'DataClasses': [u'Dates of birth', u'Email addresses', 'Instant messenger identities',
                                            'IP addresses', 'Passwords', u'Social connections', 'Spoken languages',
                                            u'Time zones', u'User website URLs',
                                            u'Usernames', u'Website activity'], u'IsRetired': False, u'IsSpamList':
        False, u'BreachDate': u'2011-06-25',
        u'IsFabricated': False, u'ModifiedDate': '2014-05-11T10:30:43Z', u'LogoPath': u'https://haveibeenpwned.com/'
                                                                                      u'Content/Images/PwnedLogos/HackForums.png',
        'AddedDate': u'2014-05-11T10:30:43Z', u'IsVerified': True,
        u'Description': 'In June 2011, the hacktivist group known as "LulzSec" leaked <a href='
                        u'"http://www.forbes.com/sites/andygreenberg/2011/06/25/lulzsec-says-goodbye-'
                        u'dumping-nato-att-gamer-data/" target="_blank" rel="noopener">one final large'
                        u' data breach they titled "50 days of lulz"</a>. The compromised data came from'
                        u' sources such as AT&T, Battlefield Heroes and the <a href="http://hackforums.'
                        u'net" target="_blank" rel="noopener">hackforums.net website</a>. The leaked '
                        u'Hack Forums data included credentials and personal '
                        u'information of nearly 200,000 registered forum users.'
    }
]

domain_req = [
    {
        u'PwnCount': 152445165, u'Domain': u'adobe.com', u'IsSensitive': False, u'Name': u'Adobe', u'Title':
        u'Adobe', u'DataClasses': [u'Email addresses', u'Password hints', u'Passwords', u'Usernames'], u'IsRetired':
        False, 'IsSpamList': False, u'BreachDate': u'2013-10-04', u'IsFabricated': False, u'ModifiedDate':
        u'2013-12-04T00:00:00Z', u'LogoPath': u'https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe'
                                              u'.png', u'AddedDate': u'2013-12-04T00:00:00Z', u'IsVerified':
        True, u'Description': u'In October 2013, 153 million Adobe accounts were breached with each'
                              u' containing an internal ID, username, email, <em>encrypted</em> password and'
                              u' a password hint in plain text. The password cryptography was poorly done'
                              u' and <a href="http://stricture-group.com/files/adobe-top100.txt" target="_'
                              u'blank" rel="noopener">many were quickly resolved back to plain text</a>. '
                              u'The unencrypted hints also <a href="http://www.troyhunt.com/2013/11/adobe-'
                              u'credentials-and-serious.html" target="_blank" rel="noopener">disclosed much'
                              u' about the passwords</a> adding further to the risk that hundreds of '
                              u'millions of Adobe customers already faced.'
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
    for hr, outputs, raw in zip(md_list, ec_list, api_email_res_list):
        assert expected_result == outputs  # entry context is found in the 2nd place in the result of the command


def test_rate_limited(mocker, requests_mock):
    # mock all requests with retry and provide a huge timeout
    requests_mock.get(ANY, status_code=429,
                      text='{ "statusCode": 429, "message": "Rate limit is exceeded. Try again in 20 seconds." }')
    mocker.patch.object(demisto, 'params', return_value={'credentials_api_key': {'password': 'test'}})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    return_error_mock.side_effect = ValueError(RETURN_ERROR_TARGET)
    PwnedV2.MAX_RETRY_ALLOWED = 10
    PwnedV2.API_KEY = 'test'
    PwnedV2.set_retry_end_time()
    with pytest.raises(ValueError, match=RETURN_ERROR_TARGET):
        PwnedV2.pwned_email(['test@test.com'])
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    assert 'Max retry time' in return_error_mock.call_args[0][0]


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
