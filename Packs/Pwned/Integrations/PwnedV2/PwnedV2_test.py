import pytest
from PwnedV2 import pwned_domain_command, pwned_username_command
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
    mocker.patch.object(demisto, 'params', return_value={'integrationReliability': 'A - Completely reliable'})
    mocker.patch('PwnedV2.http_request', return_value=response)
    md_list, ec_list, api_email_res_list = command(args)
    for hr, outputs, raw in zip(md_list, ec_list, api_email_res_list):
        assert expected_result == outputs  # entry context is found in the 2nd place in the result of the command


def test_rate_limited(mocker, requests_mock):
    # mock all requests with retry and provide a huge timeout
    requests_mock.get(ANY, status_code=429,
                      text='{ "statusCode": 429, "message": "Rate limit is exceeded. Try again in 20 seconds." }')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    return_error_mock.side_effect = ValueError(RETURN_ERROR_TARGET)
    PwnedV2.MAX_RETRY_ALLOWED = 10
    PwnedV2.set_retry_end_time()
    with pytest.raises(ValueError, match=RETURN_ERROR_TARGET):
        PwnedV2.pwned_email(['test@test.com'])
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    assert 'Max retry time' in return_error_mock.call_args[0][0]
