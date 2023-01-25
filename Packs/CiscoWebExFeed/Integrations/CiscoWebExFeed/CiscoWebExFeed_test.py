from bs4 import BeautifulSoup
import pytest
DOMAIN_TABLE = [['Client Type', 'Domain(s)'],
                ['domain1', '*.d1.com'],
                ['domain2', '*.d2.com'],
                ['Long message without domain name']]

IP_LIST = [['1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)',
            '1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)', '1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)']]

HTML_DOMAIN_SECTION = '''<div class="panel-collapse collapse" id="id_135010">
<div class="panel-body">
<div class="body refbody">
<p class="li">Webex recommends that content should not be cached at any time. The following domain(s) will be used by meeting clients that connect to Webex Meetings:</p>
<table border="1" class="li" height="289" width="640"><tbody><tr><td colspan="1" rowspan="1"><b>Client Type</b></td><td colspan="1" rowspan="1"><b>Domain(s)  </b></td></tr><tr><td colspan="1" rowspan="1">Webex Meetings Desktop Application</td><td colspan="1" rowspan="1"><b>*.wbx2.com<br/>			*.ciscospark.com<br/>			*.webexcontent.com</b><br/>			 </td></tr><tr><td colspan="1" rowspan="1">Webex Desktop Clients (Mac/PC, including WebApp the browser based thin client) connecting to Webex Meetings</td><td colspan="1" rowspan="1"><b>*.webex.com</b></td></tr><tr><td colspan="1" rowspan="1">On-prem SIP/H323 devices calling into (or being called back from) a Webex Meeting</td><td colspan="1" rowspan="1"><b>*.webex.com</b> (note IP dialing also available)</td></tr><tr><td colspan="1" rowspan="1">Webex Mobile Clients (iOS, Android) connecting to Webex Meetings</td><td colspan="1" rowspan="1"><b>*.webex.com</b></td></tr><tr><td colspan="1" rowspan="1">Certificate Validation</td><td colspan="1" rowspan="1"><b>*.identrust.com<br/>			*.quovadisglobal.com<br/>			*.digicert.com<br/>			*.godaddy.com<br/>			*.lencr.org<br/>			*.intel.com</b></td></tr><tr><td colspan="1" rowspan="1">People Insights Integration</td><td colspan="1" rowspan="1"><b>*.accompany.com</b></td></tr><tr><td colspan="1" rowspan="1">Webex Meetings site performance analytics and Webex App</td><td colspan="1" rowspan="1">*.eum-appdynamics.com<br/>			*.appdynamics.com</td></tr><tr><td colspan="1" rowspan="1">Webex Events Webcasts (Attendees only)</td><td colspan="1" rowspan="1">*.vbrickrev.com</td></tr><tr><td colspan="1" rowspan="1">Used for Slido PPT add-in and to allow Slido webpages to create polls/quizzes in pre-meeting</td><td colspan="1" rowspan="1">*.slido.com<br/>			*.sli.do<br/>			*.data.logentries.com</td></tr><tr><td colspan="1" rowspan="1">If you have Webex app Desktop Clients, Cloud Registered Devices (including Webex Boards) connecting to Webex Meetings, you also need to allow the list of domains outlined in <a href="https://help.webex.com/WBX000028782/Network-Requirements-for-Webex-Teams-Services">https://help.webex.com/WBX000028782/Network-Requirements-for-Webex-Teams-Services</a></td><td colspan="1" rowspan="1"> </td></tr></tbody></table>
All Webex hosted services are advertised under AS13445, refer to the <a href="https://www.webex.com/peering-policy.html">Webex Peering Policy</a>. Services hosted by other service providers are not included here.  This includes TSP partner systems or our content delivery partners.  If you are connecting to partner-hosted systems such as a Partner VoIP system, please contact the partner for the appropriate IP addresses and ports.<br/><br/><b>Guidance on IPS firewall:</b>
<ul><li>Bypass firewall IPS or other types of DoS protection(allowed) for Webex traffic (defined by Webex IP CIDR blocks), especially the media traffic.</li><li>If IPS can not be a bypass, proper sizing is required to be carried out to ensure IPS have sufficient capacity to handle the audio and video throughput for a large number of participants.</li><li>If IPS can not be a bypass, proper fine-tuning of the signature and threshold has to be achieved so that Webex traffic is not misclassified and subsequently dropped.</li><li>Monitor firewall IPS alerts to investigate any IPS alert against Webex traffic.</li></ul>
Note: The following UserAgents will be passed by Webex by the utiltp process in Webex, and should be allowed through an agency's firewall:

<ul><li>UserAgent=WebexInMeetingWin</li><li>UserAgent=WebexInMeetingMac</li><li>UserAgent=prefetchDocShow</li><li>UserAgent=standby</li></ul>
<br/><b>Guidance on Proxy servers:</b>
<ul><li>The Webex meeting client does not support SNI extension for TLS media connections. Connection failure to the Webex audio and video services will occur if a proxy server requires the presence of SNI.</li></ul>
</div>
</div>
</div>'''

HTML_IP_SECTION = '''<div class="panel-collapse collapse" id="id_135011">
<div class="panel-body">
<div class="body refbody">
<ul><li></li><li></li><li>150.253.128.0/17 (CIDR) or 150.253.128.0 - 150.253.255.255 (net range)</li><li></li><li></li></ul>
</div>
</div>
</div>'''


def test_grab_domains():
    """
    Given:
        - Raw list of tuples that contains domain name and domain url, returned by api call:
        first array is the title, 2 seconds arrays are data, last array is message.
    When:
        - Filtered list contains domain's urls only
    Then:
        - Return domains list without errors
    """
    from CiscoWebExFeed import grab_domains
    expected_result = ['*.d1.com', '*.d2.com']
    assert grab_domains(DOMAIN_TABLE) == expected_result


def test_grab_CIDR_ips():
    """
    Given:
        -Raw list of lists that contains ips CIDR and net range, returned by api call:
        first array is the title, 2 seconds arrays are data, last array is message.
    When:
        - Filtered list contains domain's urls only
    Then:
        - Return CIDR ips list without errors
    """
    from CiscoWebExFeed import grab_CIDR_ips
    expected_result = ['1.1.1.1/1', '1.1.1.1/1', '1.1.1.1/1']
    assert grab_CIDR_ips(IP_LIST) == expected_result


def test_grab_domain_table():
    """
    Given: a soup object that is similar to the domain table

    When:
        - grab_domain_table(soup)
    Then:
        - the function should return a list of lists that contains the domain table
    """
    from CiscoWebExFeed import grab_domain_table
    soup = BeautifulSoup(HTML_DOMAIN_SECTION, "html.parser")
    expected_result = [['Client Type', 'Domain(s)'], ['Webex Meetings Desktop Application', '*.wbx2.com\t\t\t*.ciscospark.com\t\t\t*.webexcontent.com'], ['Webex Desktop Clients (Mac/PC, including WebApp the browser based thin client) connecting to Webex Meetings', '*.webex.com'], ['On-prem SIP/H323 devices calling into (or being called back from) a Webex Meeting', '*.webex.com (note IP dialing also available)'], ['Webex Mobile Clients (iOS, Android) connecting to Webex Meetings', '*.webex.com'], ['Certificate Validation', '*.identrust.com\t\t\t*.quovadisglobal.com\t\t\t*.digicert.com\t\t\t*.godaddy.com\t\t\t*.lencr.org\t\t\t*.intel.com'], ['People Insights Integration', '*.accompany.com'], [
        'Webex Meetings site performance analytics and Webex App', '*.eum-appdynamics.com\t\t\t*.appdynamics.com'], ['Webex Events Webcasts (Attendees only)', '*.vbrickrev.com'], ['Used for Slido PPT add-in and to allow Slido webpages to create polls/quizzes in pre-meeting', '*.slido.com\t\t\t*.sli.do\t\t\t*.data.logentries.com'], ['If you have Webex app Desktop Clients, Cloud Registered Devices (including Webex Boards) connecting to Webex Meetings, you also need to allow the list of domains outlined in https://help.webex.com/WBX000028782/Network-Requirements-for-Webex-Teams-Services']]
    assert grab_domain_table(soup) == expected_result


def test_grab_ip_table():
    """
    Given: a soup object that is similar to the ip table

    When:
        - grab_ip_table(soup)
    Then:
        - the function should return a list of lists that contains the ips from the table
    """
    from CiscoWebExFeed import grab_ip_table
    soup = BeautifulSoup(HTML_IP_SECTION, "html.parser")
    expected_result = [['150.253.128.0/17 (CIDR) or 150.253.128.0 - 150.253.255.255 (net range)']]
    assert grab_ip_table(soup) == expected_result


@pytest.mark.parametrize('input, expected', [
    ('1.1.1.1/16', 'CIDR'), ('*.google.com', 'DomainGlob'), ('google.com', 'Domain')])
def test_check_indicator_type(input, expected):
    """
    Given:  a string that is an ip, domain or domain glob

    When:
        - check_indicator_type is called
    Then:
        - the function should return the correct indicator type
    """
    from CiscoWebExFeed import check_indicator_type
    assert check_indicator_type(input) == expected


def test_get_indicators_command(mocker):
    from CiscoWebExFeed import get_indicators_command, Client, parse_indicators_from_response
    client = mocker.patch.object(Client, 'all_raw_data', return_value='gg')
    mocker.patch.object(parse_indicators_from_response, return_value={'blabla': 'blabla'})

    res = get_indicators_command(client, limit=1, indicator_type="Both")
    assert res == "gg"
