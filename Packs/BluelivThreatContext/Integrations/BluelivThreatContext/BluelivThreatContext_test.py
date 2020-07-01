from BluelivThreatContext import Client, blueliv_threatActor, blueliv_campaign, blueliv_malware, blueliv_indicatorIp, \
    blueliv_indicatorFqdn, blueliv_indicatorCs, blueliv_attackPattern, blueliv_tool, \
    blueliv_signature, blueliv_cve


def test_blueliv_threatActor():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"threatActor": "Vendetta"}
    blueliv_threatActor(client, args)


def test_blueliv_campaign():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"campaign_id": 152}
    blueliv_campaign(client, args)


def test_blueliv_malware():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"hash": "ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1"}
    blueliv_malware(client, args)


def test_blueliv_indicatorIp():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"IP": "103.76.228.28"}
    blueliv_indicatorIp(client, args)


def test_blueliv_indicatorFqdn():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"FQDN": "self-repair.r53-2.services.mozilla.com"}
    blueliv_indicatorFqdn(client, args)


def test_blueliv_indicatorCs():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"CS_id": 6626263}
    blueliv_indicatorCs(client, args)


def test_blueliv_attackPattern():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"attackPattern": "Account Discovery"}
    blueliv_attackPattern(client, args)


def test_blueliv_tool():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"tool": "ACEHASH"}
    blueliv_tool(client, args)


def test_blueliv_signature():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"signature_id": 84458}
    blueliv_signature(client, args)


def test_blueliv_cve():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    args = {"CVE": "CVE-2020-8794"}
    blueliv_cve(client, args)
