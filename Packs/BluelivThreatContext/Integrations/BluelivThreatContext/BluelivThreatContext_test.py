from BluelivThreatContext import Client, blueliv_threatActor, blueliv_campaign, blueliv_malware, blueliv_indicatorIp, \
    blueliv_indicatorFqdn, blueliv_indicatorCs, blueliv_attackPattern, blueliv_tool, \
    blueliv_signature, blueliv_cve


def test_blueliv_threatActor():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_threatActor(client, "0", "Vendetta")


def test_blueliv_campaign():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_campaign(client, "0", 152)


def test_blueliv_malware():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_malware(client, "ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1", "0")


def test_blueliv_indicatorIp():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_indicatorIp(client, "103.76.228.28", "0")


def test_blueliv_indicatorFqdn():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_indicatorFqdn(client, "self-repair.r53-2.services.mozilla.com", "0")


def test_blueliv_indicatorCs():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_indicatorCs(client, "0", 6626263)


def test_blueliv_attackPattern():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_attackPattern(client, "Account Discovery", "0")


def test_blueliv_tool():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_tool(client, "ACEHASH", "0")


def test_blueliv_signature():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_signature(client, "0", 84458)


def test_blueliv_cve():
    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    client.authenticate('username', 'password')
    blueliv_cve(client, "CVE-2020-8794", "0")
