import json
import textwrap
import time

import DNSDB_v2 as DNSDB
import pytest
import CommonServerPython


class TestClient:
    def test_headers(self, requests_mock):
        apikey = 'abcdef'
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, apikey)

        requests_mock.get(
            '{server}/dnsdb/v2/rate_limit?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            json={},
            request_headers={
                'Accept': 'application/x-ndjson',
                'X-API-Key': apikey,
            })

        c.rate_limit()

    def test_rate_limit(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')

        requests_mock.get(
            f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/rate_limit?swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
            json={})

        c.rate_limit()

    def test_lookup_rrset(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count":1820,"zone_time_first":1374250920,"zone_time_last":1589472138,"rrname":"farsightsecurity.com.",'
            '"rrtype":"NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy'
            '.com."]}',
            '{"count":6350,"time_first":1380123423,"time_last":1427869045,"rrname":"farsightsecurity.com.","rrtype":"'
            'A","bailiwick":"farsightsecurity.com.","rdata":["66.160.140.81"]}',
        ]
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rrset(name):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_summarize_rrset(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        record = '{"count":6350,"num_results":3,"time_first":1380123423,"time_last":1427869045}'
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([record]))

        rrset = c.summarize_rrset(name)
        assert rrset == json.loads(record)

    def test_summarize_rrset_empty(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text='')

        with pytest.raises(DNSDB.QueryError):
            c.summarize_rrset(name)

    def test_rrset_rrtype(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count":6350,"time_first":1380123423,"time_last":1427869045,"rrname":"farsightsecurity.com.","rrtype":"A"'
            ',"bailiwick":"farsightsecurity.com.","rdata":["66.160.140.81"]}',
            '{"count":36770,"time_first":1427897872,"time_last":1538008183,"rrname":"farsightsecurity.com.","rrtype":"A'
            '","bailiwick":"farsightsecurity.com.","rdata":["104.244.13.104"]}',
            '{"count":6428,"time_first":1538047094,"time_last":1589544286,"rrname":"farsightsecurity.com.","rrtype":"A"'
            ',"bailiwick":"farsightsecurity.com.","rdata":["104.244.14.108"]}',
            '{"count":628,"time_first":1374098930,"time_last":1380124067,"rrname":"farsightsecurity.com.","rrtype":"A",'
            '"bailiwick":"farsightsecurity.com.","rdata":["149.20.4.207"]}',
        ]
        name = 'farsightsecurity.com'
        rrtype = 'A'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}/{rrtype}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                rrtype=rrtype,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rrset(name, rrtype=rrtype):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_rrset_bailiwick(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count":19,"zone_time_first":1372609301,"zone_time_last":1374164567,"rrname":"farsightsecurity.com.","rrt'
            'ype":"NS","bailiwick":"com.","rdata":["ns.lah1.vix.com.","ns1.isc-sns.net.","ns2.isc-sns.com.","ns3.isc-sn'
            's.info."]}',
            '{"count":157,"zone_time_first":1359047885,"zone_time_last":1372522741,"rrname":"farsightsecurity.com.","rr'
            'type":"NS","bailiwick":"com.","rdata":["ns.sjc1.vix.com.","ns.sql1.vix.com."]}',
            '{"count":1820,"zone_time_first":1374250920,"zone_time_last":1589472138,"rrname":"farsightsecurity.com.","r'
            'rtype":"NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com'
            '."]}',
            '{"count":58,"time_first":1372688083,"time_last":1374165919,"rrname":"farsightsecurity.com.","rrtype":"NS",'
            '"bailiwick":"com.","rdata":["ns.lah1.vix.com.","ns1.isc-sns.net.","ns2.isc-sns.com.","ns3.isc-sns.info."]'
            '}',
            '{"count":17,"time_first":1360364071,"time_last":1372437672,"rrname":"farsightsecurity.com.","rrtype":"NS",'
            '"bailiwick":"com.","rdata":["ns.sjc1.vix.com.","ns.sql1.vix.com."]}',
            '{"count":853787,"time_first":1374172950,"time_last":1589549475,"rrname":"farsightsecurity.com.","rrtype":"'
            'NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com."]}',
        ]
        name = 'farsightsecurity.com'
        bailiwick = 'com'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}/{rrtype}/{bailiwick}?swclient={swclient}&version={version}'.format(  # noqa: E501
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                rrtype='ANY',
                bailiwick=bailiwick,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rrset(name, bailiwick=bailiwick):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_rrset_rrtype_bailiwick(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count":19,"zone_time_first":1372609301,"zone_time_last":1374164567,"rrname":"farsightsecurity.com.","rrt'
            'ype":"NS","bailiwick":"com.","rdata":["ns.lah1.vix.com.","ns1.isc-sns.net.","ns2.isc-sns.com.","ns3.isc-sn'
            's.info."]}',
            '{"count":157,"zone_time_first":1359047885,"zone_time_last":1372522741,"rrname":"farsightsecurity.com.","rr'
            'type":"NS","bailiwick":"com.","rdata":["ns.sjc1.vix.com.","ns.sql1.vix.com."]}',
            '{"count":1820,"zone_time_first":1374250920,"zone_time_last":1589472138,"rrname":"farsightsecurity.com.","r'
            'rtype":"NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com'
            '."]}',
            '{"count":58,"time_first":1372688083,"time_last":1374165919,"rrname":"farsightsecurity.com.","rrtype":"NS",'
            '"bailiwick":"com.","rdata":["ns.lah1.vix.com.","ns1.isc-sns.net.","ns2.isc-sns.com.","ns3.isc-sns.info."]'
            '}',
            '{"count":17,"time_first":1360364071,"time_last":1372437672,"rrname":"farsightsecurity.com.","rrtype":"NS",'
            '"bailiwick":"com.","rdata":["ns.sjc1.vix.com.","ns.sql1.vix.com."]}',
            '{"count":853787,"time_first":1374172950,"time_last":1589549475,"rrname":"farsightsecurity.com.","rrtype":"'
            'NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com."]}',
        ]
        name = 'farsightsecurity.com'
        rrtype = 'NS'
        bailiwick = 'com'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}/{rrtype}/{bailiwick}?swclient={swclient}&version={version}'.format(  # noqa: E501
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                rrtype=rrtype,
                bailiwick=bailiwick,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rrset(name, rrtype=rrtype, bailiwick=bailiwick):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_lookup_rdata_name(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count": 7, "time_first": 1380044973, "time_last": 1380141734, "rrname": "207.4.20.149.in-addr.fsi.io.",'
            ' "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 3, "time_first": 1372650830, "time_last": 1375220475, "rrname": "7.0.2.0.0.0.0.0.0.0.0.0.0.0.0.'
            '0.6.6.0.0.1.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 11, "time_first": 1380141403, "time_last": 1381263825, "rrname": "81.64-26.140.160.66.in-addr.a'
            'rpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 4, "time_first": 1373922472, "time_last": 1374071997, "rrname": "207.192-26.4.20.149.in-addr.ar'
            'pa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
        ]
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rdata_name(name):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_summarize_rdata_name(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        record = '{"count": 7, "num_results": 5, "time_first": 1380044973, "time_last": 1380141734}'
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([record]))

        rrset = c.summarize_rdata_name(name)
        assert rrset == json.loads(record)

    def test_summarize_rdata_name_empty(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text='')

        with pytest.raises(DNSDB.QueryError):
            c.summarize_rdata_name(name)

    def test_rdata_name_rrtype(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count": 7, "time_first": 1380044973, "time_last": 1380141734, "rrname": "207.4.20.149.in-addr.fsi.io.",'
            ' "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 3, "time_first": 1372650830, "time_last": 1375220475, "rrname": "7.0.2.0.0.0.0.0.0.0.0.0.0.0.0.'
            '0.6.6.0.0.1.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 11, "time_first": 1380141403, "time_last": 1381263825, "rrname": "81.64-26.140.160.66.in-addr.a'
            'rpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 4, "time_first": 1373922472, "time_last": 1374071997, "rrname": "207.192-26.4.20.149.in-addr.ar'
            'pa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
        ]
        name = 'farsightsecurity.com'
        rrtype = 'PTR'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}/{rrtype}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='name',
                name=name,
                rrtype=rrtype,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rdata_name(name, rrtype=rrtype):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_lookup_rdata_ip(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count":51,"time_first":1403544512,"time_last":1417464427,"rrname":"farsighsecurity.com.","rrtype":"A","'
            'rdata":"66.160.140.81"}',
            '{"count":4,"time_first":1404485629,"time_last":1406648461,"rrname":"www.farsighsecurity.com.","rrtype":"A'
            '","rdata":"66.160.140.81"}',
            '{"count":6350,"time_first":1380123423,"time_last":1427869045,"rrname":"farsightsecurity.com.","rrtype":"A'
            '","rdata":"66.160.140.81"}',
            '{"count":5059,"time_first":1380139330,"time_last":1427881899,"rrname":"www.farsightsecurity.com.","rrtype'
            '":"A","rdata":"66.160.140.81"}',
            '{"count":1523,"time_first":1381265271,"time_last":1427807985,"rrname":"archive.farsightsecurity.com.","rr'
            'type":"A","rdata":"66.160.140.81"}',
        ]
        ip = '66.160.140.81'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{ip}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='ip',
                ip=ip,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rdata_ip(ip):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_summarize_rdata_ip(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        record = '{"count":51,"num_results":5,"time_first":1403544512,"time_last":1417464427}'
        ip = '66.160.140.81'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{ip}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='ip',
                ip=ip,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([record]))

        rrset = c.summarize_rdata_ip(ip)
        assert rrset == json.loads(record)

    def test_summarize_rdata_ip_empty(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        ip = '66.160.140.81'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{ip}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='ip',
                ip=ip,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text='')

        with pytest.raises(DNSDB.QueryError):
            c.summarize_rdata_ip(ip)

    def test_lookup_rdata_raw(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count": 7, "time_first": 1380044973, "time_last": 1380141734, "rrname": "207.4.20.149.in-addr.fsi.io.",'
            ' "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 3, "time_first": 1372650830, "time_last": 1375220475, "rrname": "7.0.2.0.0.0.0.0.0.0.0.0.0.0.0.'
            '0.6.6.0.0.1.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 11, "time_first": 1380141403, "time_last": 1381263825, "rrname": "81.64-26.140.160.66.in-addr.a'
            'rpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 4, "time_first": 1373922472, "time_last": 1374071997, "rrname": "207.192-26.4.20.149.in-addr.ar'
            'pa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
        ]
        raw = '0123456789ABCDEF'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{raw}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='raw',
                raw=DNSDB.quote(raw),
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rdata_raw(raw):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_summarize_rdata_raw(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        record = '{"count": 7, "num_results": 5, "time_first": 1380044973, "time_last": 1380141734}'
        raw = '0123456789ABCDEF'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{raw}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='raw',
                raw=DNSDB.quote(raw),
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([record]))

        rrset = c.summarize_rdata_raw(raw)
        assert rrset == json.loads(record)

    def test_summarize_rdata_raw_empty(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        raw = '0123456789ABCDEF'

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{raw}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='raw',
                raw=DNSDB.quote(raw),
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text='')

        with pytest.raises(DNSDB.QueryError):
            c.summarize_rdata_raw(raw)

    def test_rdata_raw_rrtype(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"count": 7, "time_first": 1380044973, "time_last": 1380141734, "rrname": "207.4.20.149.in-addr.fsi.io.",'
            ' "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 3, "time_first": 1372650830, "time_last": 1375220475, "rrname": "7.0.2.0.0.0.0.0.0.0.0.0.0.0.0.'
            '0.6.6.0.0.1.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 11, "time_first": 1380141403, "time_last": 1381263825, "rrname": "81.64-26.140.160.66.in-addr.a'
            'rpa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
            '{"count": 4, "time_first": 1373922472, "time_last": 1374071997, "rrname": "207.192-26.4.20.149.in-addr.ar'
            'pa.", "rrtype": "PTR", "rdata": "farsightsecurity.com."}',
        ]
        raw = '0123456789ABCDEF'
        rrtype = 'PTR'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{raw}/{rrtype}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rdata',
                type='raw',
                raw=raw,
                rrtype=rrtype,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap(records))

        for rrset in c.lookup_rdata_raw(raw, rrtype=rrtype):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_flex(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        records = [
            '{"rdata": "10 lists.farsightsecurity.com.", "rrtype": "MX", "raw_rdata": "000A056C69737473106661727369676874736563757269747903636F6D00"}',  # noqa: E501
            '{"rdata": "10 support.farsightsecurity.com.", "rrtype": "MX", "raw_rdata": "000A07737570706F7274106661727369676874736563757269747903636F6D00"}',  # noqa: E501
            '{"rdata": "x.support.farsightsecurity.com.", "rrtype": "CNAME", "raw_rdata": "017807737570706F7274106661727369676874736563757269747903636F6D00"}',  # noqa: E501
        ]
        method = 'regex'
        key = 'rdata'
        value = 'farsightsecurity'

        requests_mock.get(
            f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/{method}/{key}/{value}?swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
            text=_saf_wrap(records))

        for rrset in c.flex(method, key, value):
            assert rrset == json.loads(records[0])
            records = records[1:]
        assert len(records) == 0

    def test_500(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            status_code=500, text='{}\nerror')

        with pytest.raises(CommonServerPython.DemistoException):
            for rrset in c.lookup_rrset(name):
                pytest.fail(f'received {rrset}')  # pragma: no cover

    def test_limit(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'
        limit = 100

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?limit={limit}&swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                limit=limit,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([]))

        for rrset in c.lookup_rrset(name, limit=limit):
            pytest.fail(f'received {rrset}')  # pragma: no cover

    def test_time_first_before(self, requests_mock):
        self._test_time_param(requests_mock, "time_first_before")

    def test_time_first_after(self, requests_mock):
        self._test_time_param(requests_mock, "time_first_after")

    def test_time_last_before(self, requests_mock):
        self._test_time_param(requests_mock, "time_last_before")

    def test_time_last_after(self, requests_mock):
        self._test_time_param(requests_mock, "time_last_after")

    def test_aggr(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'
        aggr = 100

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?aggr={aggr}&swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                aggr=aggr,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([]))

        for rrset in c.lookup_rrset(name, aggr=aggr):
            pytest.fail(f'received {rrset}')  # pragma: no cover

    def test_offset(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'
        offset = 100

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?offset={offset}&swclient={swclient}&version={version}'.format(  # noqa: E501
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                offset=offset,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([]))

        for rrset in c.lookup_rrset(name, offset=offset):
            pytest.fail(f'received {rrset}')  # pragma: no cover

    def test_max_count(self, requests_mock):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'
        max_count = 100

        requests_mock.get(
            '{server}/dnsdb/v2/summarize/{mode}/{type}/{name}?max_count={max_count}'
            '&swclient={swclient}&version={version}'.format(server=DNSDB.DEFAULT_DNSDB_SERVER,
                                                            mode='rrset',
                                                            type='name',
                                                            name=name,
                                                            max_count=max_count,
                                                            swclient=DNSDB.SWCLIENT,
                                                            version=DNSDB.VERSION),
            text=_saf_wrap([]))

        with pytest.raises(DNSDB.QueryError):
            for rrset in c.summarize_rrset(name, max_count=max_count):
                pytest.fail(f'received {rrset}')  # pragma: no cover

    @staticmethod
    def _test_time_param(requests_mock, param: str):
        c = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        name = 'farsightsecurity.com'
        when = time.time()

        requests_mock.get(
            '{server}/dnsdb/v2/lookup/{mode}/{type}/{name}?{param}={when}&swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                mode='rrset',
                type='name',
                name=name,
                param=param,
                when=when,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ),
            text=_saf_wrap([]))

        for rrset in c.lookup_rrset(name, **{param: when}):
            pytest.fail(f'received {rrset}')  # pragma: no cover


class TestBuildResultContext:
    def test_lookup_rrset(self):
        self._run_test(
            {
                "count": 5059,
                "time_first": 1380139330,
                "time_last": 1427881899,
                "rrname": "www.farsightsecurity.com.",
                "rrtype": "A",
                "bailiwick": "farsightsecurity.com.",
                "rdata": ["66.160.140.81", '66.160.140.82']
            },
            {
                'RRName': 'www.farsightsecurity.com',
                'RRType': 'A',
                'Bailiwick': 'farsightsecurity.com',
                'RData': ['66.160.140.81', '66.160.140.82'],
                'Count': 5059,
                'TimeFirst': '2013-09-25T20:02:10Z',
                'TimeLast': '2015-04-01T09:51:39Z',
                'FromZoneFile': False,
            }
        )

    def test_lookup_rdata(self):
        self._run_test({
            "count": 5059,
            "time_first": 1380139330,
            "time_last": 1427881899,
            "rrname": "www.farsightsecurity.com.",
            "rrtype": "A",
            "bailiwick": "farsightsecurity.com.",
            "rdata": "66.160.140.81",
        }, {
            'RRName': 'www.farsightsecurity.com',
            'RRType': 'A',
            'Bailiwick': 'farsightsecurity.com',
            'RData': '66.160.140.81',
            'Count': 5059,
            'TimeFirst': '2013-09-25T20:02:10Z',
            'TimeLast': '2015-04-01T09:51:39Z',
            'FromZoneFile': False,
        })

    def test_flex(self):
        self._run_test({
            "rdata": "10 lists.farsightsecurity.com",
            "raw_rdata": "000A056C69737473106661727369676874736563757269747903636F6D00",
            "rrtype": "MX",
        }, {
            "RData": "10 lists.farsightsecurity.com",
            "RawRData": "000A056C69737473106661727369676874736563757269747903636F6D00",
            "RRType": "MX",
        })

    def test_summarize(self):
        self._run_test({
            "count": 1127,
            "num_results": 2,
            "zone_time_first": 1557859313,
            "zone_time_last": 1560537333
        }, {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': True,
        })

    def test_idna(self):
        self._run_test({
            'rrname': 'www.xn--frsight-exa.com.',
            'bailiwick': 'xn--frsight-exa.com.',
        }, {
            'RRName': 'www.xn--frsight-exa.com',
            'Bailiwick': 'xn--frsight-exa.com',
        })

    @staticmethod
    def _run_test(input, expected):
        assert DNSDB.build_result_context(input) == expected


class TestBuildLimitsContext:
    def test_no_rate(self):
        with pytest.raises(ValueError):
            DNSDB.build_rate_limits_context({})

    def test_time_based_quota(self):
        self._run_test(
            {
                "rate": {
                    "reset": 1433980800,
                    "limit": 1000,
                    "remaining": 999,
                }
            },
            {
                'Reset': '2015-06-11T00:00:00Z',
                'Limit': 1000,
                'Remaining': 999,
            }
        )

    def test_block_based_quota(self):
        self._run_test(
            {
                "rate": {
                    "reset": "n/a",
                    "burst_size": 10,
                    "expires": 1555370914,
                    "burst_window": 300,
                    "offset_max": 3000000,
                    "results_max": 256,
                    "limit": 600,
                    "remaining": 8,
                }
            }, {
                'NeverResets': True,
                'BurstSize': 10,
                'Expires': '2019-04-15T23:28:34Z',
                'BurstWindow': 300,
                'OffsetMax': 3000000,
                'ResultsMax': 256,
                'Limit': 600,
                'Remaining': 8,
            })

    def test_unlimited(self):
        self._run_test(
            {
                "rate": {
                    "reset": "n/a",
                    "limit": "unlimited",
                    "remaining": "n/a"
                }
            },
            {
                'Unlimited': True,
            }
        )

    @staticmethod
    def _run_test(input: dict, expected: dict):
        assert DNSDB.build_rate_limits_context(input) == expected


class TestRDataCommand:
    def test_empty(self, requests_mock):
        args = {
            'type': 'name',
            'value': 'farsightsecurity.com',
            'limit': '10',
        }
        input = ''
        expected_readable = textwrap.dedent('''\
                    ### Farsight DNSDB Lookup
                    **No entries.**
                                        ''')
        expected_output_prefix = 'DNSDB.Record'
        expected_outputs = []

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_name(self, requests_mock):
        args = {
            'type': 'name',
            'value': 'ns5.dnsmadeeasy.com',
            'limit': '10',
        }
        input = [
            '{"count":1078,"zone_time_first":1374250920,"zone_time_last":1468253883,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}',  # noqa: E501
            '{"count":706617,"time_first":1374096380,"time_last":1468334926,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}',  # noqa: E501
        ]

        expected_readable = textwrap.dedent('''\
            ### Farsight DNSDB Lookup
            |RRName|RRType|RData|Count|TimeFirst|TimeLast|FromZoneFile|
            |---|---|---|---|---|---|---|
            | farsightsecurity.com | NS | ns5.dnsmadeeasy.com. | 1078 | 2013-07-19T16:22:00Z | 2016-07-11T16:18:03Z | True |
            | farsightsecurity.com | NS | ns5.dnsmadeeasy.com. | 706617 | 2013-07-17T21:26:20Z | 2016-07-12T14:48:46Z | False |
            ''')  # noqa: E501

        expected_output_prefix = 'DNSDB.Record'
        expected_outputs = [
            {
                'Count': 1078,
                'RData': 'ns5.dnsmadeeasy.com.',
                'RRName': 'farsightsecurity.com',
                'RRType': 'NS',
                'TimeFirst': '2013-07-19T16:22:00Z',
                'TimeLast': '2016-07-11T16:18:03Z',
                'FromZoneFile': True,
            },
            {
                'Count': 706617,
                'RData': 'ns5.dnsmadeeasy.com.',
                'RRName': 'farsightsecurity.com',
                'RRType': 'NS',
                'TimeFirst': '2013-07-17T21:26:20Z',
                'TimeLast': '2016-07-12T14:48:46Z',
                'FromZoneFile': False,
            }
        ]

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_ip(self, requests_mock):
        args = {
            'type': 'ip',
            'value': '104.244.13.104',
            'limit': '10',
        }
        input = [
            '{"count":24,"time_first":1433550785,"time_last":1468312116,"rrname":"www.farsighsecurity.com.","rrtype":"A","rdata":"104.244.13.104"}',  # noqa: E501
            '{"count":9429,"zone_time_first":1427897872,"zone_time_last":1468333042,"rrname":"farsightsecurity.com.","rrtype":"A","rdata":"104.244.13.104"}'  # noqa: E501
        ]

        expected_readable = textwrap.dedent('''\
            ### Farsight DNSDB Lookup
            |RRName|RRType|RData|Count|TimeFirst|TimeLast|FromZoneFile|
            |---|---|---|---|---|---|---|
            | www.farsighsecurity.com | A | 104.244.13.104 | 24 | 2015-06-06T00:33:05Z | 2016-07-12T08:28:36Z | False |
            | farsightsecurity.com | A | 104.244.13.104 | 9429 | 2015-04-01T14:17:52Z | 2016-07-12T14:17:22Z | True |
            ''')

        expected_prefix = 'DNSDB.Record'
        expected_outputs = [
            {'Count': 24,
             'FromZoneFile': False,
             'RData': '104.244.13.104',
             'RRName': 'www.farsighsecurity.com',
             'RRType': 'A',
             'TimeFirst': '2015-06-06T00:33:05Z',
             'TimeLast': '2016-07-12T08:28:36Z'},
            {
                'Count': 9429,
                'FromZoneFile': True,
                'RData': '104.244.13.104',
                'RRName': 'farsightsecurity.com',
                'RRType': 'A',
                'TimeFirst': '2015-04-01T14:17:52Z',
                'TimeLast': '2016-07-12T14:17:22Z'
            }
        ]

        self._run_test(requests_mock, args, input, expected_readable, expected_prefix, expected_outputs)

    def test_raw(self, requests_mock):
        args = {
            'type': 'raw',
            'value': '0123456789ABCDEF',
            'limit': '10',
        }
        input = [
            '{"count":1078,"zone_time_first":1374250920,"zone_time_last":1468253883,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}',  # noqa: E501
            '{"count":706617,"time_first":1374096380,"time_last":1468334926,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}',  # noqa: E501
        ]

        expected_readable = textwrap.dedent('''\
            ### Farsight DNSDB Lookup
            |RRName|RRType|RData|Count|TimeFirst|TimeLast|FromZoneFile|
            |---|---|---|---|---|---|---|
            | farsightsecurity.com | NS | ns5.dnsmadeeasy.com. | 1078 | 2013-07-19T16:22:00Z | 2016-07-11T16:18:03Z | True |
            | farsightsecurity.com | NS | ns5.dnsmadeeasy.com. | 706617 | 2013-07-17T21:26:20Z | 2016-07-12T14:48:46Z | False |
            ''')  # noqa: E501

        expected_output_prefix = 'DNSDB.Record'
        expected_outputs = [
            {
                'Count': 1078,
                'RData': 'ns5.dnsmadeeasy.com.',
                'RRName': 'farsightsecurity.com',
                'RRType': 'NS',
                'TimeFirst': '2013-07-19T16:22:00Z',
                'TimeLast': '2016-07-11T16:18:03Z',
                'FromZoneFile': True,
            },
            {
                'Count': 706617,
                'RData': 'ns5.dnsmadeeasy.com.',
                'RRName': 'farsightsecurity.com',
                'RRType': 'NS',
                'TimeFirst': '2013-07-17T21:26:20Z',
                'TimeLast': '2016-07-12T14:48:46Z',
                'FromZoneFile': False,
            }
        ]

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    @staticmethod
    def _run_test(requests_mock, args: dict, input: list, expected_readable: str, expected_output_prefix: str,
                  expected_outputs: list):
        client = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        requests_mock.get(f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/lookup/rdata/{args["type"]}/{args["value"]}'
                          f'?limit={args["limit"]}'
                          f'&swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
                          text=_saf_wrap(input))

        for v in args.values():
            assert isinstance(v, str)

        res = DNSDB.dnsdb_rdata(client, args)

        assert res.readable_output == expected_readable
        assert res.outputs_prefix == expected_output_prefix
        assert res.outputs == expected_outputs


class TestSummarizeRDataCommand:
    def test_name(self, requests_mock):
        args = {
            'type': 'name',
            'value': 'www.farsightsecurity.com',
            'limit': '2',
            'max_count': '5000',
        }
        input = [
            '{"count": 1127, "num_results": 2, "time_first": 1557859313, "time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                ### Farsight DNSDB Summarize
                |Count|NumResults|TimeFirst|TimeLast|
                |---|---|---|---|
                | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                ''')
        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': False,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_ip(self, requests_mock):
        args = {
            'type': 'ip',
            'value': '127.0.0.1',
            'limit': '2',
            'max_count': '5000',
        }
        input = [
            '{"count": 1127, "num_results": 2, "time_first": 1557859313, "time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                ### Farsight DNSDB Summarize
                |Count|NumResults|TimeFirst|TimeLast|
                |---|---|---|---|
                | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                ''')

        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': False,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_raw(self, requests_mock):
        args = {
            'type': 'raw',
            'value': '0123456789ABCDEF',
            'limit': '2',
            'max_count': '5000',
        }
        input = [
            '{"count": 1127, "num_results": 2, "time_first": 1557859313, "time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                ### Farsight DNSDB Summarize
                |Count|NumResults|TimeFirst|TimeLast|
                |---|---|---|---|
                | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                ''')
        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': False,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_zone(self, requests_mock):
        args = {
            'type': 'name',
            'value': 'www.farsightsecurity.com',
            'limit': '10',
            'max_count': '50',
        }
        input = [
            '{"count": 1127, "num_results": 2, "zone_time_first": 1557859313, "zone_time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                        ### Farsight DNSDB Summarize
                        |Count|NumResults|ZoneTimeFirst|ZoneTimeLast|
                        |---|---|---|---|
                        | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                        ''')

        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': True,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    @staticmethod
    def _run_test(requests_mock, args: dict, input: dict, expected_readable: str, expected_output_prefix: str,
                  expected_outputs: dict):
        client = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        requests_mock.get(f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/summarize/rdata/{args["type"]}/{args["value"]}'
                          f'?limit={args["limit"]}'
                          f'&max_count={args["max_count"]}'
                          f'&swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
                          text=_saf_wrap(input))

        for v in args.values():
            assert isinstance(v, str)

        res = DNSDB.dnsdb_summarize_rdata(client, args)

        assert res.readable_output == expected_readable
        assert res.outputs_prefix == expected_output_prefix
        assert res.outputs == expected_outputs


class TestRRSetCommand:
    def test_empty(self, requests_mock):
        args = {
            'owner_name': '*.farsightsecurity.com',
            'limit': '10',
        }
        input = []
        expected_readable = textwrap.dedent('''\
                    ### Farsight DNSDB Lookup
                    **No entries.**
                                        ''')
        expected_output_prefix = 'DNSDB.Record'
        expected_outputs = []

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_a(self, requests_mock):
        args = {
            'owner_name': '*.farsightsecurity.com',
            'limit': '10',
        }
        input = [
            '{"count":5059,"time_first":1380139330,"time_last":1427881899,"rrname":"www.farsightsecurity.com.","rrtype":"A","bailiwick":"farsightsecurity.com.","rdata":["66.160.140.81"]}',  # noqa: E501
            '{"count":17381,"zone_time_first":1427893644,"zone_time_last":1468329272,"rrname":"farsightsecurity.com.","rrtype":"A","bailiwick":"com.","rdata":["104.244.13.104"]}',  # noqa: E501
        ]

        expected_readable = textwrap.dedent('''\
        ### Farsight DNSDB Lookup
        |RRName|RRType|Bailiwick|RData|Count|TimeFirst|TimeLast|FromZoneFile|
        |---|---|---|---|---|---|---|---|
        | www.farsightsecurity.com | A | farsightsecurity.com | 66.160.140.81 | 5059 | 2013-09-25T20:02:10Z | 2015-04-01T09:51:39Z | False |
        | farsightsecurity.com | A | com | 104.244.13.104 | 17381 | 2015-04-01T13:07:24Z | 2016-07-12T13:14:32Z | True |
        ''')  # noqa: E501

        expected_output_prefix = 'DNSDB.Record'
        expected_outputs = [
            {
                'Count': 5059,
                'RRName': 'www.farsightsecurity.com',
                'RRType': 'A',
                'RData': ['66.160.140.81'],
                'Bailiwick': 'farsightsecurity.com',
                'TimeFirst': '2013-09-25T20:02:10Z',
                'TimeLast': '2015-04-01T09:51:39Z',
                'FromZoneFile': False,
            },
            {
                'Count': 17381,
                'RRName': 'farsightsecurity.com',
                'RRType': 'A',
                'Bailiwick': 'com',
                'RData': ['104.244.13.104'],
                'TimeFirst': '2015-04-01T13:07:24Z',
                'TimeLast': '2016-07-12T13:14:32Z',
                'FromZoneFile': True,
            }
        ]

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    @staticmethod
    def _run_test(requests_mock, args: dict, input: list, expected_readable: str, expected_output_prefix: str,
                  expected_outputs: list):
        client = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        requests_mock.get(f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/lookup/rrset/name/{DNSDB.quote(args["owner_name"])}'
                          f'?limit={args["limit"]}'
                          f'&swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
                          text=_saf_wrap(input))

        for v in args.values():
            assert isinstance(v, str)

        res = DNSDB.dnsdb_rrset(client, args)

        assert res.readable_output == expected_readable
        assert res.outputs_prefix == expected_output_prefix
        assert res.outputs == expected_outputs


class TestSummarizeRRSetCommand:
    def test_1a(self, requests_mock):
        args = {
            'owner_name': 'www.farsightsecurity.com',
            'limit': '2',
            'max_count': '5000',
        }
        input = [
            '{"count": 1127, "num_results": 2, "time_first": 1557859313, "time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                ### Farsight DNSDB Summarize
                |Count|NumResults|TimeFirst|TimeLast|
                |---|---|---|---|
                | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                ''')

        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': False,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    def test_zone(self, requests_mock):
        args = {
            'owner_name': 'www.farsightsecurity.com',
            'limit': '10',
            'max_count': '50',
        }
        input = [
            '{"count": 1127, "num_results": 2, "zone_time_first": 1557859313, "zone_time_last": 1560537333}',
        ]

        expected_readable = textwrap.dedent('''\
                        ### Farsight DNSDB Summarize
                        |Count|NumResults|ZoneTimeFirst|ZoneTimeLast|
                        |---|---|---|---|
                        | 1127 | 2 | 2019-05-14T18:41:53Z | 2019-06-14T18:35:33Z |
                        ''')

        expected_output_prefix = 'DNSDB.Summary'
        expected_outputs = {
            'Count': 1127,
            'NumResults': 2,
            'TimeFirst': '2019-05-14T18:41:53Z',
            'TimeLast': '2019-06-14T18:35:33Z',
            'FromZoneFile': True,
        }

        self._run_test(requests_mock, args, input, expected_readable, expected_output_prefix, expected_outputs)

    @staticmethod
    def _run_test(requests_mock, args: dict, input: list, expected_readable: str, expected_output_prefix: str,
                  expected_outputs: dict):
        client = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        requests_mock.get(f'{DNSDB.DEFAULT_DNSDB_SERVER}/dnsdb/v2/summarize/rrset/name/{args["owner_name"]}'
                          f'?limit={args["limit"]}'
                          f'&max_count={args["max_count"]}'
                          f'&swclient={DNSDB.SWCLIENT}&version={DNSDB.VERSION}',
                          text=_saf_wrap(input))

        for v in args.values():
            assert isinstance(v, str)

        res = DNSDB.dnsdb_summarize_rrset(client, args)

        assert res.readable_output == expected_readable
        assert res.outputs_prefix == expected_output_prefix
        assert res.outputs == expected_outputs


class TestRateLimitCommand:
    def test_unlimited(self, requests_mock):
        self._run_test(requests_mock, {
            "rate": {
                "reset": "n/a",
                "limit": "unlimited",
                "remaining": "n/a"
            }
        }, textwrap.dedent('''\
        ### Farsight DNSDB Service Limits
        |Unlimited|
        |---|
        | true |
        '''))

    def test_time_based(self, requests_mock):
        self._run_test(requests_mock, {
            "rate": {
                "reset": 1433980800,
                "limit": 1000,
                "remaining": 999
            }
        }, textwrap.dedent('''\
        ### Farsight DNSDB Service Limits
        |Limit|Remaining|Reset|
        |---|---|---|
        | 1000 | 999 | 2015-06-11T00:00:00Z |
        '''))

    def test_block_based(self, requests_mock):
        self._run_test(requests_mock, {
            "rate": {
                "reset": "n/a",
                "burst_size": 10,
                "expires": 1555370914,
                "burst_window": 300,
                "offset_max": 3000000,
                "results_max": 256,
                "limit": 600,
                "remaining": 8,
            }
        }, textwrap.dedent('''\
        ### Farsight DNSDB Service Limits
        |Limit|Remaining|Reset|NeverResets|Expires|ResultsMax|OffsetMax|BurstSize|BurstWindow|
        |---|---|---|---|---|---|---|---|---|
        | 600 | 8 |  | true | 2019-04-15T23:28:34Z | 256 | 3000000 | 10 | 300 |
        '''))

    @staticmethod
    def _run_test(requests_mock, input: dict, expected_readable: str):
        client = DNSDB.Client(DNSDB.DEFAULT_DNSDB_SERVER, '')
        requests_mock.get(
            '{server}/dnsdb/v2/rate_limit?swclient={swclient}&version={version}'.format(
                server=DNSDB.DEFAULT_DNSDB_SERVER,
                swclient=DNSDB.SWCLIENT,
                version=DNSDB.VERSION,
            ), json=input)

        # The context is tested in TestBuildLimitsContext
        res = DNSDB.dnsdb_rate_limit(client, None)
        assert res.readable_output == expected_readable
        assert res.outputs_prefix == 'DNSDB.Rate'
        assert isinstance(res.outputs, dict)


class TestParseRData:
    def test_idna(self):
        assert DNSDB.parse_rdata("10 mx.xn--frsight-exa.com.") == "10 mx.fårsight.com."

    def test_idna_multi(self):
        soa = DNSDB.parse_rdata(
            "xn--frsightscurity-lib5e.com.  SOA  fsi.io. hostmaster.xn--frsight-exa.xn--scurity-bya.com. "
            "2014081222 7200 3600 604800 3600")
        assert soa == "fårsightsécurity.com.  SOA  fsi.io. hostmaster.fårsight.sécurity.com. 2014081222 7200 3600 " \
                      "604800 3600"

    def test_idna_spf(self):
        assert DNSDB.parse_rdata("include:xn--frsight-exa.com.") == "include:fårsight.com."

    def test_idna_dkim(self):
        assert DNSDB.parse_rdata("d=xn--frsight-exa.com.") == "d=fårsight.com."

    def test_idna_email(self):
        assert DNSDB.parse_rdata("test@xn--frsight-exa.com.") == "test@fårsight.com."


def _saf_wrap(records):
    return '\n'.join(
        ['{"cond":"begin"}'] + [f'{{"obj":{r}}}' for r in records] + ['{"cond":"succeeded"}']
    )
