import pytest

from dw_send_trustar_data_to_intsights_copy import *

import trustar
from trustar.models.indicator import Indicator
from trustar.models.report import Report

import demistomock as demisto

'''
@pytest.fixture
def ts():
    client = TruStar(config={
        'auth_endpoint': "test auth endpoint",
        'api_endpoint': "test api endpoint",
        'user_api_key': "test api key",
        'user_api_secret': "test api secret",
        'enclave_ids': "enclave id",
        'client_metatag': "test metatag"
    })
    return client
'''


@pytest.fixture
def mockIOCReports(mocker):
    return mocker.MagicMock(
        items=[
            Report(
                id="1",
                title="Test Report",
                body="Test Body",
            )
        ]
    )


@pytest.fixture
def mockIOCIndicators(mocker):
    return mocker.Mock(
        items=[
            Indicator(
                type="SHA256",
                value="a127d88fb73f8f1a3671557f3084d02d981396d5f5218163ef26d61314ced3c1"
            ),
            Indicator(
                type="URL",
                value="www.testUrl.com"
            ),
            Indicator(
                type="EMAIL_ADDRESS",
                value="jerryattom.com"
            ),
            Indicator(
                type="Software",
                value="mousecatcher.zip"
            ),
            Indicator(
                type="MD5",
                value="ebe8d3087f600c304df0067b6588"
            ),
            Indicator(
                type="IP",
                value="123.346.789.343"
            ),
            Indicator(
                type="IP",
                value="56l.34.08.33"
            ),
            Indicator(
                type="URL",
                value="www.notawebsite.com"
            )
        ]
    )

@pytest.fixture
def mockUncleanIndicators(mocker):
    return mocker.Mock(
        items=[
            {
                "indicatorType":"SHA256",
                "value": "a127d88fb73f8f1a3671557f3084d02d981396d5f5218163ef26d61314ced3c1"
            },
            {
                "indicatorType": "URL",
                "value": "www.testUrl.com"
            },
            {
                "indicatorType": "EMAIL_ADDRESS",
                "value": "jerryattom.com"
            },
            {
                "indicatorType": "Software",
                "value": "mousecatcher.zip"
            },
            {
                "indicatorType": "MD5",
                "value": "ebe8d3087f600c304df0067b6588"
            },
            {
                "indicatorType": "IP",
                "value": "123.346.789.343"
            },
            {
                "indicatorType": "IP",
                "value": "56l.34.08.33"
            },
            {
                "indicatorType": "URL",
                "value": "www.notawebsite.com"
            }
        ]
    )

def test_get_iocs(mockIOCReports, mockIOCIndicators, monkeypatch):

    def mock_ioc_reports(*args, **kwargs):
        return mockIOCReports

    def mock_ioc_indicators(*args, **kwargs):
        return mockIOCIndicators

    monkeypatch.setattr(trustar.TruStar, "get_reports", mock_ioc_reports)
    monkeypatch.setattr(trustar.TruStar, "get_indicators_for_report", mock_ioc_reports)
    get_ioc_data()


def test_clean_indicator(mockUncleanIndicators, monkeypatch):

    def mock_unclean_data(*args, **kwargs):
        return mockIOCIndicators()

    cleanData([
            {
                "indicatorType":"SHA256",
                "value": "a127d88fb73f8f1a3671557f3084d02d981396d5f5218163ef26d61314ced3c1"
            },
            {
                "indicatorType": "URL",
                "value": "www.testUrl.com"
            },
            {
                "indicatorType": "EMAIL_ADDRESS",
                "value": "jerryattom.com"
            },
            {
                "indicatorType": "Software",
                "value": "mousecatcher.zip"
            },
            {
                "indicatorType": "MD5",
                "value": "ebe8d3087f600c304df0067b6588"
            },
            {
                "indicatorType": "IP",
                "value": "123.346.789.343"
            },
            {
                "indicatorType": "IP",
                "value": "56l.34.08.33"
            },
            {
                "indicatorType": "URL",
                "value": "www.notawebsite.com"
            }
        ])


def test_send_data_intsights(monkeypatch):
    class GetMockResponse(object):
        def __init__(self,url,**kwargs):
            self.status_code = 200

        def json(self):
            return {'Files': []}

        def raise_for_status(self):
            pass

    class PostMockResponse(object):
        def __init__(self,url,**kwargs):
            self.status_code = 200

        def json(self):
            return {'Files': [{"Name": "Testing", "_id": "1234567891"}]}

        def raise_for_status(self):
            pass

    class DeleteMockResponse(object):
        def __init__(self,url,**kwargs):
            self.status_code = 200

        def json(self):
            return {'Files': []}

        def raise_for_status(self):
            pass

    def mock_get(url, headers):
        return GetMockResponse(url)

    def mock_post(url, data, headers):
        return PostMockResponse(url)
    
    def mock_delete(url, headers):
        return DeleteMockResponse(url)
    monkeypatch.setattr(requests, 'get', mock_get)
    monkeypatch.setattr(requests, 'post', mock_post)
    monkeypatch.setattr(requests, 'delete', mock_delete)
    sendData([{
                "indicatorType": "IP",
                "value": "123.346.789.343"
            },
            {
                "indicatorType": "IP",
                "value": "56l.34.08.33"
            },
            {
                "indicatorType": "URL",
                "value": "www.notawebsite.com"
            }], "Testing")