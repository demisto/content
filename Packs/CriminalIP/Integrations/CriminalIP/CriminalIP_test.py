# -*- coding: utf-8 -*-

import json
from freezegun import freeze_time
import CriminalIP  # 같은 폴더의 통합 모듈 (CriminalIP.py)

BASE_URL = CriminalIP.BASE_URL


def make_client():
    # 실제 네트워크는 requests_mock이 가로채므로 verify/proxies는 의미 없음
    return CriminalIP.CipApi(BASE_URL, api_key="DUMMY", verify=False, proxies={}, timeout=5)


def test_ip_report_ok(requests_mock):
    """
    /v1/asset/ip/report 엔드포인트를 모킹하고,
    criminal-ip-ip-report 명령의 실제 함수(get_ip_report)를 호출해 결과(raw_response)를 확인한다.
    """
    mocked_json = {
        "score": {"inbound": "Safe", "outbound": "Safe"},
        "protected_ip": {"count": 0, "data": []},
        "issues": {}
    }
    requests_mock.get(f"{BASE_URL}/v1/asset/ip/report", json=mocked_json)

    cip = make_client()
    res = CriminalIP.get_ip_report(cip, {"ip": "8.8.8.8"})

    # CommandResults 형태 여부 대신 핵심 필드만 검증
    assert res.raw_response == mocked_json
    assert "Criminal IP - IP Report" in res.readable_output


@freeze_time("2025-08-11 12:00:00")
def test_check_last_scan_date_recent(requests_mock):
    """
    /v1/domain/reports 응답을 최근(7일 이내) 스캔이 있는 것으로 모킹하고,
    check_last_scan_date 로직이 scanned=True 및 scan_id 반환하는지 확인한다.
    """
    mocked_json = {
        "data": {
            "count": 1,
            "reports": [
                {
                    "reg_dtime": "2025-08-10 09:00:00",  # 고정 시간 기준으로 7일 이내
                    "scan_id": "SCAN123"
                }
            ]
        }
    }
    requests_mock.get(f"{BASE_URL}/v1/domain/reports", json=mocked_json)

    cip = make_client()
    res = CriminalIP.check_last_scan_date(cip, {"domain": "example.com"})

    assert res.outputs["scanned"] is True
    assert res.outputs["scan_id"] == "SCAN123"
    assert "Scan result in 7 days." in res.readable_output
