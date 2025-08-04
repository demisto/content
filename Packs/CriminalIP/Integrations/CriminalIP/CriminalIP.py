import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import requests
import datetime

""" CONSTANTS """
BASE_URL = "https://api.criminalip.io/"

""" CIP Client Class """
class CipApi:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

def get_ip_report(cip: CipApi, args: Dict) -> CommandResults: # ip
    """
    Criminal IP API의 '/v1/ip/{ip}' 엔드포인트 호출.
    """
    ip = args.get("ip")

    url = f"{cip.base_url}/v1/asset/ip/report"
    headers = {"x-api-key": cip.api_key}
    param = {
        "ip": ip,
        "full": "true"
    }
    
    response = requests.request("GET", url, headers=headers, params=param)
    
    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.IP",
        outputs_key_field="ip",
        outputs=response.json()
    )

def check_malicious_ip(cip: CipApi, args: Dict) -> CommandResults: # ip
    """
    Criminal IP API의 '/v1/ip/{ip}' 엔드포인트 호출.
    malicious 여부를 확인한다.
    """
    ip = args.get("ip")
    enable_vpn = args.get("enable_vpn", True)
    enable_cloud = args.get("enable_cloud", True)
    enable_tor = args.get("enable_tor", True)
    enable_proxy = args.get("enable_proxy", True)
    enable_hosting = args.get("enable_hosting", True)
    enable_mobile = args.get("enable_mobile", True)
    enable_darkweb = args.get("enable_darkweb", True)
    enable_scanner = args.get("enable_scanner", True)
    enable_snort = args.get("enable_snort", True)
    enable_anonymous_vpn = args.get("enable_anonymous_vpn", True)

    malicious_flag = False

    url = f"{cip.base_url}/v1/asset/ip/report"
    headers = {"x-api-key": cip.api_key}
    param = {
        "ip": ip,
        "full": "true"
    }
    response = requests.request("GET", url, headers=headers, params=param)
    data = response.json()

    score = data.get("score", {})
    inbound = score.get("inbound", {})
    outbound = score.get("outbound", {})
    if inbound == "Dangerous" or inbound == "Critical":
        malicious_flag = True
    if outbound == "Dangerous" or outbound == "Critical":
        malicious_flag = True

    real_ip = data.get("protected_ip", {})
    real_ip_cnt = real_ip.get("count", 0)
    real_ip_list = real_ip.get("data", [])
    if real_ip_cnt > 0:
        malicious_flag = True
    issue = data.get("issues", {})
    if enable_vpn and issue.get("is_vpn", False):
        malicious_flag = True 
    if enable_cloud and issue.get("is_cloud", False):
        malicious_flag = True
    if enable_tor and issue.get("is_tor", False):
        malicious_flag = True
    if enable_proxy and issue.get("is_proxy", False):
        malicious_flag = True
    if enable_hosting and issue.get("is_hosting", False):
        malicious_flag = True
    if enable_mobile and issue.get("is_mobile", False):
        malicious_flag = True
    if enable_darkweb and issue.get("is_darkweb", False):
        malicious_flag = True
    if enable_scanner and issue.get("is_scanner", False):
        malicious_flag = True
    if enable_snort and issue.get("is_snort", False):
        malicious_flag = True
    if enable_anonymous_vpn and issue.get("is_anonymous_vpn", False):
        malicious_flag = True
    
    return CommandResults(
        readable_output=f"Malicious IP: {malicious_flag}, real_ip_list: {real_ip_list}",
        outputs_prefix="CriminalIP.Mal_IP",
        outputs_key_field="mal_ip",
        outputs={"ip": ip, "malicious": malicious_flag, "real_ip_list": real_ip_list}
    )

def domain_quick_scan(cip: CipApi, args: Dict) -> CommandResults: # domain
    """
    Criminal IP API의 '/v1/domain/quick/hash/view' 엔드포인트 호출.
    """
    domain = args.get("domain")

    url = f"{cip.base_url}/v1/domain/quick/hash/view"
    headers = {"x-api-key": cip.api_key}
    param = {
        "domain": domain
    }
    
    response = requests.request("GET", url, headers=headers, params=param)
    
    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Domain_Quick",
        outputs_key_field="domain_quick",
        outputs=response.json()
    )

def domain_lite_scan(cip: CipApi, args: Dict) -> CommandResults: # domain
    """
    Criminal IP API의 '/v1/domain/lite/hash/view' 엔드포인트 호출.
    """
    domain = args.get("domain")

    url = f"{cip.base_url}/v1/domain/lite/scan"
    headers = {"x-api-key": cip.api_key}
    param = {
        "query": domain
    }
    response = requests.request("GET", url, headers=headers, params=param)

    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Domain_Lite",
        outputs_key_field="domain_lite",
        outputs=response.json()
    )

def domain_lite_scan_status(cip: CipApi, args: Dict) -> CommandResults: # scan_id
    """
    Criminal IP API의 '/v1/domain/scan/status' 엔드포인트 호출.
    """
    scan_id = args.get("scan_id")

    url = f"{cip.base_url}/v1/domain/lite/progress"
    headers = {"x-api-key": cip.api_key}
    param = {
        "scan_id": scan_id
    }
    response = requests.request("GET", url, headers=headers, params=param)

    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Domain_Lite_Status",
        outputs_key_field="domain_lite_status",
        outputs=response.json()
    )

def domain_lite_scan_result(cip: CipApi, args: Dict) -> CommandResults: # scan_id
    """
    Criminal IP API의 '/v1/domain/lite/reports' 엔드포인트 호출.
    """
    scan_id = args.get("scan_id")

    url = f"{cip.base_url}/v1/domain/lite/report/{scan_id}"
    headers = {"x-api-key": cip.api_key}

    response = requests.request("GET", url, headers=headers)

    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Domain_Lite_Result",
        outputs_key_field="domain_lite_result",
        outputs=response.json()
    )

def check_last_scan_date(cip: CipApi, args: Dict) -> CommandResults: # domain
    """
    CIP의 /v1/domain/reports 이용해서 7일 이내 스캔 결과 있는지 확인
    7일 이내에 있는지 True or False 및 scan_id 반환
    """
    domain = args.get("domain")

    url = f"{cip.base_url}/v1/domain/reports"
    headers = {"x-api-key": cip.api_key}
    param = {
        "query": domain,
        "offset": 0
    }
    response = requests.request("GET", url, headers=headers, params=param)
    data = response.json()
    count = data.get("data", {}).get("count", 0)
    if count == 0:
        return CommandResults(
            readable_output="No scan result in 7 days",
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_date",
            outputs={"scaned": False, "scan_id": ""}
        )
    report = data.get("data", {}).get("reports", [])[0]
    reg_dtime = report.get("reg_dtime", "")
    scan_id = report.get("scan_id", "")

    cur_time = datetime.datetime.now()
    if  (cur_time - datetime.datetime.strptime(reg_dtime, "%Y-%m-%d %H:%M:%S")).days > 7:
        return CommandResults(
            readable_output="No scan result in 7 days",
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_date",
            outputs={"scaned": False, "scan_id": scan_id},
        )
    else:
        return CommandResults(
            readable_output="Scan result in 7 days",
            outputs_prefix="CriminalIP.Scan_Date",
            outputs_key_field="scan_date",
            outputs={"scaned": True, "scan_id": scan_id},
        )

def domain_full_scan(cip: CipApi, args: Dict) -> CommandResults: # domain
    """
    CIP의 /v1/domain/scan 이용해서 full scan 수행
    """
    domain = args.get("domain")

    url = f"{cip.base_url}/v1/domain/scan"
    headers = {"x-api-key": cip.api_key}

    payload = {"query": domain}
    response = requests.request("POST", url, headers=headers, data=payload)
    
    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Full_Scan",
        outputs_key_field="full_scan",
        outputs=response.json()
    )

def domain_full_scan_status(cip: CipApi, args: Dict) -> CommandResults: # scan_id
    """
    CIP의 /v1/domain/status/{id} 이용해서 full scan 상태 확인
    """
    scan_id = args.get("scan_id")

    url = f"{cip.base_url}/v1/domain/status/{scan_id}"
    headers = {"x-api-key": cip.api_key}

    response = requests.request("GET", url, headers=headers)

    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Full_Scan_Status",
        outputs_key_field="full_scan_status",
        outputs=response.json()
    )

def domain_full_scan_result(cip: CipApi, args: Dict) -> CommandResults: # scan_id
    """
    CIP의 /v1/domain/reports 이용해서 full scan 결과 확인
    """
    scan_id = args.get("scan_id")

    url = f"{cip.base_url}/v2/domain/report/{scan_id}"
    headers = {"x-api-key": cip.api_key}
    payload = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    return CommandResults(
        readable_output=response.json(),
        outputs_prefix="CriminalIP.Full_Scan_Result",
        outputs_key_field="full_scan_result",
        outputs=response.json()
    )
    
def make_email_body(cip: CipApi, args: Dict) -> CommandResults:
    """
    리포트 결과를 이메일로 전송하기 위한 body 생성
    """
    domain = args.get("domain")
    scan_id = args.get("scan_id")

    url = f"{cip.base_url}/v2/domain/report/{scan_id}"
    headers = {"x-api-key": cip.api_key}
    payload = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    data = response.json()["data"]
    #? summary 의 URL 부분에서 0이나 False 가 아닌 것들
    body_element = []
    url_with_ip = data.get("summary", {}).get("connect_to_ip_directly", 0)
    if url_with_ip != 0:
        body_element.append(f"URL with IP : {url_with_ip}")
    suspicious_length = data.get("summary", {}).get("overlong_domain", False)
    if suspicious_length != False:
        body_element.append(f"Suspicious Length : {suspicious_length}")
    url_with_at = url_with_ip = data.get("summary", {}).get("symbol_url", False)
    if url_with_at != False:
        body_element.append(f"URL with @ : {url_with_at}")
    url_with_multiple_http = data.get("summary", {}).get("fake_https_url", False)
    if url_with_multiple_http != False:
        body_element.append(f"URL with multiple http : {url_with_multiple_http}")
    url_with_punycode = data.get("summary", {}).get("punycode", False)
    if url_with_punycode != False:
        body_element.append(f"URL with punycode : {url_with_punycode}")
    prob_of_phishing_url = data.get("summary", {}).get("url_phishing_prob", 0.0)
    if prob_of_phishing_url > 0.0:
        body_element.append(f"Probability of Phishing URL : {prob_of_phishing_url}")
    dga_score = data.get("summary", {}).get("dga_score", 0.0)
    if dga_score >= 8.0:
        body_element.append(f"DGA Score : {dga_score}")
    
    #? Summary 의 Common 부분
    fake_domain = data.get("summary", {}).get("fake_domain", False)
    if fake_domain != False:
        body_element.append(f"Fake Domain : {fake_domain}")
    invalid_ssl = data.get("summary", {}).get("fake_ssl", {}).get("invalid", False)
    if invalid_ssl != False:
        body_element.append(f"Invalid SSL : {invalid_ssl}")
    mitm_attack = data.get("summary", {}).get("mitm_attack", False)
    if mitm_attack != False:
        body_element.append(f"MITM Attack : {mitm_attack}")
    locations = data.get("summary", {}).get("locations", [])
    if "CN" in locations:
        body_element.append(f"Locations : {locations}")
    newborn_domain = data.get("summary", {}).get("newborn_domain", "")
    if newborn_domain != "":
        newborn_domain_date = datetime.datetime.strptime(newborn_domain, "%Y-%m-%d")
        cur_date = datetime.datetime.now()
        if (cur_date - newborn_domain_date).days < 30:
            body_element.append(f"Newborn Domain : {newborn_domain}")
    #// abuse_record 데이터 없음
    phishing_record = data.get("summary", {}).get("phishing_record", 0)
    if phishing_record != 0:
        body_element.append(f"Phishing Record : {phishing_record}")
    mail_server = data.get("summary", {}).get("mail_server", False)
    if mail_server != False:
        body_element.append(f"Mail Server : {mail_server}")
    spam = data.get("summary", {}).get("spf1", "N/A")
    site_reputation = data.get("summary", {}).get("web_traffic", "N/A")
    if spam != "N/A" and spam != "Safe" and site_reputation == "No Rank":
        body_element.append(f"Spam (SPF1 Result) : {spam}")
        body_element.append(f"Site Reputation : {site_reputation}")
    #? Summary 의 HTML 부분
    hidden_element = data.get("summary", {}).get("hidden_element", 0)
    if hidden_element != 0:
        body_element.append(f"Hidden Element : {hidden_element}")
    hidden_iframe = data.get("summary", {}).get("hidden_iframe", 0)
    if hidden_iframe != 0:
        body_element.append(f"Hidden Iframe : {hidden_iframe}")
    iframe = data.get("summary", {}).get("iframe", 0)
    if iframe != 0:
        body_element.append(f"Iframe : {iframe}")
    obfuscated_script = data.get("summary", {}).get("js_obfuscated", 0)
    if obfuscated_script != 0:
        body_element.append(f"Obfuscated Script : {obfuscated_script}")
    suspicious_html_element = data.get("summary", {}).get("suspicious_element", 0)
    if suspicious_html_element != 0:
        body_element.append(f"Suspicious HTML Element : {suspicious_html_element}")
    suspicious_program = data.get("summary", {}).get("suspicious_file", 0)
    if suspicious_program != 0:
        body_element.append(f"Suspicious Program : {suspicious_program}")
    button_trap = data.get("summary", {}).get("redirection_onclick", "Normal")
    if button_trap != "Normal":
        body_element.append(f"Button Trap : {button_trap}")
    credential_input_form = data.get("summary", {}).get("cred_input", "None")
    if credential_input_form != "None" and credential_input_form != "Safe":
        body_element.append(f"Credential Input Form : {credential_input_form}")
    form_event =  data.get("summary", {}).get("sfh", "Safe")
    if form_event != "Safe":
        body_element.append(f"Form Event : {form_event}")
    fake_favicon = data.get("summary", {}).get("diff_domain_favicon", "Safe")
    if fake_favicon != "Safe":
        body_element.append(f"Fake Favicon : {fake_favicon}")
    page_warning = data.get("summary", {}).get("page_warning", False)
    if page_warning != False:
        body_element.append(f"Page Warning : {page_warning}")
    suspicious_footer = data.get("summary", {}).get("suspicious_footer", False)
    if suspicious_footer != False:
        body_element.append(f"Suspicious Footer : {suspicious_footer}")
    email_domain_check = data.get("summary", {}).get("email_domain_check", False)
    if email_domain_check != False:
        body_element.append(f"Email Domain Check : {email_domain_check}")
    #? Summary 의 Network 부분
    redirection_to_another_as = data.get("summary", {}).get("redirection_diff_asn", 0)
    if redirection_to_another_as != 0:
        body_element.append(f"Redirection to another AS : {redirection_to_another_as}")
    redirection_to_another_country = data.get("summary", {}).get("redirection_diff_country", 0)
    if redirection_to_another_country != 0:
        body_element.append(f"Redirection to another Country : {redirection_to_another_country}")
    redirection_to_another_domain = data.get("summary", {}).get("redirection_diff_domain", 0)
    if redirection_to_another_domain != 0:
        body_element.append(f"Redirection to another Domain : {redirection_to_another_domain}")
    suspicious_cookie = data.get("summary", {}).get("suspicious_cookie", False)
    if suspicious_cookie != False:
        body_element.append(f"Suspicious Cookie : {suspicious_cookie}")
    domain_in_subdomain = data.get("summary", {}).get("subdomain", False)
    if domain_in_subdomain != False:
        body_element.append(f"Domain in Subdomain : {domain_in_subdomain}")
    #? Summary 의 DNS 부분
    #// real_ip 데이터 없음
    associated_ip = data.get("summary", {}).get("associated_ip", "")
    if associated_ip != "":
        body_element.append(f"Associated IP : {associated_ip}")

    #? classification 부분
    google_safe_browsing = data.get("classification", {}).get("google_safe_browsing", [])
    if len(google_safe_browsing) != 0:
        body_element.append(f"Google Safe Browsing : {google_safe_browsing}")
    
    domain_type = data.get("classification", {}).get("domain_type", [])
    for i in domain_type:
        if i["type"] == "malicious":
            body_element.append(f"Domain Type {i['name']} : {i['type']}")
    
    #? Network_logs 부분
    abuse_record = data.get("network_logs", {}).get("abuse_record", {})
    if abuse_record.get("critical", 0) != 0:
        body_element.append(f"Abuse Record Critical : {abuse_record.get('critical', 0)}")
    if abuse_record.get("dangerous", 0) != 0:
        body_element.append(f"Abuse Record Dangerous : {abuse_record.get('dangerous', 0)}")
    network_logs_data = data.get("network_logs", {}).get("data", [])
    network_logs_result_data = []
    for i in network_logs_data:
        if i["url"].endswith(".exe"):
            network_logs_result_data.append(i["url"])
    if len(network_logs_result_data) != 0:
        body_element.append(f"EXE Download URL : {network_logs_result_data}")
    
    if len(body_element) == 0:
        return CommandResults(
            readable_output="No suspicious element found",
            outputs_prefix="CriminalIP.Email_Body",
            outputs_key_field="email_body",
            outputs={"domain": domain, "scan_id": scan_id, "body_element": ""}
        )
    seperator = "\n\t"
    body_element_string = seperator.join(body_element)
    body_element_result = f"Criminal IP Domain Search Result({domain}) : {seperator}{body_element_string}"
    
    return CommandResults(
        readable_output=body_element_result,
        outputs_prefix="CriminalIP.Email_Body",
        outputs_key_field="email_body",
        outputs={"domain": domain, "scan_id": scan_id, "body_element": body_element_result}
    )


def micro_asm(cip: CipApi, args: Dict) -> CommandResults:
    def result_string_indexing(x): 
        return f"{x[0]} : {x[1]}"
    scan_id = args.get("scan_id")
    domain = args.get("domain")
    url = f"{cip.base_url}/v2/domain/report/{scan_id}"
    headers = {"x-api-key": cip.api_key}
    payload = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    domain_report = response.json()["data"]
    result_element = []
    # ? Mapped IP 확인
    # ? CVE 가 나오면 알려주기
    # ? IP를 점검해봐서 80/443 말고 열린 포트가 있으면 알려주기
    mapped_ips = domain_report.get("mapped_ip", [])
    open_ports_result = {}
    cve_result = {}
    seperator = "\n\t"
    for ip_data in mapped_ips:
        param = {
            "ip": ip_data["ip"],
            "full": "true"
        }
        url = f"{cip.base_url}/v1/asset/ip/report/summary"
        headers = {
            "x-api-key": cip.api_key
        }
        response = requests.request("GET", url, headers=headers, params=param)
        ip_report = response.json()
        open_ports = ip_report.get("current_open_ports", {}).get(
            "TCP", []) + ip_report.get("current_open_ports", {}).get("UDP", [])
        open_ports_temp = []
        cve_temp = []
        for open_port in open_ports:
            if open_port["port"] not in [80, 443]:
                open_ports_temp.append(open_port["port"])
            if open_port["has_vulnerability"] == True:
                cve_temp.append(open_port["port"])
        if len(open_ports_temp) != 0:
            open_ports_result[ip_data["ip"]] = open_ports_temp
        if len(cve_temp) != 0:
            cve_result[ip_data["ip"]] = cve_temp
    if len(open_ports_result) != 0:
        ip_port = list(zip(open_ports_result.keys(), open_ports_result.values()))
        open_ports_result = list(map(result_string_indexing, ip_port))
        result_element.append(
            f"open ports other than standard HTTP/HTTPS (80/443) : \n\t{seperator.join(open_ports_result)}")
    if len(cve_result) != 0:
        ip_cve_port = list(zip(cve_result.keys(), cve_result.values()))
        cve_result = list(map(result_string_indexing, ip_cve_port))
        result_element.append(
            f"Ports exposing services with known CVEs : \n\t{seperator.join(cve_result)}")

    # ? Certicate 만료 1개월 이내
    certificates = domain_report.get("certificates", [])
    certificate_expiration_result = []
    for cert in certificates:
        valid_to_data = cert.get("valid_to", "")
        if valid_to_data != "":
            valid_to = datetime.datetime.strptime(
                valid_to_data, "%Y-%m-%d %H:%M:%S")
            cur_date = datetime.datetime.now()
            if (valid_to - cur_date).days < 30:
                certificate_expiration_result.append(cert)
    if len(certificate_expiration_result) != 0:
        certificate_expiration_result = list(
            map(str, certificate_expiration_result))
        result_element.append(
            f"Certificates expiring in less than 30 days : \n\t{seperator.join(certificate_expiration_result)}")

    # ? Abuse records
    abuse_records = domain_report.get("network_logs", {}).get("abuse_record", {})
    abuse_records_critical = abuse_records.get("critical", 0)
    abuse_records_dangerous = abuse_records.get("dangerous", 0)
    if abuse_records_critical != 0 or abuse_records_dangerous != 0:
        result_element.append(
            f"Abuse records : \n\tCritical : {abuse_records_critical} \n\tDangerous : {abuse_records_dangerous}")

    # ? network_logs Critical, Dangerous IP, EXE exsit
    network_logs = domain_report.get("network_logs", {}).get("data", [])
    network_logs_ip = []
    network_logs_exe = []
    for network_log in network_logs:
        if network_log["score"] == "critical" or network_log["score"] == "dangerous":
            network_logs_ip.append(network_log)
        if network_log["url"].endswith(".exe"):
            network_logs_exe.append(network_log)
    if len(network_logs_ip) != 0:
        network_logs_ip = list(map(str, network_logs_ip))
        result_element.append(
            f"Critical/Dangerous IP in network logs : \n\t{seperator.join(network_logs_ip)}")
    if len(network_logs_exe) != 0:
        network_logs_exe = list(map(str, network_logs_exe))
        result_element.append(
            f"EXE file in network logs : \n\t{seperator.join(network_logs_exe)}")

    # ? File Exposure
    file_exposure = domain_report.get("file_exposure", {})
    file_exposure_result = []
    if file_exposure.get("apache_status", False) == True:
        file_exposure_result.append("apache_status")
    if file_exposure.get("docker_registry", False) == True:
        file_exposure_result.append("docker_registry")
    if file_exposure.get("ds_store", False) == True:
        file_exposure_result.append("ds_store")
    if file_exposure.get("firebase", False) == True:
        file_exposure_result.append("firebase")
    if file_exposure.get("git_config", False) == True:
        file_exposure_result.append("git_config")
    if file_exposure.get("json_config", False) == True:
        file_exposure_result.append("json_config")
    if file_exposure.get("phpinfo", False) == True:
        file_exposure_result.append("phpinfo")
    if file_exposure.get("vscode_sftp_json", False) == True:
        file_exposure_result.append("vscode_sftp_json")
    if file_exposure.get("wordpress", False) == True:
        file_exposure_result.append("wordpress")

    if len(file_exposure_result) != 0:
        result_element.append(
            f"File exposure in HTML : \n\t{', '.join(file_exposure_result)}")
    if len(result_element) == 0:
        return CommandResults(
            readable_output="No suspicious element found",
            outputs_prefix="CriminalIP.Micro_ASM",
            outputs_key_field="micro_asm",
            outputs={"scan_id": scan_id, "result": ""}
        )
    header = f"======== {domain}  ========"
    result_element_string = f"{header}\n"
    result_element_string += "\n".join(result_element)
    result_element_string += "\n" + "=" * len(header)  
    
    return CommandResults(
        readable_output=result_element_string,
        outputs_prefix="CriminalIP.Micro_ASM",
        outputs_key_field="micro_asm",
        outputs={"domain": domain, "scan_id": scan_id, "result": result_element_string}
    )
    

def main() -> None:
    params = demisto.params()
    command = demisto.command()
    
    api_key = params.get("api_key", "")
    cip = CipApi(BASE_URL, api_key)
    
    try:
        if command == "ip-report":  #!
            return_results(get_ip_report(cip, demisto.args()))
        elif command == "check-malicious-ip": #!
            return_results(check_malicious_ip(cip, demisto.args()))
        elif command == "domain-quick-scan": #!
            return_results(domain_quick_scan(cip, demisto.args()))
        elif command == "domain-lite-scan": #! 
            return_results(domain_lite_scan(cip, demisto.args()))
        elif command == "domain-lite-scan-status": #!
            return_results(domain_lite_scan_status(cip, demisto.args()))
        elif command == "domain-lite-scan-result": #!
            return_results(domain_lite_scan_result(cip, demisto.args()))
        elif command == "check-last-scan-date": #! 
            return_results(check_last_scan_date(cip, demisto.args()))
        elif command == "domain-full-scan": #!
            return_results(domain_full_scan(cip, demisto.args()))
        elif command == "domain-full-scan-status":
            return_results(domain_full_scan_status(cip, demisto.args()))
        elif command == "domain-full-scan-result":
            return_results(domain_full_scan_result(cip, demisto.args()))
        elif command == "domain-full-scan-make-email-body":
            return_results(make_email_body(cip, demisto.args()))
        elif command == "micro-asm":
            return_results(micro_asm(cip, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
