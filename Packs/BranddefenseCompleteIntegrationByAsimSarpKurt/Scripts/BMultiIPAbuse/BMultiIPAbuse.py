import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ipaddress
import json

# Cortex XSOAR'dan gelen girdi verisi (IP adres listesi)
sourceip = demisto.incidents()[0].get('CustomFields', {}).get('sourceip', '')

try:
    # Veriyi JSON formatından Python listesine çevirin
    ip_list = json.loads(sourceip)

    valid_ips = []

    for ip_str in ip_list:
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private:
                valid_ips.append(ip_str)
        except ValueError:
            pass

    # AbuseIPDB sorgularını yapma ve sonuçları kontrol etme
    abuseipdb_valid_ips = []  # Sadece AbuseIPDB sorgusu sonucunda bulunan IP adreslerini tutmak için
    for valid_ip in valid_ips:
        response = demisto.executeCommand('ip', {'ip': valid_ip})
        # print(response)
        if response is None:
            demisto.results(f"İşlem başarısız: {valid_ip} için yanıt alınamadı.")
            continue

        for result_entry in response:
            if 'ModuleName' in result_entry and result_entry['ModuleName'] == 'AbuseIPDB_instance_2':
                # AbuseIPDB sorgusu sonucu
                abuseipdb_data = result_entry['Contents'][0]['IP']

                total_reports = abuseipdb_data['TotalReports']
                confidence_score = abuseipdb_data['AbuseConfidenceScore']
                print(confidence_score)
                print(total_reports)
                # Özelleştirilmiş skor koşullarınızı burada ayarlama
                if total_reports > 4 and confidence_score > 10:
                    abuseipdb_valid_ips.append(valid_ip)

    # Sadece AbuseIPDB sorgusu sonucunda bulunan IP adreslerini çıkış alanına JSON olarak ve HumanReadable olarak yazma
    formatted_ips = []
    for index, valid_ip in enumerate(abuseipdb_valid_ips, start=1):
        formatted_ips.append(f"CheckIP_{index}:{valid_ip}")

    if formatted_ips:
        formatted_ips_str = ", ".join(formatted_ips)
        human_readable_output = f"AbuseIPDB sorgusu sonucunda bulunan uygun IP Adresleri:\n{formatted_ips_str}\nCheckIPs:{formatted_ips_str}"
    else:
        human_readable_output = "AbuseIPDB sorgusu sonucunda uygun IP Adresi bulunamadı."

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {"CheckIPs": abuseipdb_valid_ips},
        'HumanReadable': human_readable_output,
        'EntryContext': {
            'CheckIPs': abuseipdb_valid_ips,
            **{f'CheckIP_{index}': valid_ip for index, valid_ip in enumerate(abuseipdb_valid_ips, start=1)}
        }
    })
except json.JSONDecodeError:
    demisto.results("Hatalı JSON verisi: sourceip verisi JSON olarak sağlanmalıdır.")
except Exception as e:
    demisto.results(f"Hata: {str(e)}")
