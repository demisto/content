import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
from typing import Dict, Any, Tuple, List, Optional
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, username: str, password: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.access_token = None

    def _get_jwt_token(self) -> str:
        headers = {
            'username': self.username,
            'password': self.password,
            'Accept': 'application/json'
        }
        response = self._http_request(
            method='POST',
            url_suffix='/dlp/rest/v1/auth/refresh-token',
            headers=headers,
            resp_type='json',
            ok_codes=(200, 201)
        )
        access_token = response.get('access_token')
        if not access_token:
            raise DemistoException(
                'Forcepoint DLP Kimlik Doğrulama Hatası: Sunucu yanıt verdi ancak geçerli bir access_token döndürmedi.')
        return access_token

    def _authenticated_request(self, method: str, url_suffix: str, json_data: Optional = None, params: Optional = None) -> Any:
        if not self.access_token:
            demisto.debug("Mevcut bir access_token bulunamadı, yeni bir token talep ediliyor.")
            self.access_token = self._get_jwt_token()
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        try:
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                headers=headers,
                json_data=json_data,
                params=params,
                resp_type='json',
                ok_codes=(200, 201)
            )
        except Exception as e:
            error_message = str(e)
            if '401' in error_message or '403' in error_message:
                demisto.debug("Erişim token'ının süresi dolmuş veya geçersiz (401/403). Token yenilenerek istek tekrar edilecek.")
                self.access_token = self._get_jwt_token()
                headers['Authorization'] = f'Bearer {self.access_token}'
                return self._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    headers=headers,
                    json_data=json_data,
                    params=params,
                    resp_type='json',
                    ok_codes=(200, 201)
                )
            else:
                raise e

    def get_incidents(self, incident_type: str = "INCIDENTS", from_date: Optional[str] = None, to_date: Optional[str] = None, incident_ids: Optional[List[int]] = None) -> Dict:
        payload: Dict[str, Any] = {"type": incident_type}
        if incident_ids:
            payload["ids"] = incident_ids
        elif from_date and to_date:
            payload["from_date"] = from_date
            payload["to_date"] = to_date
        else:
            raise ValueError("ID veya Tarih aralığı belirtilmelidir.")
        return self._authenticated_request(method='POST', url_suffix='/dlp/rest/v1/incidents', json_data=payload)

    def update_incident(self, incident_ids: List[str], status: str) -> Dict:
        payload = {
            "incident_ids": incident_ids,
            "status": status
        }
        return self._authenticated_request(method='POST', url_suffix='/dlp/rest/v1/incidents/update', json_data=payload)

    def list_policies(self, policy_type: str) -> Dict:
        return self._authenticated_request(method='GET', url_suffix='/dlp/rest/v1/policy/enabled-names', params={'type': policy_type})

    def get_policy_rules(self, policy_name: str) -> Dict:
        return self._authenticated_request(method='GET', url_suffix='/dlp/rest/v1/policy/rules', params={'policyName': policy_name})


def test_module(client: Client) -> str:
    try:
        client._get_jwt_token()
        return 'ok'
    except Exception as e:
        return f"Bağlantı veya Kimlik Doğrulama Hatası. Detay: {str(e)}"


def get_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_ids_str = args.get('incident_ids')
    from_date = args.get('from_date')
    to_date = args.get('to_date')
    incident_type = args.get('type', 'INCIDENTS')

    incident_ids = None
    if incident_ids_str:
        incident_ids = [int(x.strip()) for x in incident_ids_str.split(',') if x.strip().isdigit()]

    if not incident_ids and not (from_date and to_date):
        raise DemistoException(
            "Eksik Parametre: API sorgusu için 'incident_ids' VEYA ('from_date' ve 'to_date') argümanları girilmelidir.")

    response = client.get_incidents(
        incident_type=incident_type,
        from_date=from_date,
        to_date=to_date,
        incident_ids=incident_ids
    )

    incidents = response.get('incidents',)

    if not incidents:
        return CommandResults(readable_output="Belirtilen kriterlere uygun Forcepoint olayı bulunamadı.")
    # ---------------------------------------------------------------------------------
    # DEBUG BÖLÜMÜ: XSOAR War Room'a gelen ham veriyi görmek için ilk olayı yazdırıyoruz.
    # Bu sayede policy ve match alanlarının API'den tam olarak hangi isimle geldiğini tespit edebilirsiniz.
    # ---------------------------------------------------------------------------------
    demisto.debug(f"Forcepoint Ilk Olay Ham JSON: {json.dumps(incidents)}")

    table_data = []
    for inc in incidents:
        source = inc.get('source', {})
        if isinstance(source, str):
            user = source
            computer = inc.get('host_name', '')
            source_str = source
        else:
            user = source.get('user_name', inc.get('user_name', ''))
            computer = source.get('host_name', inc.get('host_name', ''))
            ip = source.get('ip_address', '')
            source_str = f"User: {user} | Host: {computer} | IP: {ip}".strip(" |")

        destinations = inc.get('destinations', inc.get('destination', ''))
        dest_str = str(destinations) if destinations else 'N/A'
        file_name = inc.get('file_name', inc.get('file', 'N/A'))
        transaction_size = inc.get('transaction_size', inc.get('file_size', inc.get('size', 'N/A')))
        max_matches = inc.get('maximum_matches', inc.get('match_count', 'N/A'))

        # ALTERNATİF KEY ARAMALARI: Forcepoint'in farklı versiyonlarında dönebilecek olası isimler eklendi
        policy_info = inc.get('policy_name', inc.get('policies', inc.get('matched_policies', inc.get('rule_name', 'N/A'))))
        matches = inc.get('maximum_matches', inc.get('violation_details', inc.get('classifiers', inc.get('forensics', 'N/A'))))

        table_data.append({
            'Incident ID': inc.get('incident_id', inc.get('id', '')),
            'Incident Time': inc.get('time', inc.get('insert_date', inc.get('date', ''))),
            'Source': source_str,
            'Policies': str(policy_info),
            'Channel': inc.get('channel', inc.get('data_channel', '')),
            'Destination': dest_str,
            'Severity': inc.get('severity', ''),
            'Action': inc.get('action', inc.get('action_type', '')),
            'Max Matches': max_matches,
            'Transaction Size': transaction_size,
            'FileName': file_name,
            'Violation Triggers': str(matches) if matches else 'N/A'
        })

    # Tablo ve RAW veriyi War Room'a yansıt
    readable_output = tableToMarkdown(f"Forcepoint DLP Olay Detayları ({len(incidents)} Kayıt)", table_data, removeNull=True)
    # Sorunu tespit edebilmek için ham JSON çıktısını geçici olarak readable_output'a ekleyebiliriz:
    # readable_output += f"\n\n### API'den Gelen Ham Veri (Örnek İlk Kayıt)\n```json\n{json.dumps(incidents, indent=4)}\n```"

    return CommandResults(
        outputs_prefix='ForcepointDLP.Incident',
        outputs_key_field='incident_id',
        outputs=incidents,
        readable_output=readable_output,
        raw_response=response
    )


def update_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_ids = argToList(args.get('incident_ids'))
    status = args.get('status')
    if not incident_ids or not status:
        raise DemistoException("Zorunlu Parametre Eksik: En az bir 'incident_ids' ve hedef 'status' belirtilmelidir.")
    response = client.update_incident(incident_ids, status)
    readable_output = tableToMarkdown(f"Forcepoint DLP Durum Güncelleme: {status}", response, removeNull=True)
    return CommandResults(
        outputs_prefix='ForcepointDLP.UpdateResponse',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


def list_policies_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    policy_type = args.get('type', 'DLP')
    response = client.list_policies(policy_type)
    policies = response.get('enabled_policies',)
    if not policies:
        return CommandResults(readable_output="Sistemde aktif bir politika bulunamadı.")
    table_data = [{"Policy Name": p} for p in policies]
    readable_output = tableToMarkdown(f"Etkin Forcepoint DLP Politikaları (Tip: {policy_type})", table_data)
    return CommandResults(
        outputs_prefix='ForcepointDLP.Policy',
        outputs_key_field='',
        outputs=policies,
        readable_output=readable_output,
        raw_response=response
    )


def get_policy_rules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    policy_name = args.get('policy_name')
    if not policy_name:
        raise DemistoException("Zorunlu Parametre Eksik: Kuralları çekilecek olan 'policy_name' belirtilmelidir.")
    response = client.get_policy_rules(policy_name)
    rules = response.get('rules',)
    if not rules:
        return CommandResults(readable_output=f"'{policy_name}' politikası için herhangi bir kural bulunamadı.")
    readable_output = tableToMarkdown(f"Forcepoint DLP Politika Kuralları ({policy_name})", rules, removeNull=True)
    return CommandResults(
        outputs_prefix='ForcepointDLP.PolicyRule',
        outputs_key_field='rule_name',
        outputs=rules,
        readable_output=readable_output,
        raw_response=response
    )


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    url = params.get('url')
    username = params.get('username')
    password = params.get('password')
    insecure = not params.get('insecure', True)
    proxy = params.get('proxy', False)
    try:
        client = Client(base_url=url, verify=insecure, proxy=proxy, username=username, password=password)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'forcepoint-dlp-get-incidents':
            return_results(get_incidents_command(client, args))
        elif command == 'forcepoint-dlp-update-incident':
            return_results(update_incident_command(client, args))
        elif command == 'forcepoint-dlp-list-policies':
            return_results(list_policies_command(client, args))
        elif command == 'forcepoint-dlp-get-policy-rules':
            return_results(get_policy_rules_command(client, args))
        else:
            raise NotImplementedError(f"'{command}' komutu XSOAR entegrasyonunda tanımlanmamıştır.")
    except Exception as e:
        return_error(f"{command} komutu yürütülürken hata ile karşılaşıldı. Detay: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
