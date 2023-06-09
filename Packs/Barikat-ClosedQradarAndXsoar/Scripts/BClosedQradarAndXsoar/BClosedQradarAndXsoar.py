import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Bu script Halim ONUR tarafından 06/06/2023 tarihinde yazılmıştır.


def close_investigation_and_qradar_offense():
    # Get Investigation kısmı
    current_investigation_id = demisto.investigation()['id']

    # Kapatılacak notu gir
    note = demisto.args().get('note')

    # Incident ı kapatmak için gerekli adımmlar
    close_params = {
        'id': current_investigation_id,
        'status': 'Closed'
    }

    try:
        # Incident kapatılıyor
        demisto.executeCommand('CloseInvestigation', close_params)
        demisto.results('Incident başarıyla kapatıldı.')

        # Notu XSOAR'daki Incident a ekle
        demisto.executeCommand('setIncident', {'closeNotes': note})
        demisto.results('Not, incident a başarıyla eklendi.')
    except Exception as e:
        demisto.error(f'incident kapatılırken bir hata oluştu: {str(e)}')

    try:
        # QRadar offense'ını kapatmak için gerekli parametrele
        incident = demisto.incident()
        qradar_close_params = {
            'offense_id': incident.get('CustomFields', {}).get('alertid', ''),
            'status': 'CLOSED',
            'closing_reason_id': '2'
        }

        # QRadar offense'ını kapat
        demisto.executeCommand('qradar-offense-update', qradar_close_params)
        demisto.results('QRadar offense\'ı başarıyla kapatıldı.')

        # Notu QRadar offense'ına ekle
        qradar_note_params = {
            # 'offense_id': qradar_close_params['id'],
            'offense_id': incident.get('CustomFields', {}).get('alertid', ''),
            'note_text': note
        }
        demisto.executeCommand('qradar-offense-note-create', qradar_note_params)
        demisto.results('Not, QRadar offense\'ına başarıyla eklendi.')
    except Exception as e:
        demisto.error(f'QRadar offense\'ı kapatılırken bir hata oluştu: {str(e)}')


# Main modul
close_investigation_and_qradar_offense()
