import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime

import dateutil.parser
import pytz

utc = pytz.UTC


class FieldNotFound(Exception):
    pass


def get_duration_html():
    try:
        incident_id = demisto.incident().get('id', {})
        context = demisto.executeCommand("getContext", {'id': incident_id})
        first_date = demisto.get(context[0]['Contents']['context'], "EmailCampaign.firstIncidentDate")

        if not first_date:
            raise FieldNotFound()
        if isinstance(first_date, list):
            first_date = first_date[-1]

        now = datetime.now().replace(tzinfo=utc)
        parsed_first_date: datetime = dateutil.parser.isoparse(first_date).replace(tzinfo=utc)
        diff = now - parsed_first_date

        return f"""
                <table style="margin-left:auto;margin-right:auto;">
                <tr>
                <th style="font-size: 25px;">&#128345;</th>
                <th style="font-size: 30px;">{diff.days}</th>
                <th style="font-size: 30px;">:</th>
                <th style="font-size: 30px;">{(diff.seconds // 3600) % 24}</th>
                <th style="font-size: 30px;">:</th>
                <th style="font-size: 30px;">{(diff.seconds // 60) % 60}</th>
                </tr>
                <tr>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Days</td>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Hours</td>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Minutes</td>
                </tr>
                </table>
        """

    except FieldNotFound:
        return '<div style="text-align: center;">Duration is not available.</div>'
    except Exception as e:
        return_error(f"Error calculating duration\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': get_duration_html()
    })
