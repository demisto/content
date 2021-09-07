from datetime import datetime

import dateutil.parser
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
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
                    <div class="demisto-duration vertical-strech">
                        <div class="duration-widget">
                            <div class="grid-container">
                                <div class="duration-icon"><i class="wait icon home"></i></div>
                                <div class="days-number">{diff.days}</div>
                                <div class="colon center aligned">:</div>
                                <div class="hours-number">{(diff.seconds // 3600) % 24}</div>
                                <div class="colon-2 center aligned">:</div>
                                <div class="one column wide minutes-number">{(diff.seconds // 60) % 60}</div>
                                <div class="days-label time-unit title-h5 opacity-description">DAYS</div>
                                <div class="hours-label time-unit title-h5 opacity-description">HOURS</div>
                                <div class="minutes-label time-unit title-h5 opacity-description">MIN</div>
                            </div>
                        </div>
                    </div>

    """
    except FieldNotFound:
        return '<div style="text-align: center;">Duration is not available.</div>'
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Error calculating duration\n{str(e)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': get_duration_html()
    })
