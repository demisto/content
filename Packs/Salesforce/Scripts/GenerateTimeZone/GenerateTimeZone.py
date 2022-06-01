import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

location_to_timezonesidkey = {
    "kiritimati": "Pacific/Kiritimati",
    "chatham": "Pacific/Chatham",
    "auckland": "Pacific/Auckland",
    "enderbury": "Pacific/Enderbury",
    "fiji": "Pacific/Fiji",
    "tongatapu": "Pacific/Tongatapu",
    "kamchatka": "Asia/Kamchatka",
    "norfolk": "Pacific/Norfolk",
    "lord howe": "Australia/Lord_Howe",
    "sydney": "Australia/Sydney",
    "guadalcanal": "Pacific/Guadalcanal",
    "adelaide": "Australia/Adelaide",
    "darwin": "Australia/Darwin",
    "seoul": "Asia/Seoul",
    "tokyo": "Asia/Tokyo",
    "hong kong": "Asia/Hong_Kong",
    "kuala lumpur": "Asia/Kuala_Lumpur",
    "manila": "Asia/Manila",
    "shanghai": "Asia/Shanghai",
    "singapore": "Asia/Singapore",
    "taipei": "Asia/Taipei",
    "perth": "Australia/Perth",
    "bangkok": "Asia/Bangkok",
    "ho chi minh": "Asia/Ho_Chi_Minh",
    "jakarta": "Asia/Jakarta",
    "rangoon": "Asia/Rangoon",
    "dhaka": "Asia/Dhaka",
    "yekaterinburg": "Asia/Yekaterinburg",
    "kathmandu": "Asia/Kathmandu",
    "colombo": "Asia/Colombo",
    "kolkata": "Asia/Kolkata",
    "karachi": "Asia/Karachi",
    "tashkent": "Asia/Tashkent",
    "kabul": "Asia/Kabul",
    "dubai": "Asia/Dubai",
    "tbilisi": "Asia/Tbilisi",
    "moscow": "Europe/Moscow",
    "tehran": "Asia/Tehran",
    "nairobi": "Africa/Nairobi",
    "baghdad": "Asia/Baghdad",
    "kuwait": "Asia/Kuwait",
    "riyadh": "Asia/Riyadh",
    "minsk": "Europe/Minsk",
    "cairo": "Africa/Cairo",
    "johannesburg": "Africa/Johannesburg",
    "jerusalem": "Asia/Jerusalem",
    "athens": "Europe/Athens",
    "bucharest": "Europe/Bucharest",
    "helsinki": "Europe/Helsinki",
    "istanbul": "Europe/Istanbul",
    "algiers": "Africa/Algiers",
    "amsterdam": "Europe/Amsterdam",
    "berlin": "Europe/Berlin",
    "brussels": "Europe/Brussels",
    "paris": "Europe/Paris",
    "prague": "Europe/Prague",
    "rome": "Europe/Rome",
    "dublin": "Europe/Dublin",
    "lisbon": "Europe/Lisbon",
    "london": "Europe/London",
    "cape verde": "Atlantic/Cape_Verde",
    "sao paulo": "America/Sao_Paulo",
    "south georgia": "Atlantic/South_Georgia",
    "buenos aires": "America/Argentina/Buenos_Aires",
    "santiago": "America/Santiago",
    "st johns": "America/St_Johns",
    "halifax": "America/Halifax",
    "puerto rico": "America/Puerto_Rico",
    "bermuda": "Atlantic/Bermuda",
    "caracas": "America/Caracas",
    "bogota": "America/Bogota",
    "indianapolis": "America/Indiana/Indianapolis",
    "lima": "America/Lima",
    "new york": "America/New_York",
    "panama": "America/Panama",
    "chicago": "America/Chicago",
    "el salvador": "America/El_Salvador",
    "mexico city": "America/Mexico_City",
    "denver": "America/Denver",
    "phoenix": "America/Phoenix",
    "los angeles": "America/Los_Angeles",
    "tijuana": "America/Tijuana",
    "anchorage": "America/Anchorage",
    "honolulu": "Pacific/Honolulu",
    "niue": "Pacific/Niue",
    "pago pago": "Pacific/Pago_Pago",
}

location_default = "America/New_York"


def main():
    try:
        args = demisto.args()
        user_profile = args.get("value")

        location = user_profile.get("location")

        timezonesidkey = location_to_timezonesidkey.get(location)

        if not timezonesidkey:
            timezonesidkey = location_default

        return timezonesidkey

    except Exception as e:
        demisto.log(traceback.format_exc())
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
