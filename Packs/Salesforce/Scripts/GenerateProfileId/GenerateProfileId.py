import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

title_to_profile_id = {
    "sales": "123",
    "marketing": "234",
    "engineer": "345"
}


def main():
    try:
        args = demisto.args()
        user_profile = args.get("value")

        title = user_profile.get("title")

        profile_id = title.get(title)
        return profile_id

    except Exception as e:
        demisto.log(traceback.format_exc())
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
