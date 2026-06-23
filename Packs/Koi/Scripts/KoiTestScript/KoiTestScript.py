import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def build_profile(first_name: str, last_name: str, age: int, city: str) -> dict:
    """Build a profile dictionary from the provided arguments.

    Args:
        first_name: The person's first name.
        last_name: The person's last name.
        age: The person's age.
        city: The person's city.

    Returns:
        A dictionary representing the profile.
    """
    return {
        "FullName": f"{first_name} {last_name}",
        "FirstName": first_name,
        "LastName": last_name,
        "Age": age,
        "City": city,
        "IsAdult": age >= 18,
    }


def koi_test_command(args: dict) -> CommandResults:
    """Create a profile from the four provided arguments and return it as outputs.

    Args:
        args: The script arguments.

    Returns:
        CommandResults with the built profile.
    """
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    city = args.get("city")
    age_arg = args.get("age")

    if not first_name or not last_name or not city or age_arg is None:
        raise ValueError("The arguments 'first_name', 'last_name', 'age' and 'city' are all required.")

    try:
        age = int(age_arg)
    except (TypeError, ValueError):
        raise ValueError(f"The 'age' argument must be an integer, got: {age_arg}")

    profile = build_profile(first_name, last_name, age, city)

    return CommandResults(
        outputs_prefix="Koi.Profile",
        outputs_key_field="FullName",
        outputs=profile,
        readable_output=tableToMarkdown("Koi Profile", profile),
    )


def main():  # pragma: no cover
    try:
        return_results(koi_test_command(demisto.args()))
    except Exception as e:
        return_error(f"Failed to execute KoiTestScript. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
