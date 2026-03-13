from CommonServerPython import *  # noqa: F401


def main() -> None:
    raise DemistoException(
        'The Stairwell Inception integration is deprecated. '
        'Please migrate to the Stairwell integration. '
        'All inception-* commands have been renamed to stairwell-* commands '
        'and context paths have changed from Inception.* to Stairwell.*.'
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
