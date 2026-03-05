import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


map_customer = {
    "Redeban Ciberseguridad - SENTRIA": "Redeban",
    "Brinks Chile - SENTRIA": "Brinks",
    "RUNT - SENTRIA": "RUNT",
    "Andean Trade - Unisabana - SENTRIA": "Unisabana",
    "Netdata - SENTRIA": "Netdata",
    "CrowdstrikeFalcon_PuntosColombia": "PCO",
    "Puntos Colombia SAS": "PCO",
    "Caja de Compensación Familiar - COMPENSAR": "Compensar",
    "Promigas - SENTRIA": "Promigas"
}


def main():
    customer = demisto.args().get("value")
    resultsMapped = map_customer.get(customer)
    return_results(resultsMapped)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
