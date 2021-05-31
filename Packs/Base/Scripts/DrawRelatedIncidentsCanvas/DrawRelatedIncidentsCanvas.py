import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import networkx as nx
import math
MINIMUM_SERVER_VERSION = '6.1.0'


LAYOUT = demisto.args().get('layout')
layout_to_functions = {
    'shell': lambda G: nx.shell_layout(G, scale=200),
    'spring': lambda G: nx.spring_layout(G, scale=400),
    'kamada_kawai': lambda G: nx.kamada_kawai_layout(G, scale=400),
    'circular': lambda G: nx.circular_layout(G, scale=600),
    'multipartite': lambda G: nx.multipartite_layout(G, scale=500, subset_key="layer", align='horizontal')
}


def convert_position(_id, _type, xy_arr):
    return {
        'id': _id, 'type': _type, 'position': {'x': xy_arr[0], 'y': xy_arr[1]}
    }


def generate_layout(current_incident_id, incident_ids, indicator_ids, connections):
    G = nx.Graph()
    graph_incidents = ["incident-" + x for x in incident_ids]
    graph_indicators = ["indicator-" + x for x in indicator_ids]
    G.add_nodes_from(graph_incidents, layer=0)   # type: ignore
    n_indicators = len(indicator_ids)
    n_indicators_lines = int(n_indicators / (len(incident_ids) + 1)) + 1
    indicators_per_line = math.ceil(n_indicators / n_indicators_lines)
    for line in range(n_indicators_lines):
        layer = line - int(n_indicators_lines / 2) if line < int(n_indicators_lines / 2) else line - int(
            n_indicators_lines / 2) + 1
        G.add_nodes_from(graph_indicators[indicators_per_line * line:indicators_per_line * (line + 1)], layer=layer)

    for connection in connections:
        src = "%s-%s" % (connection['srcEntityType'], connection['srcEntityId'])
        dest = "%s-%s" % (connection['targetEntityType'], connection['targetEntityId'])
        G.add_edge(src, dest)
    pos = layout_to_functions.get(LAYOUT)(G)  # type: ignore
    layout = {}
    for k, v in pos.items():
        _type = k.split("-")[0]
        layout[k] = convert_position(k, _type, v)

    if LAYOUT == 'shell':
        layout["incident-" + current_incident_id]['position']["x"] = 0
        layout["incident-" + current_incident_id]['position']["y"] = 0
    return layout


def get_incident_to_incident_connection(inc1, inc2):
    return {"srcEntityType": "incident", "srcEntityId": inc1, "targetEntityType": "incident", "targetEntityId": inc2}


def get_incident_to_indicator_connection(inc, ioc):
    return {"srcEntityType": "incident", "srcEntityId": inc, "targetEntityType": "indicator", "targetEntityId": ioc}


def generate_canvas(current_incident_id, incident_ids, indicators):
    indicator_ids = list(map(lambda x: x['id'], indicators))

    incident_nodes = list(map(lambda x: {'type': 'incident', 'id': x}, incident_ids))
    indicators_nodes = list(map(lambda x: {'type': 'indicator', 'id': x}, indicator_ids))
    nodes = incident_nodes + indicators_nodes

    incident_to_other_incidents = []
    for incident_id in incident_ids:
        if incident_id != current_incident_id:
            incident_to_other_incidents.append(get_incident_to_incident_connection(current_incident_id, incident_id))

    incident_to_indicator_connections = []
    for indicator in indicators:
        for investigation_id in indicator.get('investigationIDs', []):
            if investigation_id in incident_ids + [current_incident_id]:
                incident_to_indicator_connections.append(
                    get_incident_to_indicator_connection(investigation_id, indicator['id']))

    connections = incident_to_other_incidents + incident_to_indicator_connections
    canvas = {
        "incidentID": current_incident_id,
        "version": -1,
        'nodes': nodes,
        'layout': generate_layout(current_incident_id, incident_ids, indicator_ids, connections)
    }
    return canvas, connections


def main():
    if not is_demisto_version_ge(MINIMUM_SERVER_VERSION):
        return_error('This script is supported only from version {}.'.format(MINIMUM_SERVER_VERSION))
    current_incident_id = demisto.args().get('incidentID')
    if current_incident_id is None:
        incident = demisto.incident()
        current_incident_id = incident['id']
    related_incidents_ids = demisto.args().get('relatedIncidentsIDs', [])
    if type(related_incidents_ids) is not list:
        related_incidents_ids = related_incidents_ids.split(",")
        related_incidents_ids = [x for x in related_incidents_ids if x]
    indicators = demisto.args().get('indicators', [])

    if len(indicators) and len(related_incidents_ids) == 0:
        return_error("No related incidents or indicators specified")

    canvas, connections = generate_canvas(current_incident_id, related_incidents_ids, indicators)
    override = demisto.args().get('overrideUserCanvas') == 'true'
    res = demisto.executeCommand('drawCanvas',
                                 {'canvas': canvas, 'canvasLinks': connections, 'id': current_incident_id,
                                  'overrideUserCanvas': override})
    if res is None:
        return_error("Unexpected error")
    elif is_error(res):
        return_error(get_error(res))
    else:
        hr = "### Check the incidents and indicators layout on the [canvas](#/Canvas/{0})".format(current_incident_id)
        return_outputs(hr)


main()
