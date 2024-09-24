import json


def load_json_from_file(path):
    with open(path) as _json_file:
        return json.load(_json_file)


def test_parse_cluster(datadir):
    from GoogleKubernetesEngine import parse_cluster
    parsed_act = parse_cluster(load_json_from_file(datadir["cluster_raw_response.json"]))
    expected = load_json_from_file(datadir["cluster_entry_context.json"])
    assert expected == parsed_act


def test_parse_cluster_table(datadir):
    from GoogleKubernetesEngine import parse_cluster_table
    table_act = parse_cluster_table(load_json_from_file(datadir["cluster_entry_context.json"]))
    expected = load_json_from_file(datadir["cluster_table.json"])
    assert table_act == expected


def test_parse_node_pool(datadir):
    from GoogleKubernetesEngine import parse_node_pool
    parsed_act = parse_node_pool(load_json_from_file(datadir["node_pools_raw_response.json"]))
    expected = load_json_from_file(datadir["node_pools_entry_context.json"])
    assert expected == parsed_act


def test_parse_node_pool_table(datadir):
    from GoogleKubernetesEngine import parse_node_pool_table
    table_act = parse_node_pool_table(load_json_from_file(datadir["node_pools_entry_context.json"]))
    expected = load_json_from_file(datadir["node_pools_table.json"])
    assert table_act == expected


def test_parse_operation(datadir):
    from GoogleKubernetesEngine import parse_operation
    parsed_act = parse_operation(load_json_from_file(datadir["operation_raw_response.json"]))
    expected = load_json_from_file(datadir["operation_entry_context.json"])
    assert expected == parsed_act
