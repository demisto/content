

def test_parse_cluster(datadir):
    from GoogleKubernetesEngine import parse_cluster
    from json import load
    parsed_act = parse_cluster(load(open(datadir["cluster_raw_response.json"])))
    expected = load(open(datadir["cluster_entry_context.json"]))
    assert expected == parsed_act


def test_parse_cluster_table(datadir):
    from GoogleKubernetesEngine import parse_cluster_table
    from json import load
    table_act = parse_cluster_table(load(open(datadir["cluster_entry_context.json"])))
    expected = load(open(datadir["cluster_table.json"]))
    assert table_act == expected


def test_parse_node_pool(datadir):
    from GoogleKubernetesEngine import parse_node_pool
    from json import load
    parsed_act = parse_node_pool(load(open(datadir["node_pools_raw_response.json"])))
    expected = load(open(datadir["node_pools_entry_context.json"]))
    assert expected == parsed_act


def test_parse_node_pool_table(datadir):
    from GoogleKubernetesEngine import parse_node_pool_table
    from json import load
    table_act = parse_node_pool_table(load(open(datadir["node_pools_entry_context.json"])))
    expected = load(open(datadir["node_pools_table.json"]))
    assert table_act == expected


def test_parse_operation(datadir):
    from GoogleKubernetesEngine import parse_operation
    from json import load
    parsed_act = parse_operation(load(open(datadir["operation_raw_response.json"])))
    expected = load(open(datadir["operation_entry_context.json"]))
    assert expected == parsed_act
