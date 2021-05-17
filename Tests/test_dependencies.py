import json
import math


class VertexTester:
    def __init__(self, test_name):
        self.neighbors = {}
        self.test_name = test_name

        self.visited = False

    def add_neighbor(self, neighbor_test):
        neighbor_name = neighbor_test.test_name
        self.neighbors[neighbor_name] = neighbor_test

    def get_connected_component(self, tests_in_component):
        tests_in_component.append(self.test_name)
        self.visited = True
        for neighbor_name in self.neighbors:
            neighbor_vertex = self.neighbors[neighbor_name]
            if not neighbor_vertex.visited:
                tests_in_component = neighbor_vertex.get_connected_component(tests_in_component)
        return tests_in_component


class GraphTester:
    """A graph representing the tests in Demisto and whether they use mutual integrations.

    Attributes:
        test_vertices (list): A list of vertices (of type TestVertex), each representing a test.
        clusters (list): A list of test clusters, where the tests of each cluster need to be run sequentially.

    """
    def __init__(self):
        self.test_vertices = {}
        self.clusters = []

    def add_test_graph_vertices(self, tests_data):
        for test_playbook_record in tests_data:
            playbook_name_in_record = test_playbook_record.get("playbookID")
            if playbook_name_in_record and playbook_name_in_record not in self.test_vertices:
                new_test_vertex = VertexTester(playbook_name_in_record)
                self.test_vertices[playbook_name_in_record] = new_test_vertex

    def add_test_graph_neighbors(self, tests_data):
        integration_to_tests_mapping = get_integration_to_tests_mapping(tests_data)
        for integration_name in integration_to_tests_mapping:
            tests_using_integration = integration_to_tests_mapping[integration_name]
            for i in range(len(tests_using_integration)):
                first_test_name = tests_using_integration[i]
                first_test_vertex = self.test_vertices[first_test_name]

                for j in range(i + 1, len(tests_using_integration)):
                    second_test_name = tests_using_integration[j]
                    second_test_vertex = self.test_vertices[second_test_name]

                    first_test_vertex.add_neighbor(second_test_vertex)
                    second_test_vertex.add_neighbor(first_test_vertex)

    def get_clusters(self):
        clusters = []
        for test_name in self.test_vertices:
            test_vertex = self.test_vertices[test_name]
            if not test_vertex.visited:
                test_connected_component = test_vertex.get_connected_component([])
                clusters.append(test_connected_component)
        self.clusters = clusters

    def build_tests_graph_from_conf_json(self, tests_file_path, dependent_tests):
        with open(tests_file_path, 'r') as myfile:
            conf_json_string = myfile.read()

        tests_data = json.loads(conf_json_string)["tests"]

        dependent_tests_data = [test_record for test_record in tests_data
                                if test_record.get("playbookID") in dependent_tests]

        self.add_test_graph_vertices(dependent_tests_data)
        self.add_test_graph_neighbors(dependent_tests_data)
        self.get_clusters()


def get_integration_to_tests_mapping(tests_data):
    integration_to_tests_mapping = {}
    for test_playbook_record in tests_data:
        record_playbook_name = test_playbook_record.get("playbookID", None)
        record_integrations = get_used_integrations(test_playbook_record)
        for integration_name in record_integrations:
            if integration_name in integration_to_tests_mapping:
                if record_playbook_name not in integration_to_tests_mapping[integration_name]:
                    integration_to_tests_mapping[integration_name].append(record_playbook_name)
            else:
                integration_to_tests_mapping[integration_name] = [record_playbook_name]
    return integration_to_tests_mapping


def get_used_integrations(test_playbook_record):
    tested_integrations = test_playbook_record.get("integrations", [])
    if isinstance(tested_integrations, list):
        return tested_integrations
    else:
        return [tested_integrations]


def get_dependent_and_independent_integrations(tests_file_path):
    with open(tests_file_path, 'r') as myfile:
        conf_json_string = myfile.read()

    conf_json_obj = json.loads(conf_json_string)

    integration_tests_count = {}
    for test_record in conf_json_obj["tests"]:
        integrations_used = get_used_integrations(test_record)
        for integration_name in integrations_used:
            if integration_name in integration_tests_count:
                integration_tests_count[integration_name] += 1
            else:
                integration_tests_count[integration_name] = 1

    dependent_integrations = [integration_name for integration_name in integration_tests_count
                              if integration_tests_count[integration_name] > 1]
    independent_integrations = [integration_name for integration_name in integration_tests_count
                                if integration_tests_count[integration_name] <= 1]
    return dependent_integrations, independent_integrations


def get_test_dependencies(tests_file_path):
    dependent_integrations = get_dependent_and_independent_integrations(tests_file_path)[0]

    with open(tests_file_path, 'r') as myfile:
        conf_json_string = myfile.read()
    conf_json_obj = json.loads(conf_json_string)

    dependent_tests = []
    all_tests = []
    for test_record in conf_json_obj["tests"]:
        integrations_used = get_used_integrations(test_record)
        playbook = test_record.get("playbookID", None)
        if playbook not in all_tests:
            all_tests.append(playbook)
        dependent_integrations_used = [integration for integration in integrations_used
                                       if integration in dependent_integrations]
        if dependent_integrations_used and playbook not in dependent_tests:
            dependent_tests.append(playbook)

    independent_tests = [test for test in all_tests if test not in dependent_tests]
    return dependent_tests, independent_tests, all_tests


def get_dependent_integrations_clusters_data(tests_file_path, dependent_tests):
    tests_graph = GraphTester()
    tests_graph.build_tests_graph_from_conf_json(tests_file_path, dependent_tests)
    return tests_graph.clusters


def get_tests_allocation_for_threads(number_of_instances, tests_file_path):
    dependent_tests, independent_tests, all_tests = get_test_dependencies(tests_file_path)
    dependent_tests_clusters = get_dependent_integrations_clusters_data(tests_file_path, dependent_tests)
    dependent_tests_clusters.sort(key=len, reverse=True)  # Sort the clusters from biggest to smallest
    tests_allocation = []
    number_of_tests_left = len(all_tests)
    while number_of_tests_left > 0:
        allocations_left = number_of_instances - len(tests_allocation)
        desired_tests_per_allocation = math.ceil(number_of_tests_left / allocations_left)  # We prefer an equal division of tests.
        current_allocation = []

        # If we have one allocation left, add all tests to it and finish
        if allocations_left == 1:
            for tests_cluster in dependent_tests_clusters:
                current_allocation.extend(tests_cluster)
            for test_name in independent_tests:
                current_allocation.append(test_name)
            tests_allocation.append(current_allocation)
            break

        if len(dependent_tests_clusters) > 0:
            # Even if the first cluster is bigger than the desired amount, we have to add it to the allocation.
            # If we don't, it will not be added to any allocation.
            first_cluster = dependent_tests_clusters.pop(0)
            first_cluster_size = len(first_cluster)
            current_allocation.extend(first_cluster)
            number_of_tests_left -= first_cluster_size

        if len(current_allocation) >= desired_tests_per_allocation:
            tests_allocation.append(current_allocation)
            continue

        clusters_added = 0
        for cluster in dependent_tests_clusters:
            cluster_size = len(cluster)
            if len(current_allocation) + cluster_size > desired_tests_per_allocation:
                # Will fill the quota from the independent test lists.
                break
            current_allocation.extend(cluster)
            number_of_tests_left -= cluster_size
            clusters_added += 1

        del dependent_tests_clusters[:clusters_added]

        num_of_tests_to_add = int(desired_tests_per_allocation - len(current_allocation))
        independent_tests_to_add = independent_tests[:num_of_tests_to_add]
        current_allocation.extend(independent_tests_to_add)
        del independent_tests[:num_of_tests_to_add]

        tests_allocation.append(current_allocation)
    return tests_allocation
