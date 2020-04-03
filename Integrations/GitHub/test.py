import requests
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://api.github.com'

def start_graphql_client():
    sample_transport = RequestsHTTPTransport(
        url=BASE_URL + '/graphql',
        use_json=True,
        headers={
            'Authorization': "Bearer "
        },
        verify=False
    )
    client = Client(
        retries=3,
        transport=sample_transport,
        fetch_schema_from_transport=True,
    )
    return client


def execute_graphql_query(query, variable_values=None):
    client = start_graphql_client()

    gql_query = gql(query)
    response = client.execute(gql_query, variable_values=variable_values)
    return response


def send_get_query_to_get_data():
    return execute_graphql_query('''
        {
          repository(owner: "demisto", name: "etc") {
            project(number: 31) {
              name
              id
              columns(first: 30) {
                  nodes {
                    name
                    id
                    cards(first: 100) {
                      edges {
                        node {
                          note
                          state
                          id
                          content {
                            ... on Issue {
                              id
                              number
                              title
                            }
                            ... on PullRequest {
                              id
                              number
                              title
                            }
                          }
                        }
                      }
                    }
                  }
              }
            }
            issues(first: 100, states: OPEN, labels:"bug") {
              edges {
                cursor
                node {
                  title
                  id
                  number
                  labels(first: 10) {
                    edges {
                      node {
                        name
                      }
                    }
                  }
                  assignees(last: 10) {
                    edges {
                      node {
                        id
                        login
                      }
                    }
                  }
                }
              }
            }
          }
        }''')


def send_get_query_to_get_data_with_after(after):
    return execute_graphql_query('''
        query ($after: String!) {
          repository(owner: "demisto", name: "etc") {
            project(number: 31) {
              name
              id
              columns(first: 30) {
                  nodes {
                    name
                    id
                    cards(first: 100) {
                      edges {
                        node {
                          note
                          state
                          id
                          content {
                            ... on Issue {
                              id
                              number
                              title
                            }
                            ... on PullRequest {
                              id
                              number
                              title
                            }
                          }
                        }
                      }
                    }
                  }
              }
            }
            issues(first: 100, after:$after, states: OPEN, labels:"bug") {
              edges {
                cursor
                node {
                  title
                  id
                  number
                  labels(first: 10) {
                    edges {
                      node {
                        name
                      }
                    }
                  }
                  assignees(last: 10) {
                    edges {
                      node {
                        id
                        login
                      }
                    }
                  }
                }
              }
            }
          }
        }''', {"after": after})


def get_issues_and_projects_data():
    response = send_get_query_to_get_data()
    projects = response.get("repository", {}).get('project', {})
    issues = response.get('repository', {}).get('issues', {})

    while len(response.get('repository', {}).get('issues', {}).get('edges')) > 0:
        after = response.get('repository', {}).get('issues', {}).get('edges')[-1].get('cursor')
        issues.get('edges').extend(response.get('repository', {}).get('issues', {}).get('edges'))
        response = send_get_query_to_get_data_with_after(after=after)

    return projects, issues


def extract_card_node_data(column_node):
    card_id_to_issue_details = {}
    for card in column_node['cards']['edges']:
        card_content = card.get('node', {}).get('content')
        if not card_content:
            continue

        card_id_to_issue_details[card.get('node', {}).get('id')] = {
            'issue_id': card_content['id'],
            'title': card_content['title'],
            'number': card_content['number']
        }

    return card_id_to_issue_details


def extract_project_information(project):
    all_issues = set()
    column_name_to_details = {}
    for column_node in project['columns']['nodes']:
        card_id_to_issue_details = extract_card_node_data(column_node)
        column_name_to_details[column_node['name']] = {
            'id': column_node['id'],
            'cards': card_id_to_issue_details
        }
        all_issues = all_issues.union({val['issue_id'] for val in card_id_to_issue_details.values()})

    return column_name_to_details, all_issues


def extract_issue_assignees(edges):
    assignee_id_to_name = {}
    for edge in edges:
        node_data = edge.get('node')
        if node_data:
            assignee_id_to_name[node_data['id']] = node_data['login']

    return assignee_id_to_name


def extract_issue_labels(edges):
    label_names = []
    for edge in edges:
        node_data = edge.get('node')
        if node_data:
            label_names.append(node_data['name'])

    return label_names


def extract_issues_information(issues):
    issue_id_to_data = {}
    for edge in issues['edges']:
        node_data = edge['node']
        labels = extract_issue_labels(node_data['labels']['edges'])
        if 'content' not in labels or 'Playbooks' in labels:
            continue

        issue_id_to_data[node_data['id']] = {
            'title': node_data['title'],
            'number': node_data['number'],
            'assignees': extract_issue_assignees(node_data['assignees']['edges']),
            'labels': labels
        }

    return issue_id_to_data


def find_missing_issues(all_issues_in_project, issues_info):
    issues_in_project_keys = set(all_issues_in_project)
    all_matching_issues = set(issues_info.keys())
    return all_matching_issues - issues_in_project_keys


def get_matching_queue(column_name_to_details, issue_info):
    if 'PendingSupport' in issue_info['labels']:
        column_id = column_name_to_details['Pending Support']['id']
    elif issue_info['assignees']:
        column_id = column_name_to_details['In progress']['id']
    else:
        column_id = column_name_to_details['Queue']['id']

    return column_id


def add_issues_to_project(column_name_to_details, all_issues_in_project, issues_info):
    missing_issue_ids = find_missing_issues(all_issues_in_project, issues_info)
    for issue_id in missing_issue_ids:
        print("adding issue '{}'".format(issues_info[issue_id]['title']))
        column_id = get_matching_queue(column_name_to_details, issues_info[issue_id])

        execute_graphql_query('''
mutation addProjectCardAction($contentID: ID!, $columnId: ID!){
  addProjectCard(input: {contentId: $contentID, projectColumnId: $columnId}) {
    cardEdge{
      node{
        id
      }
    }
  }
}''', {'contentID': issue_id, 'columnId': column_id})


def find_card_id(column_name_to_details, issue_id):
    # import ipdb
    # ipdb.set_trace()
    for column_value in column_name_to_details.values():
        for card_id, card_value in column_value['cards'].items():
            if card_value['issue_id'] == issue_id:
                return card_id


def move_issue_in_project(column_name_to_details, issues_info):
    for issue_id, issue_details in issues_info.items():
        print("moving issue '{}'".format(issues_info[issue_id]['title']))

        if 'PendingSupport' in issue_details['labels'] and all([issue_id != val['issue_id'] for val in column_name_to_details['Pending Support']['cards'].values()]):
            column_id = column_name_to_details['Pending Support']['id']

            card_id = find_card_id(column_name_to_details, issue_id)
            execute_graphql_query('''
            mutation moveProjectCardAction($cardId: ID!, $columnId: ID!){
              moveProjectCard(input: {cardId: $cardId, columnId: $columnId}) {
                cardEdge{
                  node{
                    id
                  }
                }
              }
            }''', {'cardId': card_id, 'columnId': column_id})

        if 'PendingSupport' not in issue_details['labels'] and any([issue_id == val['issue_id'] for val in column_name_to_details['Pending Support']['cards'].values()]):

            if issue_details['assignees']:
                column_id = column_name_to_details['In progress']['id']

            else:
                column_id = column_name_to_details['Queue']['id']

            card_id = find_card_id(column_name_to_details, issue_id)
            execute_graphql_query('''
            mutation moveProjectCardAction($cardId: ID!, $columnId: ID!){
              moveProjectCard(input: {cardId: $cardId, columnId: $columnId}) {
                cardEdge{
                  node{
                    id
                  }
                }
              }
            }''', {'cardId': card_id, 'columnId': column_id})

        if issue_details['assignees'] and any([issue_id == val['issue_id'] for val in column_name_to_details['Queue']['cards'].values()]):
            column_id = column_name_to_details['In progress']['id']

            card_id = find_card_id(column_name_to_details, issue_id)
            execute_graphql_query('''
            mutation moveProjectCardAction($cardId: ID!, $columnId: ID!){
              moveProjectCard(input: {cardId: $cardId, columnId: $columnId}) {
                cardEdge{
                  node{
                    id
                  }
                }
              }
            }''', {'cardId': card_id, 'columnId': column_id})


def process_issue_moves():
    projects, issues = get_issues_and_projects_data()
    column_name_to_details, all_issues_in_project = extract_project_information(projects)
    issues_info = extract_issues_information(issues)
    add_issues_to_project(column_name_to_details, all_issues_in_project, issues_info)
    move_issue_in_project(column_name_to_details, issues_info)


if __name__ == "__main__":
    process_issue_moves()
