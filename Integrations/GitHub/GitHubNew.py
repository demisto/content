import requests
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class GraphQLClient(object):
    BASE_URL = 'https://api.github.com'

    def __init__(self):
        sample_transport = RequestsHTTPTransport(
            url=self.BASE_URL + '/graphql',
            use_json=True,
            headers={
                'Authorization': "Bearer 50e16ef3982c6e79d70fc5b364fba7f43e6f68a1"
            },
            verify=False
        )
        self.client = Client(
            retries=3,
            transport=sample_transport,
            fetch_schema_from_transport=True,
        )

    def execute_query(self, query, variable_values=None):
        gql_query = gql(query)
        response = self.client.execute(gql_query, variable_values=variable_values)
        return response

    def send_get_query_to_get_data(self):
        return self.execute_query('''
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
                      timelineItems(first:10){
                        __typename
                        ... on IssueTimelineItemsConnection{
                          nodes {
                            ... on CrossReferencedEvent {
                              willCloseTarget
                              source {
                                __typename 
                                ... on PullRequest {
                                  number
                                  reviewDecision
                                }
                              }
                            }
                          }
                        }
                      }
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

    def send_get_query_to_get_data_with_after(self, after):
        return self.execute_query('''
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
                      timelineItems(first:10){
                        __typename
                        ... on IssueTimelineItemsConnection{
                          nodes {
                            ... on CrossReferencedEvent {
                              willCloseTarget
                              source {
                                __typename 
                                ... on PullRequest {
                                  number
                                  reviewDecision
                                }
                              }
                            }
                          }
                        }
                      }
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

    def add_issues_to_project(self, issue_id, column_id):
        self.execute_query('''
        mutation addProjectCardAction($contentID: ID!, $columnId: ID!){
          addProjectCard(input: {contentId: $contentID, projectColumnId: $columnId}) {
            cardEdge{
              node{
                id
              }
            }
          }
        }''', {'contentID': issue_id, 'columnId': column_id})

    def move_issue_in_project(self, card_id, column_id, after_card_id=''):
        #todo: afterCardId
        self.execute_query('''
        mutation moveProjectCardAction($cardId: ID!, $columnId: ID!){
          moveProjectCard(input: {cardId: $cardId, columnId: $columnId}) {
            cardEdge{
              node{
                id
              }
            }
          }
        }''', {'cardId': card_id, 'columnId': column_id})


class Project(object):
    def __init__(self, git_hub_project):
        all_issues = set()
        column_name_to_details = {}
        for column_node in git_hub_project['columns']['nodes']:
            card_id_to_issue_details = self.extract_card_node_data(column_node)
            column_name_to_details[column_node['name']] = {
                'id': column_node['id'],
                'cards': card_id_to_issue_details
            }
            all_issues = all_issues.union({val['issue_id'] for val in card_id_to_issue_details.values()})

        self.column_name_to_details = column_name_to_details
        self.all_issues = all_issues

    def extract_card_node_data(self, column_node):
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

    def find_missing_issue_ids(self, issues):
        issues_in_project_keys = set(self.all_issues)
        all_matching_issues = set(issues.issue_id_to_data.keys())
        return all_matching_issues - issues_in_project_keys

    def add_issues(self, client, issues):
        missing_issue_ids = self.find_missing_issue_ids(issues)
        for issue_id in missing_issue_ids:
            column_name, column_id = self.get_matching_column(issue_id, issues.issue_id_to_data[issue_id])

            print("Adding issue '{}' to column '{}'".format(issues.issue_id_to_data[issue_id]['title'], column_name))
            client.add_issues_to_project(issue_id, column_id)

    def is_in_column(self, column_name, issue_id):
        for card in self.column_name_to_details[column_name]['cards'].values():
            if issue_id == card['issue_id']:
                return True

        return False

    def get_matching_column(self, issue_id, issue_info):
        if 'PendingSupport' in issue_info['labels']:
            if not self.is_in_column('Pending Support', issue_id):
                column_name = 'Pending Support'

            else:  # In Case he is in the queue already
                return None, None

        elif not issue_info['assignees'] and not self.is_in_column('Queue', issue_id):
            column_name = 'Queue'

        elif issue_info['assignees']:
            #TODO: if you have review, if review approved
            column_name = 'In progress'

        else:
            column_name = 'Queue'

        column_id = self.column_name_to_details[column_name]['id']
        return column_name, column_id

    def get_card_id(self, column_name, issue_id):
        for card_id, card_data in self.column_name_to_details[column_name]['cards'].items():
            if issue_id == card_data['issue_id']:
                return card_id

    def re_order_issues(self, client, issues):
        for issue_id, issue_details in issues.issue_id_to_data.items():
            column_name, column_id = self.get_matching_column(issue_id, issue_details)
            card_id = self.get_card_id(column_name, issue_id)

            #TODO: add treatment of after_card_id
            #todo: add treatment of pull request

            print("moving issue '{}' to '{}'".format(issue_details['title'], column_name))
            client.move_issue_in_project(card_id, column_id)

            if 'PendingSupport' not in issue_details['labels'] and any([issue_id == val['issue_id'] for val in
                                                                        self.column_name_to_details['Pending Support'][
                                                                            'cards'].values()]):

                if issue_details['assignees']:
                    column_id = self.column_name_to_details['In progress']['id']

                else:
                    column_id = self.column_name_to_details['Queue']['id']

                card_id = self.get_card_id(issue_id)
                client.move_issue_in_project(card_id, column_id)

            if issue_details['assignees'] and any(
                    [issue_id == val['issue_id'] for val in self.column_name_to_details['Queue']['cards'].values()]):
                column_id = self.column_name_to_details['In progress']['id']

                card_id = self.get_card_id(issue_id)
                client.move_issue_in_project(card_id, column_id)


class Issues(object):
    def __init__(self, git_hub_issues):
        issue_id_to_data = {}
        for edge in git_hub_issues['edges']:
            node_data = edge['node']
            labels = self.extract_issue_labels(node_data['labels']['edges'])
            if 'content' not in labels or 'Playbooks' in labels:
                continue

            issue_id_to_data[node_data['id']] = {
                'title': node_data['title'],
                'number': node_data['number'],
                'assignees': self.extract_issue_assignees(node_data['assignees']['edges']),
                'labels': labels,
                'pull_request': self.extract_pull_request(node_data)  # TODO: update in the request
            }

        self.issue_id_to_data = issue_id_to_data

    def extract_issue_assignees(self, edges):
        assignee_id_to_name = {}
        for edge in edges:
            node_data = edge.get('node')
            if node_data:
                assignee_id_to_name[node_data['id']] = node_data['login']

        return assignee_id_to_name

    def extract_issue_labels(self, edges):
        label_names = []
        for edge in edges:
            node_data = edge.get('node')
            if node_data:
                label_names.append(node_data['name'])

        return label_names

    def get_pull_request_assignee(self, timeline_node):
        assignees = []
        for assignee in timeline_node['source']['assignees']['nodes']:
            if assignee:
                assignees.append(assignee['login'])

        return assignees

    def extract_pull_request(self, node):
        timeline_nodes = node['timelineItems']['nodes']
        for timeline_node in timeline_nodes:
            if not timeline_node:
                continue

            if timeline_node['willCloseTarget'] and timeline_node['__typename'] == 'PullRequest':
                return {
                    'number': timeline_node['source']['number'],
                    'review_completed': False if timeline_node['source']['reviewDecision'] != 'APPROVED' else True,
                    'assignees': self.get_pull_request_assignee(timeline_node)
                }


def get_github_information(client):
    response = client.send_get_query_to_get_data()
    project = response.get("repository", {}).get('project', {})
    issues = response.get('repository', {}).get('issues', {})

    while len(response.get('repository', {}).get('issues', {}).get('edges')) > 0:
        after = response.get('repository', {}).get('issues', {}).get('edges')[-1].get('cursor')
        issues.get('edges').extend(response.get('repository', {}).get('issues', {}).get('edges'))
        response = client.send_get_query_to_get_data_with_after(after=after)

    project = Project(project)
    issues = Issues(issues)
    return project, issues


def process_issue_moves():
    client = GraphQLClient()
    project, issues = get_github_information(client)

    # project.add_issues(client, issues)
    # project.re_order_issues(client, issues)


if __name__ == "__main__":
    process_issue_moves()
