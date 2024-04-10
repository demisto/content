import pandas

import demistomock as demisto
from CommonServerPython import *
import enum
import abc
import pandas as pd


INTEGRATION_NAME = 'PrismaCloudCompute'
ISSUES_INPUT_PATH = 'EnrichedComplianceIssue'


class ComplianceObj(enum.Enum):
    HOST = 'host'
    CONTAINER = 'container'
    IMAGE = 'image'


class ComplianceObject(abc.ABC):
    def __init__(self, object_type: ComplianceObj, input_context_path: str, output_context_id: str):
        self.object_type = object_type
        self.capitalized_type = object_type.value.capitalize()
        self.input_context_path = input_context_path
        self.output_context_path = f'{INTEGRATION_NAME}.ComplianceTable.{self.capitalized_type}'
        self.output_context_id = output_context_id

    def get_input_context_id(self, obj: dict):
        try:
            return self._get_input_context_id(obj)
        except AttributeError as err:
            raise Exception(f'Input context does not match provided type: {self.object_type.value}') from err

    @abc.abstractmethod
    def _get_input_context_id(self, obj: dict):
        pass

    @abc.abstractmethod
    def get_data(self, input_data: dict, identifier: str, issues: list) -> dict:
        pass


class Host(ComplianceObject):

    def __init__(self):
        super().__init__(object_type=ComplianceObj.HOST,
                         input_context_path=f'{INTEGRATION_NAME}.ReportHostScan',
                         output_context_id='Hostname')

    def _get_input_context_id(self, obj: dict):
        return obj.get('hostname')

    def get_data(self, input_data: dict, identifier: str, issues: list) -> dict:
        """Get the host data as needed in the table.

        Args:
            input_data (dict): The input context data containing information about the host.
            identifier (str): The host name.
            issues (list): List of issues the host appeared in.

        Returns:
            (dict) The host data as needed in the table.
        """
        compliance_distribution = input_data.get('complianceDistribution')
        cloud_metadata = input_data.get('cloudMetadata')
        cloud_metadata.pop('labels', None) if cloud_metadata else None

        host_data = {
            self.output_context_id: identifier,
            'ComplianceIssues': issues,
            'ComplianceDistribution': compliance_distribution,
            'CloudMetaData': cloud_metadata
        }
        return host_data


class Container(ComplianceObject):

    def __init__(self):
        super().__init__(object_type=ComplianceObj.CONTAINER,
                         input_context_path=f'{INTEGRATION_NAME}.ContainersScanResults',
                         output_context_id='ContainerID')

    def _get_input_context_id(self, obj: dict):
        return obj.get('info', {}).get('id')

    def get_data(self, input_data: dict, identifier: str, issues: list) -> dict:
        """Get the container data as needed in the table.

        Args:
            input_data (dict): The input context data containing information about the container.
            identifier (str): The container ID.
            issues (list): List of issues the container appeared in.

        Returns:
            (dict) The container data as needed in the table.
        """
        container_info = input_data.get('info', {})
        compliance_dist = container_info.get('complianceDistribution')
        image_name = container_info.get('imageName')
        cloud_metadata = container_info.get('cloudMetadata', {})
        cloud_metadata.pop('labels', None)
        hostname = input_data.get('hostname', {})

        container_data = {
            self.output_context_id: identifier,
            'ComplianceIssues': issues,
            'ComplianceDistribution': compliance_dist,
            'Hostname': hostname,
            'ImageName': image_name,
            'CloudMetaData': cloud_metadata
        }
        return container_data


class Image(ComplianceObject):

    def __init__(self):
        super().__init__(object_type=ComplianceObj.IMAGE,
                         input_context_path=f'{INTEGRATION_NAME}.ReportsImagesScan',
                         output_context_id='ImageID')

    def _get_input_context_id(self, obj: dict):
        return obj.get('id')

    def get_data(self, input_data: dict, identifier: str, issues: list) -> dict:
        """Get the image data as needed in the table.

        Args:
            input_data (dict): The input context data containing information about the image.
            identifier (str): The image id.
            issues (list): List of issues it appeared in.

        Returns:
            (dict) The image data as needed in the table.
        """
        compliance_dist = input_data.get('complianceDistribution')
        hosts = list(input_data.get('hosts', {}).keys())
        instances_data = input_data.get('instances', [])
        image_instances = [instance_data.get('image') for instance_data in instances_data]
        cloud_metadata = input_data.get('cloudMetadata', {})
        cloud_metadata.pop('labels', {})

        image_data = {
            self.output_context_id: identifier,
            'ComplianceIssues': issues,
            'ComplianceDistribution': compliance_dist,
            'Hosts': hosts,
            'ImageInstances': image_instances,
            'CloudMetaData': cloud_metadata
        }
        return image_data


COMPLIANCE_OBJ_CLASS = {
    ComplianceObj.HOST.value: Host(),
    ComplianceObj.CONTAINER.value: Container(),
    ComplianceObj.IMAGE.value: Image(),
}


def get_input_object_list(context_data: dict, compliance_obj: ComplianceObject) -> list:
    """Get list of the input objects that the table will be updated with.

    Args:
        context_data (dict): The context data object the input objects are stored in.
        compliance_obj (ComplianceObject): The resource type class to get.

    Returns:
        (List[dict]) The list of the resource specified.
    """
    input_objects = demisto.get(context_data, compliance_obj.input_context_path)
    if type(input_objects) is list:
        return input_objects
    return [input_objects]


def get_output_object_list(compliance_obj: ComplianceObject, grid_id: str = '') -> tuple[list, list]:
    """Get the already present resource list in the table.

    Args:
        compliance_obj (ComplianceObject): The resource type class to get the list of.

    Returns:
        (List[dict], List[str]): The list of the specified resource, list of their ids.
    """

    if grid_id:
        incident = demisto.incident()
        custom_fields = incident.get("CustomFields", {}) or {}
        output_objects = custom_fields.get(grid_id)
        output_id = compliance_obj.output_context_id.lower()

    else:
        context_data = demisto.context()
        compliance_table_context = context_data.get(f'{INTEGRATION_NAME}', {}).get('ComplianceTable', {})
        output_objects = compliance_table_context.get(compliance_obj.capitalized_type, [])
        output_id = compliance_obj.output_context_id

    if type(output_objects) is list:
        output_objects_list = output_objects
    else:
        output_objects_list = [output_objects]

    return output_objects_list, [output_obj.get(output_id) for output_obj in output_objects_list]


def update_output_obj_with_issues(compliance_obj: ComplianceObject, input_obj_id: str, issues: list):
    """Update an object in the output table with new issues. Modify the context data.

    Args:
        compliance_obj (ComplianceObject): The resource type class to update.
        input_obj_id (str): The id of the resource to update.
        issues (List[str]): Issue records to update with.
    """
    context_key = compliance_obj.output_context_path
    output_objs, output_objs_ids = get_output_object_list(compliance_obj)
    output_obj_index = output_objs_ids.index(input_obj_id)
    output_obj = output_objs[output_obj_index]

    previous_issues = output_obj.get('ComplianceIssues', [])
    previous_issues = previous_issues if type(previous_issues) is list else [previous_issues]
    non_duplicated_issues = [issue for issue in issues if issue not in previous_issues]
    if non_duplicated_issues:
        demisto.debug(f"Updating {compliance_obj.object_type.value} in id {input_obj_id} with new issues: "
                      f"{non_duplicated_issues}")
        new_issues_list = previous_issues + non_duplicated_issues
        output_obj.update({'ComplianceIssues': new_issues_list})
        output_id_path = compliance_obj.output_context_id
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': output_obj,
            'HumanReadable': tableToMarkdown(f'Updating {compliance_obj.object_type.value} ({input_obj_id}) with new '
                                             f'compliance issues',
                                             non_duplicated_issues,
                                             'Compliance Issue'),
            'EntryContext': {f"{context_key}(val.{output_id_path} == obj.{output_id_path})": output_obj}
        })


def update_context_data(all_object_type_data: list, output_objs_to_append: dict, compliance_obj: ComplianceObject) -> None:
    """Update context data with new objects and new compliance issues that need updating.

    Args:
        all_object_type_data (list): List of the new data.
        output_objs_to_append (dict): Dict of (key: object id) and their (value: new compliance issues).
        compliance_obj (ComplianceObject): The compliance object the data refers to.
    """
    if all_object_type_data:
        appendContext(compliance_obj.output_context_path, all_object_type_data)

    demisto.debug(f"The objects to update are {list(output_objs_to_append.keys())}. Updating")
    for obj_to_update_id in output_objs_to_append:
        update_output_obj_with_issues(compliance_obj, obj_to_update_id, output_objs_to_append[obj_to_update_id])


def turn_pd_grid_to_context_table(pd_grid: pandas.DataFrame) -> list:
    """Turn pandas DataFrame object to a list of dicts to save in the context_data.

    Args:
        pd_grid (pandas.DataFrame): The pandas dataframe to convert

    Returns: (list) of dicts of data inside the pd_grid provided.
    """
    context_table = []
    for record in pd_grid.to_dict(orient='records'):
        new_record_dict = {}
        for record_key, record_value in record.items():
            if record_value and (isinstance(record_value, dict | list) or pd.notnull(record_value)):
                if isinstance(record_value, dict):
                    str_record_value = "\n".join(f'{dict_key}: {dict_value}' for dict_key, dict_value in record_value.items())
                elif isinstance(record_value, list):
                    str_record_value = "\n\n".join(record_value)
                else:
                    str_record_value = str(record_value)
                new_record_dict.update({record_key.lower(): str_record_value})
        if new_record_dict:
            context_table.append(new_record_dict)
    return context_table


def update_grid_table(all_new_data: list, output_objs_to_append: dict,
                      compliance_obj: ComplianceObject, grid_id: str, current_table: list) -> None:
    """Update grid in the incident context data.

    Args:
        all_new_data (list): List of the new data.
        output_objs_to_append (dict): Dict of object ids (keys) and their new compliance issues (values).
        compliance_obj (ComplianceObject): The compliance object the data refers to.
        grid_id (str): The grid id to update.
        current_table (list): The already present table in the incident.
    """
    demisto.debug(f"Updating grid {grid_id} table with all new:\n{all_new_data}\n"
                  f"output_objs:\n{output_objs_to_append}\ncurrent table is:\n{current_table}")
    current_df = pd.DataFrame(current_table) if current_table else pd.DataFrame()
    demisto.debug(f"Current dataframe {current_df}")

    out_id = compliance_obj.output_context_id.lower()
    for id_to_update in output_objs_to_append:
        previous_issues = current_df.loc[current_df[out_id] == id_to_update, 'complianceissues'].iloc[0]
        issues = output_objs_to_append[id_to_update]
        non_duplicated_issues = [issue for issue in issues if issue not in previous_issues]
        if non_duplicated_issues:
            merged_issue_list = previous_issues + "\n\n" + "\n\n".join(non_duplicated_issues)
            current_df.loc[current_df[out_id] == id_to_update, 'complianceissues'] = merged_issue_list

    new_grid = pd.concat([pd.DataFrame(all_new_data), current_df])

    demisto.debug(f"New dataframe after concat and sort:\n{new_grid}")

    # filter empty values in the generated table and turn to dict
    context_table = turn_pd_grid_to_context_table(new_grid)

    demisto.debug(f"New table for context: {context_table}")

    # Execute automation 'setIncident` which change the Context data in the incident
    demisto.executeCommand("setIncident", {
        'customFields': {
            grid_id: context_table,
        },
    })


def create_issue_record(issue_obj: dict):
    """Create a unique issue string from the issue_obj dict."""
    return f"{issue_obj.get('id')} ({issue_obj.get('severity')} | {issue_obj.get('type')}) - {issue_obj.get('title')}"


def categorize_issue_in_object(issue: str, input_obj: dict, compliance_obj: ComplianceObject,
                               output_objs_ids: list, output_objs_to_create: dict, output_objs_to_append: dict) -> None:
    """Categorize the new issue information based on if the object is new or old.

    WARNING: Mutates output_objs_to_create and output_objs_to_append.

    Args:
        issue (str): The issue to categorize.
        input_obj (dict): The input object dict.
        compliance_obj (ComplianceObject): The type of compliance object.
        output_objs_ids (list): The ids of the objects already present in the output.
        output_objs_to_append (dict): Append the issues to this dict if they are already present in the output.
        output_objs_to_create (dict): Add the issues with the corresponding object id to this dict if they are new.

    """
    input_obj_id = compliance_obj.get_input_context_id(input_obj)
    if input_obj_id not in output_objs_ids:
        demisto.debug(f"Got new {compliance_obj.object_type.value} with id {input_obj_id} in issue {issue}")
        if input_obj_id in output_objs_to_create:
            output_objs_to_create[input_obj_id]['issues'].append(issue)
        else:
            output_objs_to_create[input_obj_id] = {
                'input_obj': input_obj,
                'issues': [issue]
            }
    else:
        demisto.debug(f"Got old {compliance_obj.object_type.value} with id {input_obj_id} in issue {issue}")
        if input_obj_id in output_objs_to_append:
            output_objs_to_append[input_obj_id].append(issue)
        else:
            output_objs_to_append[input_obj_id] = [issue]


def update_objects_by_issues(compliance_obj: ComplianceObject, root_context_key: str, grid_id: str = ''):
    """Go over enriched issues in the context data and update the output table.

    Args:
        compliance_obj (ComplianceObject): The resource type class to update in the table.
        root_context_key (str): The context data path to the root, containing the input data.
        grid_id (str): The grid id to write the outputs to.
    """
    if root_context_key:
        issues_input_objects = demisto.get(demisto.context(), root_context_key)
    else:
        issues_input_objects = demisto.context()
    issues_input_objects = issues_input_objects if type(issues_input_objects) is list else [issues_input_objects]
    output_objs, output_objs_ids = get_output_object_list(compliance_obj, grid_id)
    demisto.debug(f"Starting update, the already present output object ids are {output_objs_ids}")

    output_objs_to_create: dict = {}
    output_objs_to_append: dict = {}
    demisto.debug(f"Starting to go over {len(issues_input_objects)} issues and search for {compliance_obj.object_type.value}")
    for issue_input_obj in issues_input_objects:
        issue = create_issue_record(issue_input_obj.get(ISSUES_INPUT_PATH, {}))
        input_objs = get_input_object_list(issue_input_obj, compliance_obj)
        demisto.debug(f"Got {len(input_objs)} {compliance_obj.object_type.value} for issue {issue}")

        for input_obj in input_objs:
            categorize_issue_in_object(issue, input_obj, compliance_obj, output_objs_ids, output_objs_to_create,
                                       output_objs_to_append)

    demisto.debug(f"The new objects to create are {list(output_objs_to_create.keys())}. Creating")

    all_object_type_data = []
    for obj_to_create_id in output_objs_to_create:
        output_context_data = compliance_obj.get_data(output_objs_to_create[obj_to_create_id]['input_obj'],
                                                      obj_to_create_id,
                                                      output_objs_to_create[obj_to_create_id]['issues'])

        all_object_type_data.append(output_context_data)

    # Append after collecting all the new data
    if grid_id:
        update_grid_table(all_object_type_data, output_objs_to_append, compliance_obj, grid_id, output_objs)

    else:
        update_context_data(all_object_type_data, output_objs_to_append, compliance_obj)


def update_context_paths(demisto_args: dict):
    compliance_obj = COMPLIANCE_OBJ_CLASS[demisto_args.get('resourceType', '').lower()]
    return update_objects_by_issues(compliance_obj,
                                    demisto_args.get('contextPath', ''),
                                    demisto_args.get('gridID', ''))


def main():  # pragma: no cover
    try:
        return_results(update_context_paths(demisto_args=demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute PrismaCloudComputeComplianceTable. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
