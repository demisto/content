from CommonServerPython import demisto
import json
import pytest
import copy
import PrismaCloudComputeComplianceTable
from PrismaCloudComputeComplianceTable import update_context_paths


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


'''--------- Host input context data ---------'''
HOST_INPUT = util_load_json('test_data/host-scan-results.json')
HOST_INPUT_AS_DICT = copy.deepcopy(HOST_INPUT)
HOST_INPUT_AS_DICT['PrismaCloudCompute']['ReportHostScan'] = HOST_INPUT_AS_DICT['PrismaCloudCompute']['ReportHostScan'][0]

TWO_HOST_INPUT = copy.deepcopy(HOST_INPUT)
SECOND_HOST_ONLY_INPUT = copy.deepcopy(HOST_INPUT['PrismaCloudCompute']['ReportHostScan'][0])
SECOND_HOST_ONLY_INPUT['hostname'] = 'some_hostname2'
TWO_HOST_INPUT['PrismaCloudCompute']['ReportHostScan'].append(SECOND_HOST_ONLY_INPUT)

HOST_UPDATE_INPUT = copy.deepcopy(HOST_INPUT)
HOST_UPDATE_INPUT['EnrichedComplianceIssue']['id'] = 13372

TWO_HOST_UPDATE_INPUT = copy.deepcopy(HOST_UPDATE_INPUT)
TWO_HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'].append(SECOND_HOST_ONLY_INPUT)

'''--------- Host output context data ---------'''
HOST_OUTPUT = util_load_json('test_data/host-expected-output.json')
HOST_OUTPUT_UPDATED = copy.deepcopy(HOST_OUTPUT)
HOST_OUTPUT_UPDATED.update({'ComplianceIssues': ['1337 (high | custom) - title', '13372 (high | custom) - title']})

SECOND_HOST_OUTPUT = copy.deepcopy(HOST_OUTPUT)
SECOND_HOST_OUTPUT['Hostname'] = 'some_hostname2'
SECOND_HOST_OUTPUT['ComplianceIssues'] = ['13372 (high | custom) - title']

TWO_HOST_OUTPUT = [copy.deepcopy(HOST_OUTPUT), copy.deepcopy(HOST_OUTPUT)]
TWO_HOST_OUTPUT[1]['Hostname'] = 'some_hostname2'

'''--------- Host output context data grid ---------'''
HOST_OUTPUT_GRID = util_load_json('test_data/host-expected-output-grid.json')
HOST_OUTPUT_UPDATED_GRID = copy.deepcopy(HOST_OUTPUT_GRID)
HOST_OUTPUT_UPDATED_GRID.update({'complianceissues': '1337 (high | custom) - title\n\n13372 (high | custom) - title'})

SECOND_HOST_OUTPUT_GRID = copy.deepcopy(HOST_OUTPUT_GRID)
SECOND_HOST_OUTPUT_GRID['hostname'] = 'some_hostname2'
SECOND_HOST_OUTPUT_GRID['complianceissues'] = '13372 (high | custom) - title'

TWO_HOST_OUTPUT_GRID = [copy.deepcopy(HOST_OUTPUT_GRID), copy.deepcopy(HOST_OUTPUT_GRID)]
TWO_HOST_OUTPUT_GRID[1]['hostname'] = 'some_hostname2'

TWO_HOST_OUTPUT_UPDATED_GRID = [copy.deepcopy(HOST_OUTPUT_UPDATED_GRID), copy.deepcopy(HOST_OUTPUT_UPDATED_GRID)]
TWO_HOST_OUTPUT_UPDATED_GRID[1]['hostname'] = 'some_hostname2'


'''--------- Container input context data ---------'''
CONTAINER_INPUT = util_load_json('test_data/container-scan-results.json')
CONTAINER_INPUT_AS_DICT = copy.deepcopy(CONTAINER_INPUT)
CONTAINER_DATA_ONLY = CONTAINER_INPUT_AS_DICT['PrismaCloudCompute']['ContainersScanResults'][0]
CONTAINER_INPUT_AS_DICT['PrismaCloudCompute']['ContainersScanResults'] = CONTAINER_DATA_ONLY

TWO_CONTAINER_INPUT = copy.deepcopy(CONTAINER_INPUT)
SECOND_CONTAINER_ONLY_INPUT = copy.deepcopy(CONTAINER_INPUT['PrismaCloudCompute']['ContainersScanResults'][0])
SECOND_CONTAINER_ONLY_INPUT['info']['id'] = 'some_container_id2'
TWO_CONTAINER_INPUT['PrismaCloudCompute']['ContainersScanResults'].append(SECOND_CONTAINER_ONLY_INPUT)

CONTAINER_UPDATE_INPUT = copy.deepcopy(CONTAINER_INPUT)
CONTAINER_UPDATE_INPUT['EnrichedComplianceIssue']['id'] = 13372

TWO_CONTAINER_UPDATE_INPUT = copy.deepcopy(CONTAINER_UPDATE_INPUT)
TWO_CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'].append(SECOND_CONTAINER_ONLY_INPUT)

'''--------- Container output context data ---------'''
CONTAINER_OUTPUT = util_load_json('test_data/container-expected-output.json')
CONTAINER_OUTPUT_UPDATED = copy.deepcopy(CONTAINER_OUTPUT)
CONTAINER_OUTPUT_UPDATED.update({'ComplianceIssues': ['1337 (high | custom) - title', '13372 (high | custom) - title']})

SECOND_CONTAINER_OUTPUT = copy.deepcopy(CONTAINER_OUTPUT)
SECOND_CONTAINER_OUTPUT['ContainerID'] = 'some_container_id2'
SECOND_CONTAINER_OUTPUT['ComplianceIssues'] = ['13372 (high | custom) - title']

TWO_CONTAINER_OUTPUT = [copy.deepcopy(CONTAINER_OUTPUT), copy.deepcopy(CONTAINER_OUTPUT)]
TWO_CONTAINER_OUTPUT[1]['ContainerID'] = 'some_container_id2'

'''--------- Container output context as grid ---------'''

CONTAINER_OUTPUT_GRID = util_load_json('test_data/container-expected-output-grid.json')
CONTAINER_OUTPUT_UPDATED_GRID = copy.deepcopy(CONTAINER_OUTPUT_GRID)
CONTAINER_OUTPUT_UPDATED_GRID.update({'complianceissues': '1337 (high | custom) - title\n\n13372 (high | custom) - title'})

SECOND_CONTAINER_OUTPUT_GRID = copy.deepcopy(CONTAINER_OUTPUT_GRID)
SECOND_CONTAINER_OUTPUT_GRID['containerid'] = 'some_container_id2'
SECOND_CONTAINER_OUTPUT_GRID['complianceissues'] = '13372 (high | custom) - title'

TWO_CONTAINER_OUTPUT_GRID = [copy.deepcopy(CONTAINER_OUTPUT_GRID), copy.deepcopy(CONTAINER_OUTPUT_GRID)]
TWO_CONTAINER_OUTPUT_GRID[1]['containerid'] = 'some_container_id2'

TWO_CONTAINER_OUTPUT_UPDATED_GRID = [copy.deepcopy(CONTAINER_OUTPUT_UPDATED_GRID), copy.deepcopy(CONTAINER_OUTPUT_UPDATED_GRID)]
TWO_CONTAINER_OUTPUT_UPDATED_GRID[1]['containerid'] = 'some_container_id2'

'''--------- Image input context data ---------'''
IMAGE_INPUT = util_load_json('test_data/image-scan-results.json')
IMAGE_INPUT_AS_DICT = copy.deepcopy(IMAGE_INPUT)
IMAGE_DATA_ONLY = IMAGE_INPUT_AS_DICT['PrismaCloudCompute']['ReportsImagesScan'][0]
IMAGE_INPUT_AS_DICT['PrismaCloudCompute']['ContainersScanResults'] = IMAGE_DATA_ONLY

TWO_IMAGE_INPUT = copy.deepcopy(IMAGE_INPUT)
SECOND_IMAGE_ONLY_INPUT = copy.deepcopy(IMAGE_INPUT['PrismaCloudCompute']['ReportsImagesScan'][0])
SECOND_IMAGE_ONLY_INPUT['id'] = 'some_image_id2'
TWO_IMAGE_INPUT['PrismaCloudCompute']['ReportsImagesScan'].append(SECOND_IMAGE_ONLY_INPUT)

IMAGE_UPDATE_INPUT = copy.deepcopy(IMAGE_INPUT)
IMAGE_UPDATE_INPUT['EnrichedComplianceIssue']['id'] = 13372

TWO_IMAGE_UPDATE_INPUT = copy.deepcopy(IMAGE_UPDATE_INPUT)
TWO_IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'].append(SECOND_IMAGE_ONLY_INPUT)

'''--------- Image output context data ---------'''
IMAGE_OUTPUT = util_load_json('test_data/image-expected-output.json')
IMAGE_OUTPUT_UPDATED = copy.deepcopy(IMAGE_OUTPUT)
IMAGE_OUTPUT_UPDATED.update({'ComplianceIssues': ['1337 (high | custom) - title', '13372 (high | custom) - title']})

SECOND_IMAGE_OUTPUT = copy.deepcopy(IMAGE_OUTPUT)
SECOND_IMAGE_OUTPUT['ImageID'] = 'some_image_id2'
SECOND_IMAGE_OUTPUT['ComplianceIssues'] = ['13372 (high | custom) - title']

TWO_IMAGE_OUTPUT = [copy.deepcopy(IMAGE_OUTPUT), copy.deepcopy(IMAGE_OUTPUT)]
TWO_IMAGE_OUTPUT[1]['ImageID'] = 'some_image_id2'

'''--------- Image output context data grid ---------'''
IMAGE_OUTPUT_GRID = util_load_json('test_data/image-expected-output-grid.json')
IMAGE_OUTPUT_UPDATED_GRID = copy.deepcopy(IMAGE_OUTPUT_GRID)
IMAGE_OUTPUT_UPDATED_GRID.update({'complianceissues': '1337 (high | custom) - title\n\n13372 (high | custom) - title'})

SECOND_IMAGE_OUTPUT_GRID = copy.deepcopy(IMAGE_OUTPUT_GRID)
SECOND_IMAGE_OUTPUT_GRID['imageid'] = 'some_image_id2'
SECOND_IMAGE_OUTPUT_GRID['complianceissues'] = '13372 (high | custom) - title'

TWO_IMAGE_OUTPUT_GRID = [copy.deepcopy(IMAGE_OUTPUT_GRID), copy.deepcopy(IMAGE_OUTPUT_GRID)]
TWO_IMAGE_OUTPUT_GRID[1]['imageid'] = 'some_image_id2'

TWO_IMAGE_OUTPUT_UPDATED_GRID = [copy.deepcopy(IMAGE_OUTPUT_UPDATED_GRID), copy.deepcopy(IMAGE_OUTPUT_UPDATED_GRID)]
TWO_IMAGE_OUTPUT_UPDATED_GRID[1]['imageid'] = 'some_image_id2'


@pytest.mark.parametrize('input_context, object_type, expected_context, expected_context_path', [
    (HOST_INPUT, 'Host', [HOST_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Host'),
    (TWO_HOST_INPUT, 'Host', TWO_HOST_OUTPUT, 'PrismaCloudCompute.ComplianceTable.Host'),
    (HOST_INPUT_AS_DICT, 'Host', [HOST_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Host'),
    (CONTAINER_INPUT, 'Container', [CONTAINER_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Container'),
    (TWO_CONTAINER_INPUT, 'Container', TWO_CONTAINER_OUTPUT, 'PrismaCloudCompute.ComplianceTable.Container'),
    (CONTAINER_INPUT_AS_DICT, 'Container', [CONTAINER_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Container'),
    (IMAGE_INPUT, 'Image', [IMAGE_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Image'),
    (TWO_IMAGE_INPUT, 'Image', TWO_IMAGE_OUTPUT, 'PrismaCloudCompute.ComplianceTable.Image'),
    (IMAGE_INPUT_AS_DICT, 'Image', [IMAGE_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Image'),
], ids=['Host', 'TwoHosts', 'HostAsDict', 'Container', 'TwoContainers', 'ContainerAsDict', 'Image', 'TwoImages', 'ImageAsDict'])
def test_create_new_outputs(mocker, input_context, object_type, expected_context, expected_context_path):
    """
    Given:
        NEW enriched compliance issues with NEW compliance objects ids in the input context data.
        For each compliance object type (Host, Container, Image) check the following:
            1. Single object in a list
            2. Two objects in a list
            3. Single object as a dict response

    When:
        Running update_context_paths

    Then:
        Assert the newly created compliance table in the context data is as expected.
        Assert nothing was updated.
    """
    demisto_args = {'resourceType': object_type}
    mocker.patch.object(demisto, 'context', return_value=input_context)
    update_results = mocker.patch.object(demisto, 'results', return_value=None)
    append_context = mocker.patch.object(PrismaCloudComputeComplianceTable, 'appendContext', return_value=None)

    update_context_paths(demisto_args)

    append_context.assert_called_once_with(expected_context_path, expected_context)
    assert not update_results.called, 'Should only create context data and not update existing in this test.'


@pytest.mark.parametrize('input_context, object_type, expected_context', [
    (HOST_INPUT, 'Host', [HOST_OUTPUT_GRID]),
    (TWO_HOST_INPUT, 'Host', TWO_HOST_OUTPUT_GRID),
    (HOST_INPUT_AS_DICT, 'Host', [HOST_OUTPUT_GRID]),
    (CONTAINER_INPUT, 'Container', [CONTAINER_OUTPUT_GRID]),
    (TWO_CONTAINER_INPUT, 'Container', TWO_CONTAINER_OUTPUT_GRID),
    (CONTAINER_INPUT_AS_DICT, 'Container', [CONTAINER_OUTPUT_GRID]),
    (IMAGE_INPUT, 'Image', [IMAGE_OUTPUT_GRID]),
    (TWO_IMAGE_INPUT, 'Image', TWO_IMAGE_OUTPUT_GRID),
    (IMAGE_INPUT_AS_DICT, 'Image', [IMAGE_OUTPUT_GRID]),
], ids=['Host', 'TwoHosts', 'HostAsDict', 'Container', 'TwoContainers', 'ContainerAsDict', 'Image', 'TwoImages', 'ImageAsDict'])
def test_create_new_outputs_in_grid(mocker, input_context, object_type, expected_context):
    """
    Given:
        NEW enriched compliance issues with NEW compliance objects ids in the input context data.
        For each compliance object type (Host, Container, Image) check the following:
            1. Single object in a list
            2. Two objects in a list
            3. Single object as a dict response

    When:
        Running update_context_paths

    Then:
        Assert the newly created compliance GRID in the context data is as expected.
        Assert nothing was updated.
    """
    grid_id = 'some_grid_id'
    demisto_args = {'resourceType': object_type, 'gridID': grid_id}
    incident_fields = {"CustomFields": {grid_id: [{}, {}]}}
    mocker.patch.object(demisto, 'incident', return_value=incident_fields)
    mocker.patch.object(demisto, 'context', return_value=input_context)
    update_results = mocker.patch.object(demisto, 'executeCommand', return_value=None)

    update_context_paths(demisto_args)
    expected_fields = {
        'customFields': {
            grid_id: expected_context
        }
    }

    update_results.assert_called_once_with("setIncident", expected_fields)


def merge_input_and_output_context(input_context, output_context, object_type):
    """Merge the input of the script and already existing output of the script to one context data dict."""
    merged_context = copy.deepcopy(input_context)
    merged_context.update({'PrismaCloudCompute': {'ComplianceTable': {object_type: copy.deepcopy(output_context)}}})
    return merged_context


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output, expected_context, '
                         'expected_context_path',
                         [(HOST_UPDATE_INPUT, HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                             'Host', [HOST_OUTPUT], HOST_OUTPUT_UPDATED,
                             'PrismaCloudCompute.ComplianceTable.Host(val.Hostname == obj.Hostname)'),
                          (TWO_HOST_UPDATE_INPUT, TWO_HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                           'Host', TWO_HOST_OUTPUT, HOST_OUTPUT_UPDATED,
                           'PrismaCloudCompute.ComplianceTable.Host(val.Hostname == obj.Hostname)'),
                          (CONTAINER_UPDATE_INPUT, CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                           'Container', [CONTAINER_OUTPUT], CONTAINER_OUTPUT_UPDATED,
                           'PrismaCloudCompute.ComplianceTable.Container(val.ContainerID == obj.ContainerID)'),
                          (TWO_CONTAINER_UPDATE_INPUT,
                           TWO_CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                           'Container', TWO_CONTAINER_OUTPUT, CONTAINER_OUTPUT_UPDATED,
                           'PrismaCloudCompute.ComplianceTable.Container(val.ContainerID == obj.ContainerID)'),
                          (IMAGE_UPDATE_INPUT, IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                           'Image', [IMAGE_OUTPUT], IMAGE_OUTPUT_UPDATED,
                           'PrismaCloudCompute.ComplianceTable.Image(val.ImageID == obj.ImageID)'),
                          (TWO_IMAGE_UPDATE_INPUT, TWO_IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                           'Image', TWO_IMAGE_OUTPUT, IMAGE_OUTPUT_UPDATED,
                           'PrismaCloudCompute.ComplianceTable.Image(val.ImageID == obj.ImageID)')],
                         ids=['Host', 'TwoHosts', 'Container', 'TwoContainers', 'Image', 'TwoImages'])
def test_update_outputs(mocker, input_context, input_context_in_path, object_type, already_present_output, expected_context,
                        expected_context_path):
    """
    Given:
        NEW enriched compliance issues with OLD compliance objects ids in the input context data.
        For each compliance object type (Host, Container, Image) check the following:
            1. Single object in a list
            2. Two objects in a list

    When:
        Running update_context_paths

    Then:
        Assert the updated compliance table in the context data is as expected.
        Assert nothing was created.
    """
    demisto_args = {'resourceType': object_type}
    merged_input_context = merge_input_and_output_context(input_context, already_present_output, object_type)
    mocker.patch.object(demisto, 'context', return_value=merged_input_context)
    mocker.patch.object(demisto, 'get', side_effect=input_context_in_path)
    update_results = mocker.patch.object(demisto, 'results', return_value=None)
    append_context = mocker.patch.object(PrismaCloudComputeComplianceTable, 'appendContext', return_value=None)

    update_context_paths(demisto_args)
    assert list(update_results.call_args[0][0]['EntryContext'].keys()) == [expected_context_path]
    assert update_results.call_args[0][0]['EntryContext'][expected_context_path] == expected_context
    assert not append_context.called, 'Should only update context data and not update existing in this test.'


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output, expected_context',
                         [(HOST_UPDATE_INPUT, HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                             'Host', [HOST_OUTPUT_GRID], [HOST_OUTPUT_UPDATED_GRID]),
                          (TWO_HOST_UPDATE_INPUT, TWO_HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                           'Host', TWO_HOST_OUTPUT_GRID, TWO_HOST_OUTPUT_UPDATED_GRID),
                          (CONTAINER_UPDATE_INPUT, CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                           'Container', [CONTAINER_OUTPUT_GRID], [CONTAINER_OUTPUT_UPDATED_GRID]),
                          (TWO_CONTAINER_UPDATE_INPUT,
                           TWO_CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                           'Container', TWO_CONTAINER_OUTPUT_GRID, TWO_CONTAINER_OUTPUT_UPDATED_GRID),
                          (IMAGE_UPDATE_INPUT, IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                           'Image', [IMAGE_OUTPUT_GRID], [IMAGE_OUTPUT_UPDATED_GRID]),
                          (TWO_IMAGE_UPDATE_INPUT, TWO_IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                           'Image', TWO_IMAGE_OUTPUT_GRID, TWO_IMAGE_OUTPUT_UPDATED_GRID)],
                         ids=['Host', 'TwoHosts', 'Container', 'TwoContainers', 'Image', 'TwoImages'])
def test_update_outputs_grid(mocker, input_context, input_context_in_path, object_type, already_present_output, expected_context):
    """
    Given:
        NEW enriched compliance issues with OLD compliance objects ids in the input context data.
        For each compliance object type (Host, Container, Image) check the following:
            1. Single object in a list
            2. Two objects in a list

    When:
        Running update_context_paths

    Then:
        Assert the updated compliance table in the context data is as expected.
        Assert nothing was created.
    """
    grid_id = 'some_grid'
    demisto_args = {'resourceType': object_type, 'gridID': grid_id}
    incident_fields = {"CustomFields": {grid_id: already_present_output}}

    mocker.patch.object(demisto, 'incident', return_value=incident_fields)
    mocker.patch.object(demisto, 'context', return_value=input_context)

    update_results = mocker.patch.object(demisto, 'executeCommand', return_value=None)

    update_context_paths(demisto_args)
    expected_fields = {
        'customFields': {
            grid_id: expected_context
        }
    }

    update_results.assert_called_once_with("setIncident", expected_fields)


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output',
                         [
                             (HOST_INPUT, HOST_INPUT['PrismaCloudCompute']['ReportHostScan'], 'Host', [HOST_OUTPUT]),
                             (CONTAINER_INPUT, CONTAINER_INPUT['PrismaCloudCompute']['ContainersScanResults'], 'Container',
                              [CONTAINER_OUTPUT]),
                             (IMAGE_INPUT, IMAGE_INPUT['PrismaCloudCompute']['ReportsImagesScan'], 'Image', [IMAGE_OUTPUT])],
                         ids=['Host', 'Container', 'Image'])
def test_update_existing_outputs(mocker, input_context, input_context_in_path, object_type, already_present_output):
    """
    Given:
        OLD enriched compliance issues with OLD compliance objects ids in the input context data.
        Given a different compliance object type in each case: Host, Container, Image.

    When:
        Running update_context_paths

    Then:
        Assert nothing was updated.
        Assert nothing was created.
    """
    demisto_args = {'resourceType': object_type}
    merged_input_context = merge_input_and_output_context(input_context, already_present_output, object_type)
    mocker.patch.object(demisto, 'context', return_value=merged_input_context)
    mocker.patch.object(demisto, 'get', return_value=input_context_in_path)
    update_results = mocker.patch.object(demisto, 'results', return_value=None)
    append_context = mocker.patch.object(PrismaCloudComputeComplianceTable, 'appendContext', return_value=None)

    update_context_paths(demisto_args)

    assert not update_results.called, 'Should not update anything in this test.'
    assert not append_context.called, 'Should not create any new outputs in this test.'


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output',
                         [
                             (HOST_INPUT, HOST_INPUT['PrismaCloudCompute']['ReportHostScan'], 'Host', [HOST_OUTPUT_GRID]),
                             (CONTAINER_INPUT, CONTAINER_INPUT['PrismaCloudCompute']['ContainersScanResults'], 'Container',
                              [CONTAINER_OUTPUT_GRID]),
                             (IMAGE_INPUT, IMAGE_INPUT['PrismaCloudCompute']['ReportsImagesScan'], 'Image', [IMAGE_OUTPUT_GRID])],
                         ids=['Host', 'Container', 'Image'])
def test_update_existing_outputs_grid(mocker, input_context, input_context_in_path, object_type, already_present_output):
    """
    Given:
        OLD enriched compliance issues with OLD compliance objects ids in the input context data.
        Given a different compliance object type in each case: Host, Container, Image.

    When:
        Running update_context_paths

    Then:
        Assert the returned output is untouched.
    """
    grid_id = 'some_grid'
    demisto_args = {'resourceType': object_type, 'gridID': grid_id}
    incident_fields = {"CustomFields": {grid_id: already_present_output}}

    mocker.patch.object(demisto, 'incident', return_value=incident_fields)
    mocker.patch.object(demisto, 'context', return_value=input_context)

    update_results = mocker.patch.object(demisto, 'executeCommand', return_value=None)

    update_context_paths(demisto_args)

    update_results.assert_called_once_with("setIncident", {'customFields': {grid_id: already_present_output}})


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output, expected_update, '
                         'expected_update_path, expected_create, expected_create_path',
                         [
                             (TWO_HOST_UPDATE_INPUT, TWO_HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                              'Host', [HOST_OUTPUT], HOST_OUTPUT_UPDATED,
                              'PrismaCloudCompute.ComplianceTable.Host(val.Hostname == obj.Hostname)',
                              [SECOND_HOST_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Host'),
                             (TWO_CONTAINER_UPDATE_INPUT,
                              TWO_CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                              'Container', [CONTAINER_OUTPUT], CONTAINER_OUTPUT_UPDATED,
                              'PrismaCloudCompute.ComplianceTable.Container(val.ContainerID == obj.ContainerID)',
                              [SECOND_CONTAINER_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Container'),
                             (TWO_IMAGE_UPDATE_INPUT, TWO_IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                              'Image', [IMAGE_OUTPUT], IMAGE_OUTPUT_UPDATED,
                              'PrismaCloudCompute.ComplianceTable.Image(val.ImageID == obj.ImageID)',
                              [SECOND_IMAGE_OUTPUT], 'PrismaCloudCompute.ComplianceTable.Image'),
                         ], ids=['Hosts', 'Containers', 'Images'])
def test_create_and_update_outputs(mocker, input_context, input_context_in_path, object_type, already_present_output,
                                   expected_update, expected_update_path, expected_create, expected_create_path):
    """
    Given:
        NEW enriched compliance issues with OLD & NEW compliance objects ids in the input context data.
        Given a different compliance object type in each case: Host, Container, Image.

    When:
        Running update_context_paths

    Then:
        Assert the updated objects in the table are as expected.
        Assert the expected objects were created.
    """
    demisto_args = {'resourceType': object_type}
    merged_input_context = merge_input_and_output_context(input_context, already_present_output, object_type)
    mocker.patch.object(demisto, 'context', return_value=merged_input_context)
    mocker.patch.object(demisto, 'get', return_value=input_context_in_path)
    update_results = mocker.patch.object(demisto, 'results', return_value=None)
    append_context = mocker.patch.object(PrismaCloudComputeComplianceTable, 'appendContext', return_value=None)

    update_context_paths(demisto_args)

    assert list(update_results.call_args[0][0]['EntryContext'].keys()) == [expected_update_path]
    assert update_results.call_args[0][0]['EntryContext'][expected_update_path] == expected_update
    append_context.assert_called_once_with(expected_create_path, expected_create)


@pytest.mark.parametrize('input_context, input_context_in_path, object_type, already_present_output, expected_grid',
                         [
                             (TWO_HOST_UPDATE_INPUT, TWO_HOST_UPDATE_INPUT['PrismaCloudCompute']['ReportHostScan'],
                              'Host', [HOST_OUTPUT_GRID], [SECOND_HOST_OUTPUT_GRID, HOST_OUTPUT_UPDATED_GRID]),
                             (TWO_CONTAINER_UPDATE_INPUT,
                              TWO_CONTAINER_UPDATE_INPUT['PrismaCloudCompute']['ContainersScanResults'],
                              'Container', [CONTAINER_OUTPUT_GRID],
                              [SECOND_CONTAINER_OUTPUT_GRID, CONTAINER_OUTPUT_UPDATED_GRID]),
                             (TWO_IMAGE_UPDATE_INPUT, TWO_IMAGE_UPDATE_INPUT['PrismaCloudCompute']['ReportsImagesScan'],
                              'Image', [IMAGE_OUTPUT_GRID], [SECOND_IMAGE_OUTPUT_GRID, IMAGE_OUTPUT_UPDATED_GRID]),
                         ], ids=['Hosts', 'Containers', 'Images'])
def test_create_and_update_outputs_grid(mocker, input_context, input_context_in_path, object_type, already_present_output,
                                        expected_grid):
    """
    Given:
        NEW enriched compliance issues with OLD & NEW compliance objects ids in the input context data.
        Given a different compliance object type in each case: Host, Container, Image.

    When:
        Running update_context_paths

    Then:
        Assert the updated objects in the table are as expected.
        Assert the expected objects were created.
    """
    grid_id = 'some_grid'
    demisto_args = {'resourceType': object_type, 'gridID': grid_id}
    incident_fields = {"CustomFields": {grid_id: already_present_output}}

    mocker.patch.object(demisto, 'incident', return_value=incident_fields)
    mocker.patch.object(demisto, 'get', return_value=input_context_in_path)
    mocker.patch.object(demisto, 'context', return_value=input_context)

    update_results = mocker.patch.object(demisto, 'executeCommand', return_value=None)

    update_context_paths(demisto_args)

    update_results.assert_called_once_with("setIncident", {'customFields': {grid_id: expected_grid}})
