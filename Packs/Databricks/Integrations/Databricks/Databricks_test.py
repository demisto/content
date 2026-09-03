import copy
import pytest
from Databricks import (
    DatabricksClient,
    convert_epoch_fields,
    cluster_get_command,
    cluster_list_command,
    cluster_create_command,
    cluster_delete_command,
    cluster_start_command,
    job_get_command,
    job_list_command,
    job_create_command,
    job_run_now_command,
    pipeline_get_command,
    pipeline_list_command,
    warehouse_get_command,
    warehouse_list_command,
    sql_statement_execute_command,
    sql_query_get_command,
    sql_query_list_command,
    sql_alert_get_command,
    catalog_get_command,
    catalog_list_command,
    schema_list_command,
    table_get_command,
    table_list_command,
    volume_list_command,
    user_get_command,
    user_list_command,
    group_list_command,
    service_principal_list_command,
    token_list_command,
    secret_list_command,
    secret_scope_list_command,
    dashboard_list_command,
    serving_endpoint_list_command,
    mlflow_model_list_command,
    dbfs_list_command,
    dbfs_get_status_command,
    workspace_list_command,
    ip_access_list_list_command,
    global_init_script_list_command,
    permissions_get_command,
    repo_list_command,
    git_credential_list_command,
    fetch_incidents,
    test_module,
)


@pytest.fixture
def client():
    return DatabricksClient(
        base_url='https://dbc-test.cloud.databricks.com',
        verify=False,
        headers={'Authorization': 'Bearer test-token'},
    )


CLUSTER_RESPONSE = {
    'cluster_id': 'abc-123',
    'cluster_name': 'test-cluster',
    'state': 'RUNNING',
    'creator_user_name': 'user@example.com',
    'spark_version': '14.3.x-scala2.12',
    'node_type_id': 'i3.xlarge',
    'num_workers': 2,
    'autotermination_minutes': 120,
    'start_time': 1693000000000,
}

JOB_RESPONSE = {
    'job_id': 42,
    'creator_user_name': 'user@example.com',
    'created_time': 1693000000000,
    'settings': {'name': 'test-job'},
}

WAREHOUSE_RESPONSE = {
    'id': 'wh-001',
    'name': 'test-warehouse',
    'cluster_size': '2X-Small',
    'state': 'RUNNING',
    'num_clusters': 1,
    'creator_name': 'user@example.com',
    'num_active_sessions': 0,
}


class TestClusterCommands:
    def test_cluster_get(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value=copy.deepcopy(CLUSTER_RESPONSE))
        result = cluster_get_command(client, {'cluster_id': 'abc-123'})
        assert result.outputs['cluster_id'] == 'abc-123'
        assert result.outputs['state'] == 'RUNNING'
        assert result.outputs_prefix == 'Databricks.Cluster'
        assert result.outputs_key_field == 'cluster_id'

    def test_cluster_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'clusters': [copy.deepcopy(CLUSTER_RESPONSE)]})
        result = cluster_list_command(client, {})
        assert len(result.outputs) == 1
        assert result.outputs[0]['cluster_name'] == 'test-cluster'

    def test_cluster_create(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'cluster_id': 'new-123'})
        result = cluster_create_command(client, {
            'cluster_name': 'new-cluster',
            'spark_version': '14.3.x-scala2.12',
            'node_type_id': 'i3.xlarge',
            'num_workers': '4',
        })
        assert result.outputs['cluster_id'] == 'new-123'
        assert result.outputs_prefix == 'Databricks.Cluster'
        assert result.outputs_key_field == 'cluster_id'

    def test_cluster_delete(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value={})
        result = cluster_delete_command(client, {'cluster_id': 'abc-123'})
        assert 'terminated' in result.readable_output.lower()

    def test_cluster_start(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value={})
        result = cluster_start_command(client, {'cluster_id': 'abc-123'})
        assert 'start' in result.readable_output.lower()


class TestJobCommands:
    def test_job_get(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value=copy.deepcopy(JOB_RESPONSE))
        result = job_get_command(client, {'job_id': '42'})
        assert result.outputs['job_id'] == 42
        assert result.outputs_prefix == 'Databricks.Job'
        assert result.outputs_key_field == 'job_id'

    def test_job_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'jobs': [copy.deepcopy(JOB_RESPONSE)]})
        result = job_list_command(client, {})
        assert len(result.outputs) == 1

    def test_job_create(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'job_id': 99})
        result = job_create_command(client, {
            'name': 'new-job',
            'tasks': '[{"task_key": "t1"}]',
        })
        assert result.outputs['job_id'] == 99

    def test_job_run_now(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'run_id': 555, 'number_in_job': 1})
        result = job_run_now_command(client, {'job_id': '42'})
        assert result.outputs['run_id'] == 555


class TestPipelineCommands:
    def test_pipeline_get(self, client, mocker):
        response = {'pipeline_id': 'pipe-1', 'name': 'test-pipe', 'state': 'RUNNING'}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = pipeline_get_command(client, {'pipeline_id': 'pipe-1'})
        assert result.outputs['pipeline_id'] == 'pipe-1'

    def test_pipeline_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'statuses': [{'pipeline_id': 'pipe-1', 'name': 'p1'}]})
        result = pipeline_list_command(client, {})
        assert len(result.outputs) == 1


class TestWarehouseCommands:
    def test_warehouse_get(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value=WAREHOUSE_RESPONSE)
        result = warehouse_get_command(client, {'warehouse_id': 'wh-001'})
        assert result.outputs['id'] == 'wh-001'
        assert result.outputs_prefix == 'Databricks.Warehouse'
        assert result.outputs_key_field == 'id'

    def test_warehouse_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'warehouses': [WAREHOUSE_RESPONSE]})
        result = warehouse_list_command(client, {})
        assert len(result.outputs) == 1


class TestSQLCommands:
    def test_sql_statement_execute(self, client, mocker):
        response = {'statement_id': 'stmt-1', 'status': {'state': 'SUCCEEDED'}}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = sql_statement_execute_command(client, {
            'warehouse_id': 'wh-001', 'statement': 'SELECT 1'
        })
        assert result.outputs['statement_id'] == 'stmt-1'

    def test_sql_query_get(self, client, mocker):
        response = {'id': 'q-1', 'name': 'test-query', 'query': 'SELECT 1'}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = sql_query_get_command(client, {'query_id': 'q-1'})
        assert result.outputs['id'] == 'q-1'

    def test_sql_query_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'results': [{'id': 'q-1', 'name': 'q'}]})
        result = sql_query_list_command(client, {})
        assert len(result.outputs) == 1

    def test_sql_alert_get(self, client, mocker):
        response = {'id': 'a-1', 'display_name': 'test-alert', 'state': 'UNKNOWN',
                     'lifecycle_state': 'ACTIVE', 'create_time': '2026-08-31T22:53:15Z'}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = sql_alert_get_command(client, {'alert_id': 'a-1'})
        assert result.outputs['id'] == 'a-1'
        assert result.outputs['display_name'] == 'test-alert'


class TestUnityCatalogCommands:
    def test_catalog_get(self, client, mocker):
        response = {'name': 'main', 'owner': 'admin', 'metastore_id': 'ms-1'}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = catalog_get_command(client, {'name': 'main'})
        assert result.outputs['name'] == 'main'
        assert result.outputs_prefix == 'Databricks.Catalog'
        assert result.outputs_key_field == 'name'

    def test_catalog_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'catalogs': [{'name': 'main'}]})
        result = catalog_list_command(client, {})
        assert len(result.outputs) == 1

    def test_schema_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'schemas': [{'name': 'default', 'catalog_name': 'main'}]})
        result = schema_list_command(client, {'catalog_name': 'main'})
        assert result.outputs[0]['catalog_name'] == 'main'

    def test_table_get(self, client, mocker):
        response = {'name': 't1', 'catalog_name': 'main', 'schema_name': 'default',
                     'table_type': 'MANAGED', 'full_name': 'main.default.t1'}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = table_get_command(client, {'full_name': 'main.default.t1'})
        assert result.outputs['full_name'] == 'main.default.t1'

    def test_table_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'tables': [{'name': 't1', 'table_type': 'MANAGED'}]})
        result = table_list_command(client, {'catalog_name': 'main', 'schema_name': 'default'})
        assert len(result.outputs) == 1

    def test_volume_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'volumes': [{'name': 'v1', 'volume_type': 'MANAGED'}]})
        result = volume_list_command(client, {'catalog_name': 'main', 'schema_name': 'default'})
        assert len(result.outputs) == 1


class TestIAMCommands:
    def test_user_get(self, client, mocker):
        response = {'id': '1', 'userName': 'user@example.com', 'displayName': 'User', 'active': True}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = user_get_command(client, {'user_id': '1'})
        assert result.outputs['userName'] == 'user@example.com'

    def test_user_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'Resources': [{'id': '1', 'userName': 'user@example.com'}]})
        result = user_list_command(client, {})
        assert len(result.outputs) == 1

    def test_group_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'Resources': [{'id': '1', 'displayName': 'admins'}]})
        result = group_list_command(client, {})
        assert len(result.outputs) == 1

    def test_service_principal_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'Resources': [{'id': '1', 'displayName': 'sp1'}]})
        result = service_principal_list_command(client, {})
        assert len(result.outputs) == 1

    def test_permissions_get(self, client, mocker):
        response = {'object_id': 'abc', 'object_type': 'clusters', 'access_control_list': []}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = permissions_get_command(client, {'object_type': 'clusters', 'object_id': 'abc'})
        assert result.outputs['object_id'] == 'abc'


class TestTokenAndSecretCommands:
    def test_token_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'token_infos': [{'token_id': 't1', 'comment': 'test'}]})
        result = token_list_command(client, {})
        assert len(result.outputs) == 1

    def test_secret_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'secrets': [{'key': 'my-key'}]})
        result = secret_list_command(client, {'scope': 'my-scope'})
        assert result.outputs[0]['key'] == 'my-key'

    def test_secret_scope_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'scopes': [{'name': 'my-scope'}]})
        result = secret_scope_list_command(client, {})
        assert result.outputs[0]['name'] == 'my-scope'


class TestMiscCommands:
    def test_dashboard_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'dashboards': [{'dashboard_id': 'd1', 'display_name': 'D1'}]})
        result = dashboard_list_command(client, {})
        assert len(result.outputs) == 1

    def test_serving_endpoint_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'endpoints': [{'name': 'ep1'}]})
        result = serving_endpoint_list_command(client, {})
        assert len(result.outputs) == 1

    def test_mlflow_model_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'registered_models': [{'name': 'model1'}]})
        result = mlflow_model_list_command(client, {})
        assert result.outputs[0]['name'] == 'model1'

    def test_dbfs_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'files': [{'path': '/data/file.csv', 'is_dir': False}]})
        result = dbfs_list_command(client, {'path': '/data'})
        assert result.outputs[0]['path'] == '/data/file.csv'

    def test_dbfs_get_status(self, client, mocker):
        response = {'path': '/data', 'is_dir': True, 'file_size': 0}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = dbfs_get_status_command(client, {'path': '/data'})
        assert result.outputs['is_dir'] is True

    def test_workspace_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'objects': [{'object_type': 'NOTEBOOK', 'path': '/nb'}]})
        result = workspace_list_command(client, {'path': '/'})
        assert result.outputs[0]['object_type'] == 'NOTEBOOK'

    def test_ip_access_list_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'ip_access_lists': [{'list_id': 'l1', 'label': 'test'}]})
        result = ip_access_list_list_command(client, {})
        assert result.outputs[0]['list_id'] == 'l1'

    def test_global_init_script_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'scripts': [{'script_id': 's1', 'name': 'init'}]})
        result = global_init_script_list_command(client, {})
        assert result.outputs[0]['script_id'] == 's1'

    def test_repo_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'repos': [{'id': 1, 'url': 'https://github.com/test'}]})
        result = repo_list_command(client, {})
        assert len(result.outputs) == 1

    def test_git_credential_list(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            return_value={'credentials': [{'credential_id': 1, 'git_provider': 'gitHub'}]})
        result = git_credential_list_command(client, {})
        assert result.outputs[0]['git_provider'] == 'gitHub'


class TestFetchIncidents:
    def test_fetch_incidents_failed_jobs(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={'results': []})
        mocker.patch.object(client, 'list_job_runs', return_value={
            'runs': [{
                'run_id': 100,
                'run_name': 'failing-job',
                'start_time': 1693000001000,
                'state': {'result_state': 'FAILED', 'state_message': 'Task failed'},
            }]
        })
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '10',
            'first_fetch': '3 days',
            'fetch_types': ['Failed Jobs'],
        }, {})
        assert len(incidents) == 1
        assert 'failing-job' in incidents[0]['name']
        assert next_run['last_fetch_time'] == 1693000001000
        assert 'seen_ids' in next_run

    def test_fetch_incidents_sql_alerts(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={
            'results': [{
                'id': 'a-1',
                'display_name': 'Row Count Alert',
                'state': 'UNKNOWN',
                'lifecycle_state': 'ACTIVE',
                'create_time': '2026-08-31T22:53:15Z',
                'update_time': '2026-08-31T23:00:00Z',
            }]
        })
        mocker.patch.object(client, 'list_job_runs', return_value={'runs': []})
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '10',
            'first_fetch': '3 days',
            'fetch_types': ['SQL Alerts'],
        }, {})
        assert len(incidents) == 1
        assert 'Row Count Alert' in incidents[0]['name']
        assert 'seen_ids' in next_run
        assert next_run['last_fetch_time'] > 0

    def test_fetch_incidents_empty(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={'results': []})
        mocker.patch.object(client, 'list_job_runs', return_value={'runs': []})
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '10',
            'first_fetch': '3 days',
        }, {})
        assert incidents == []
        assert 'seen_ids' in next_run

    def test_fetch_incidents_with_last_run(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={'results': []})
        mocker.patch.object(client, 'list_job_runs', return_value={'runs': []})
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '10',
        }, {'last_fetch_time': 1693000000000, 'seen_ids': ['prev-1']})
        assert next_run['last_fetch_time'] == 1693000000000

    def test_fetch_incidents_dedup_seen_ids(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={'results': []})
        mocker.patch.object(client, 'list_job_runs', return_value={
            'runs': [
                {
                    'run_id': 100,
                    'run_name': 'already-seen',
                    'start_time': 1693000001000,
                    'state': {'result_state': 'FAILED'},
                },
                {
                    'run_id': 101,
                    'run_name': 'new-failure',
                    'start_time': 1693000001000,
                    'state': {'result_state': 'FAILED'},
                },
            ]
        })
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '10',
            'fetch_types': ['Failed Jobs'],
        }, {'last_fetch_time': 1693000001000, 'seen_ids': ['100']})
        assert len(incidents) == 1
        assert 'new-failure' in incidents[0]['name']

    def test_fetch_incidents_max_fetch_cap(self, client, mocker):
        mocker.patch.object(client, 'list_sql_alerts', return_value={'results': []})
        mocker.patch.object(client, 'list_job_runs', return_value={'runs': []})
        next_run, incidents = fetch_incidents(client, {
            'max_fetch': '9999',
            'first_fetch': '3 days',
        }, {})
        assert incidents == []


class TestConvertEpochFields:
    def test_convert_dict(self):
        data = {'start_time': 1693000000000, 'name': 'test'}
        convert_epoch_fields(data)
        assert isinstance(data['start_time'], str)
        assert 'T' in data['start_time']
        assert data['name'] == 'test'

    def test_convert_list(self):
        data = [{'created_time': 1693000000000}, {'created_time': 1693100000000}]
        convert_epoch_fields(data)
        assert all(isinstance(d['created_time'], str) for d in data)

    def test_no_conversion_for_zero(self):
        data = {'start_time': 0}
        convert_epoch_fields(data)
        assert data['start_time'] == 0

    def test_no_conversion_for_non_epoch_fields(self):
        data = {'cluster_id': 'abc', 'name': 'test'}
        convert_epoch_fields(data)
        assert data == {'cluster_id': 'abc', 'name': 'test'}

    def test_cluster_get_converts_epochs(self, client, mocker):
        response = {**CLUSTER_RESPONSE}
        mocker.patch.object(client, '_http_request', return_value=response)
        result = cluster_get_command(client, {'cluster_id': 'abc-123'})
        assert isinstance(result.outputs['start_time'], str)


class TestTestModule:
    def test_test_module_success(self, client, mocker):
        mocker.patch.object(client, '_http_request', return_value={'warehouses': []})
        result = test_module(client)
        assert result == 'ok'

    def test_test_module_failure(self, client, mocker):
        mocker.patch.object(client, '_http_request',
                            side_effect=Exception('Connection refused'))
        with pytest.raises(Exception, match='Failed to connect'):
            test_module(client)
