import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import traceback
import urllib3

urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def parse_json_arg(args: dict, key: str):
    val = args.get(key)
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    return json.loads(val)


class DatabricksClient(BaseClient):

    # ---- Clusters (API 2.1) ----

    def get_cluster(self, cluster_id: str) -> dict:
        return self._http_request('GET', '/api/2.1/clusters/get', params={'cluster_id': cluster_id})

    def list_clusters(self) -> dict:
        return self._http_request('GET', '/api/2.1/clusters/list')

    def create_cluster(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/create', json_data=assign_params(**kwargs))

    def edit_cluster(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/edit', json_data=assign_params(**kwargs))

    def delete_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/delete', json_data={'cluster_id': cluster_id})

    def permanent_delete_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/permanent-delete', json_data={'cluster_id': cluster_id})

    def start_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/start', json_data={'cluster_id': cluster_id})

    def restart_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/restart', json_data={'cluster_id': cluster_id})

    def resize_cluster(self, cluster_id: str, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/resize',
                                  json_data=assign_params(cluster_id=cluster_id, **kwargs))

    def pin_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/pin', json_data={'cluster_id': cluster_id})

    def unpin_cluster(self, cluster_id: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/unpin', json_data={'cluster_id': cluster_id})

    def change_cluster_owner(self, cluster_id: str, owner_username: str) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/change-owner',
                                  json_data={'cluster_id': cluster_id, 'owner_username': owner_username})

    def list_zones(self) -> dict:
        return self._http_request('GET', '/api/2.1/clusters/list-zones')

    def update_cluster(self, cluster_id: str, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/clusters/update',
                                  json_data=assign_params(cluster_id=cluster_id, **kwargs))

    # ---- Cluster Policies (API 2.0) ----

    def get_cluster_policy(self, policy_id: str) -> dict:
        return self._http_request('GET', '/api/2.0/policies/clusters/get', params={'policy_id': policy_id})

    def list_cluster_policies(self) -> dict:
        return self._http_request('GET', '/api/2.0/policies/clusters/list')

    def create_cluster_policy(self, name: str, definition: str) -> dict:
        return self._http_request('POST', '/api/2.0/policies/clusters/create',
                                  json_data={'name': name, 'definition': definition})

    def edit_cluster_policy(self, policy_id: str, name: str = None, definition: str = None) -> dict:
        return self._http_request('POST', '/api/2.0/policies/clusters/edit',
                                  json_data=assign_params(policy_id=policy_id, name=name, definition=definition))

    def delete_cluster_policy(self, policy_id: str) -> dict:
        return self._http_request('POST', '/api/2.0/policies/clusters/delete',
                                  json_data={'policy_id': policy_id})

    # ---- Instance Pools (API 2.0) ----

    def get_instance_pool(self, instance_pool_id: str) -> dict:
        return self._http_request('GET', '/api/2.0/instance-pools/get',
                                  params={'instance_pool_id': instance_pool_id})

    def list_instance_pools(self) -> dict:
        return self._http_request('GET', '/api/2.0/instance-pools/list')

    def create_instance_pool(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/instance-pools/create', json_data=assign_params(**kwargs))

    def edit_instance_pool(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/instance-pools/edit', json_data=assign_params(**kwargs))

    def delete_instance_pool(self, instance_pool_id: str) -> dict:
        return self._http_request('POST', '/api/2.0/instance-pools/delete',
                                  json_data={'instance_pool_id': instance_pool_id})

    # ---- Libraries (API 2.0) ----

    def get_library_status(self, cluster_id: str) -> dict:
        return self._http_request('GET', '/api/2.0/libraries/cluster-status',
                                  params={'cluster_id': cluster_id})

    def get_all_library_statuses(self) -> dict:
        return self._http_request('GET', '/api/2.0/libraries/all-cluster-statuses')

    def install_libraries(self, cluster_id: str, libraries: list) -> dict:
        return self._http_request('POST', '/api/2.0/libraries/install',
                                  json_data={'cluster_id': cluster_id, 'libraries': libraries})

    def uninstall_libraries(self, cluster_id: str, libraries: list) -> dict:
        return self._http_request('POST', '/api/2.0/libraries/uninstall',
                                  json_data={'cluster_id': cluster_id, 'libraries': libraries})

    # ---- Command Execution (API 1.2) ----

    def create_context(self, cluster_id: str, language: str) -> dict:
        return self._http_request('POST', '/api/1.2/contexts/create',
                                  json_data={'clusterId': cluster_id, 'language': language})

    def destroy_context(self, cluster_id: str, context_id: str) -> dict:
        return self._http_request('POST', '/api/1.2/contexts/destroy',
                                  json_data={'clusterId': cluster_id, 'contextId': context_id})

    def get_context_status(self, cluster_id: str, context_id: str) -> dict:
        return self._http_request('GET', '/api/1.2/contexts/status',
                                  params={'clusterId': cluster_id, 'contextId': context_id})

    def execute_command(self, cluster_id: str, context_id: str, language: str, command: str) -> dict:
        return self._http_request('POST', '/api/1.2/commands/execute',
                                  json_data={'clusterId': cluster_id, 'contextId': context_id,
                                             'language': language, 'command': command})

    def get_command_status(self, cluster_id: str, command_id: str, context_id: str) -> dict:
        return self._http_request('GET', '/api/1.2/commands/status',
                                  params={'clusterId': cluster_id, 'commandId': command_id,
                                          'contextId': context_id})

    def cancel_command(self, cluster_id: str, command_id: str, context_id: str) -> dict:
        return self._http_request('POST', '/api/1.2/commands/cancel',
                                  json_data={'clusterId': cluster_id, 'commandId': command_id,
                                             'contextId': context_id})

    # ---- Jobs (API 2.2) ----

    def get_job(self, job_id: str) -> dict:
        return self._http_request('GET', '/api/2.2/jobs/get', params={'job_id': job_id})

    def list_jobs(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.2/jobs/list', params=assign_params(**kwargs))

    def create_job(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.2/jobs/create', json_data=assign_params(**kwargs))

    def reset_job(self, job_id: str, new_settings: dict) -> dict:
        return self._http_request('POST', '/api/2.2/jobs/reset',
                                  json_data={'job_id': int(job_id), 'new_settings': new_settings})

    def update_job(self, job_id: str, fields_to_update: dict) -> dict:
        return self._http_request('POST', '/api/2.2/jobs/update',
                                  json_data={'job_id': int(job_id), **fields_to_update})

    def delete_job(self, job_id: str) -> dict:
        return self._http_request('POST', '/api/2.2/jobs/delete', json_data={'job_id': int(job_id)})

    def run_job_now(self, job_id: str, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.2/jobs/run-now',
                                  json_data=assign_params(job_id=int(job_id), **kwargs))

    def list_job_runs(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.2/jobs/runs/list', params=assign_params(**kwargs))

    # ---- Pipelines (API 2.0) ----

    def get_pipeline(self, pipeline_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/pipelines/{pipeline_id}')

    def list_pipelines(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/pipelines', params=assign_params(**kwargs))

    def create_pipeline(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/pipelines', json_data=assign_params(**kwargs))

    def update_pipeline(self, pipeline_id: str, **kwargs) -> dict:
        return self._http_request('PUT', f'/api/2.0/pipelines/{pipeline_id}',
                                  json_data=assign_params(**kwargs))

    def delete_pipeline(self, pipeline_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/pipelines/{pipeline_id}')

    def clone_pipeline(self, pipeline_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/pipelines/{pipeline_id}/clone')

    def start_pipeline(self, pipeline_id: str, **kwargs) -> dict:
        return self._http_request('POST', f'/api/2.0/pipelines/{pipeline_id}/updates',
                                  json_data=assign_params(**kwargs))

    def stop_pipeline(self, pipeline_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/pipelines/{pipeline_id}/stop')

    def get_pipeline_events(self, pipeline_id: str, **kwargs) -> dict:
        return self._http_request('GET', f'/api/2.0/pipelines/{pipeline_id}/events',
                                  params=assign_params(**kwargs))

    def list_pipeline_updates(self, pipeline_id: str, **kwargs) -> dict:
        return self._http_request('GET', f'/api/2.0/pipelines/{pipeline_id}/updates',
                                  params=assign_params(**kwargs))

    def get_pipeline_update(self, pipeline_id: str, update_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/pipelines/{pipeline_id}/updates/{update_id}')

    def apply_pipeline_environment(self, pipeline_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/pipelines/{pipeline_id}/environment/apply')

    # ---- DBFS (API 2.0) ----

    def dbfs_get_status(self, path: str) -> dict:
        return self._http_request('GET', '/api/2.0/dbfs/get-status', params={'path': path})

    def dbfs_list(self, path: str) -> dict:
        return self._http_request('GET', '/api/2.0/dbfs/list', params={'path': path})

    def dbfs_read(self, path: str, offset: int = None, length: int = None) -> dict:
        return self._http_request('GET', '/api/2.0/dbfs/read',
                                  params=assign_params(path=path, offset=offset, length=length))

    def dbfs_create(self, path: str, overwrite: bool = None) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/create',
                                  json_data=assign_params(path=path, overwrite=overwrite))

    def dbfs_add_block(self, handle: int, data: str) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/add-block',
                                  json_data={'handle': handle, 'data': data})

    def dbfs_close(self, handle: int) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/close', json_data={'handle': handle})

    def dbfs_put(self, path: str, contents: str = None, overwrite: bool = None) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/put',
                                  json_data=assign_params(path=path, contents=contents, overwrite=overwrite))

    def dbfs_delete(self, path: str, recursive: bool = None) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/delete',
                                  json_data=assign_params(path=path, recursive=recursive))

    def dbfs_mkdirs(self, path: str) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/mkdirs', json_data={'path': path})

    def dbfs_move(self, source_path: str, destination_path: str) -> dict:
        return self._http_request('POST', '/api/2.0/dbfs/move',
                                  json_data={'source_path': source_path, 'destination_path': destination_path})

    # ---- Workspace (API 2.0) ----

    def workspace_get_status(self, path: str) -> dict:
        return self._http_request('GET', '/api/2.0/workspace/get-status', params={'path': path})

    def workspace_list(self, path: str) -> dict:
        return self._http_request('GET', '/api/2.0/workspace/list', params={'path': path})

    def workspace_export(self, path: str, format_str: str = None) -> dict:
        return self._http_request('GET', '/api/2.0/workspace/export',
                                  params=assign_params(path=path, format=format_str))

    def workspace_import(self, path: str, content: str, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/workspace/import',
                                  json_data=assign_params(path=path, content=content, **kwargs))

    def workspace_delete(self, path: str, recursive: bool = None) -> dict:
        return self._http_request('POST', '/api/2.0/workspace/delete',
                                  json_data=assign_params(path=path, recursive=recursive))

    def workspace_mkdirs(self, path: str) -> dict:
        return self._http_request('POST', '/api/2.0/workspace/mkdirs', json_data={'path': path})

    # ---- Git Credentials (API 2.0) ----

    def get_git_credential(self, credential_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/git-credentials/{credential_id}')

    def list_git_credentials(self) -> dict:
        return self._http_request('GET', '/api/2.0/git-credentials')

    def create_git_credential(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/git-credentials', json_data=assign_params(**kwargs))

    def update_git_credential(self, credential_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/git-credentials/{credential_id}',
                                  json_data=assign_params(**kwargs))

    def delete_git_credential(self, credential_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/git-credentials/{credential_id}')

    # ---- Repos (API 2.0) ----

    def get_repo(self, repo_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/repos/{repo_id}')

    def list_repos(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/repos', params=assign_params(**kwargs))

    def create_repo(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/repos', json_data=assign_params(**kwargs))

    def update_repo(self, repo_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/repos/{repo_id}', json_data=assign_params(**kwargs))

    # ---- SQL Warehouses (API 2.0) ----

    def get_warehouse(self, warehouse_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/sql/warehouses/{warehouse_id}')

    def list_warehouses(self) -> dict:
        return self._http_request('GET', '/api/2.0/sql/warehouses')

    def create_warehouse(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/sql/warehouses', json_data=assign_params(**kwargs))

    def edit_warehouse(self, warehouse_id: str, **kwargs) -> dict:
        return self._http_request('POST', f'/api/2.0/sql/warehouses/{warehouse_id}/edit',
                                  json_data=assign_params(**kwargs))

    def delete_warehouse(self, warehouse_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/sql/warehouses/{warehouse_id}')

    def start_warehouse(self, warehouse_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/sql/warehouses/{warehouse_id}/start')

    def stop_warehouse(self, warehouse_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/sql/warehouses/{warehouse_id}/stop')

    def get_warehouse_config(self) -> dict:
        return self._http_request('GET', '/api/2.0/sql/config/warehouses')

    def set_warehouse_config(self, config: dict) -> dict:
        return self._http_request('PUT', '/api/2.0/sql/config/warehouses', json_data=config)

    # ---- SQL Statements (API 2.0) ----

    def execute_sql_statement(self, warehouse_id: str, statement: str, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/sql/statements',
                                  json_data=assign_params(warehouse_id=warehouse_id, statement=statement, **kwargs))

    def get_sql_statement_status(self, statement_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/sql/statements/{statement_id}')

    def get_sql_result_chunk(self, statement_id: str, chunk_index: int) -> dict:
        return self._http_request('GET',
                                  f'/api/2.0/sql/statements/{statement_id}/result/chunks/{chunk_index}')

    def cancel_sql_statement(self, statement_id: str) -> dict:
        return self._http_request('POST', f'/api/2.0/sql/statements/{statement_id}/cancel')

    # ---- SQL Queries (API 2.0) ----

    def get_sql_query(self, query_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/sql/queries/{query_id}')

    def list_sql_queries(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/sql/queries', params=assign_params(**kwargs))

    def create_sql_query(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/sql/queries', json_data=assign_params(**kwargs))

    def update_sql_query(self, query_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/sql/queries/{query_id}',
                                  json_data=assign_params(**kwargs))

    def delete_sql_query(self, query_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/sql/queries/{query_id}')

    # ---- SQL Alerts (API 2.0) ----

    def list_sql_alerts(self) -> dict:
        return self._http_request('GET', '/api/2.0/sql/alerts')

    def get_sql_alert(self, alert_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/sql/alerts/{alert_id}')

    def create_sql_alert(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/sql/alerts', json_data=assign_params(**kwargs))

    def update_sql_alert(self, alert_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/sql/alerts/{alert_id}',
                                  json_data=assign_params(**kwargs))

    def delete_sql_alert(self, alert_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/sql/alerts/{alert_id}')

    # ---- SQL Query History (API 2.0) ----

    def list_sql_query_history(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/sql/history/queries', params=assign_params(**kwargs))

    # ---- Serving Endpoints (API 2.0) ----

    def list_serving_endpoints(self) -> dict:
        return self._http_request('GET', '/api/2.0/serving-endpoints')

    def get_serving_endpoint(self, name: str) -> dict:
        return self._http_request('GET', f'/api/2.0/serving-endpoints/{name}')

    def create_serving_endpoint(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/serving-endpoints', json_data=assign_params(**kwargs))

    def update_serving_endpoint_config(self, name: str, served_entities: list) -> dict:
        return self._http_request('PUT', f'/api/2.0/serving-endpoints/{name}/config',
                                  json_data={'served_entities': served_entities})

    def delete_serving_endpoint(self, name: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/serving-endpoints/{name}')

    def query_serving_endpoint(self, name: str, inputs: dict) -> dict:
        return self._http_request('POST', f'/api/2.0/serving-endpoints/{name}/invocations',
                                  json_data=inputs)

    def get_serving_endpoint_logs(self, name: str, served_model_name: str) -> dict:
        return self._http_request('GET',
                                  f'/api/2.0/serving-endpoints/{name}/served-models/{served_model_name}/logs')

    # ---- Vector Search (API 2.0) ----

    def list_vector_search_endpoints(self) -> dict:
        return self._http_request('GET', '/api/2.0/vector-search/endpoints')

    def get_vector_search_endpoint(self, name: str) -> dict:
        return self._http_request('GET', f'/api/2.0/vector-search/endpoints/{name}')

    def create_vector_search_endpoint(self, name: str, endpoint_type: str) -> dict:
        return self._http_request('POST', '/api/2.0/vector-search/endpoints',
                                  json_data={'name': name, 'endpoint_type': endpoint_type})

    def delete_vector_search_endpoint(self, name: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/vector-search/endpoints/{name}')

    def get_vector_search_metrics(self, name: str) -> dict:
        return self._http_request('POST', f'/api/2.0/vector-search/endpoints/{name}/metrics')

    # ---- MLflow (API 2.0) ----

    def get_mlflow_metric_history(self, run_id: str, metric_key: str) -> dict:
        return self._http_request('GET', '/api/2.0/mlflow/metrics/get-history',
                                  params=assign_params(run_id=run_id, metric_key=metric_key))

    def list_mlflow_models(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/mlflow/registered-models/list',
                                  params=assign_params(**kwargs))

    def get_mlflow_model(self, name: str) -> dict:
        return self._http_request('GET', '/api/2.0/mlflow/databricks/registered-models/get',
                                  params={'name': name})

    def create_mlflow_model_version(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/mlflow/model-versions/create',
                                  json_data=assign_params(**kwargs))

    def get_mlflow_model_version(self, name: str, version: str) -> dict:
        return self._http_request('GET', '/api/2.0/mlflow/model-versions/get',
                                  params={'name': name, 'version': version})

    def search_mlflow_model_versions(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/mlflow/model-versions/search',
                                  params=assign_params(**kwargs))

    def delete_mlflow_model_version(self, name: str, version: str) -> dict:
        return self._http_request('DELETE', '/api/2.0/mlflow/model-versions/delete',
                                  params={'name': name, 'version': version})

    def transition_mlflow_model_version_stage(self, name: str, version: str, stage: str) -> dict:
        return self._http_request('POST', '/api/2.0/mlflow/databricks/model-versions/transition-stage',
                                  json_data={'name': name, 'version': version, 'stage': stage,
                                             'archive_existing_versions': True})

    # ---- Unity Catalog — Catalogs (API 2.1) ----

    def get_catalog(self, name: str) -> dict:
        return self._http_request('GET', f'/api/2.1/unity-catalog/catalogs/{name}')

    def list_catalogs(self) -> dict:
        return self._http_request('GET', '/api/2.1/unity-catalog/catalogs')

    def create_catalog(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/unity-catalog/catalogs',
                                  json_data=assign_params(**kwargs))

    def update_catalog(self, name: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.1/unity-catalog/catalogs/{name}',
                                  json_data=assign_params(**kwargs))

    def delete_catalog(self, name: str, force: bool = None) -> dict:
        return self._http_request('DELETE', f'/api/2.1/unity-catalog/catalogs/{name}',
                                  params=assign_params(force=force))

    # ---- Unity Catalog — Schemas (API 2.1) ----

    def get_schema(self, full_name: str) -> dict:
        return self._http_request('GET', f'/api/2.1/unity-catalog/schemas/{full_name}')

    def list_schemas(self, catalog_name: str) -> dict:
        return self._http_request('GET', '/api/2.1/unity-catalog/schemas',
                                  params={'catalog_name': catalog_name})

    def create_schema(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/unity-catalog/schemas',
                                  json_data=assign_params(**kwargs))

    def update_schema(self, full_name: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.1/unity-catalog/schemas/{full_name}',
                                  json_data=assign_params(**kwargs))

    def delete_schema(self, full_name: str) -> dict:
        return self._http_request('DELETE', f'/api/2.1/unity-catalog/schemas/{full_name}')

    # ---- Unity Catalog — Tables (API 2.1) ----

    def get_table(self, full_name: str) -> dict:
        return self._http_request('GET', f'/api/2.1/unity-catalog/tables/{full_name}')

    def list_tables(self, catalog_name: str, schema_name: str, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.1/unity-catalog/tables',
                                  params=assign_params(catalog_name=catalog_name,
                                                       schema_name=schema_name, **kwargs))

    def delete_table(self, full_name: str) -> dict:
        return self._http_request('DELETE', f'/api/2.1/unity-catalog/tables/{full_name}')

    def table_exists(self, full_name: str) -> dict:
        return self._http_request('GET', f'/api/2.1/unity-catalog/tables/{full_name}/exists')

    def list_table_summaries(self, catalog_name: str, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.1/unity-catalog/table-summaries',
                                  params=assign_params(catalog_name=catalog_name, **kwargs))

    # ---- Unity Catalog — Volumes (API 2.1) ----

    def get_volume(self, full_name: str) -> dict:
        return self._http_request('GET', f'/api/2.1/unity-catalog/volumes/{full_name}')

    def list_volumes(self, catalog_name: str, schema_name: str) -> dict:
        return self._http_request('GET', '/api/2.1/unity-catalog/volumes',
                                  params=assign_params(catalog_name=catalog_name,
                                                       schema_name=schema_name))

    def create_volume(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.1/unity-catalog/volumes',
                                  json_data=assign_params(**kwargs))

    def update_volume(self, full_name: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.1/unity-catalog/volumes/{full_name}',
                                  json_data=assign_params(**kwargs))

    def delete_volume(self, full_name: str) -> dict:
        return self._http_request('DELETE', f'/api/2.1/unity-catalog/volumes/{full_name}')

    # ---- Unity Catalog — Grants (API 2.1) ----

    def get_grants(self, securable_type: str, full_name: str) -> dict:
        return self._http_request('GET',
                                  f'/api/2.1/unity-catalog/permissions/{securable_type}/{full_name}')

    def update_grants(self, securable_type: str, full_name: str, changes: list) -> dict:
        return self._http_request('PATCH',
                                  f'/api/2.1/unity-catalog/permissions/{securable_type}/{full_name}',
                                  json_data={'changes': changes})

    # ---- IAM — Users (SCIM) ----

    def get_user(self, user_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/preview/scim/v2/Users/{user_id}')

    def list_users(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/preview/scim/v2/Users',
                                  params=assign_params(**kwargs))

    def create_user(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/preview/scim/v2/Users',
                                  json_data=assign_params(**kwargs))

    def update_user(self, user_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/preview/scim/v2/Users/{user_id}',
                                  json_data=assign_params(**kwargs))

    def delete_user(self, user_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/preview/scim/v2/Users/{user_id}')

    # ---- IAM — Groups (SCIM) ----

    def get_group(self, group_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/preview/scim/v2/Groups/{group_id}')

    def list_groups(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/preview/scim/v2/Groups',
                                  params=assign_params(**kwargs))

    def create_group(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/preview/scim/v2/Groups',
                                  json_data=assign_params(**kwargs))

    def update_group(self, group_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/preview/scim/v2/Groups/{group_id}',
                                  json_data=assign_params(**kwargs))

    def delete_group(self, group_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/preview/scim/v2/Groups/{group_id}')

    # ---- IAM — Service Principals (SCIM) ----

    def get_service_principal(self, sp_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}')

    def list_service_principals(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/preview/scim/v2/ServicePrincipals',
                                  params=assign_params(**kwargs))

    def create_service_principal(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/preview/scim/v2/ServicePrincipals',
                                  json_data=assign_params(**kwargs))

    def update_service_principal(self, sp_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}',
                                  json_data=assign_params(**kwargs))

    def delete_service_principal(self, sp_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/preview/scim/v2/ServicePrincipals/{sp_id}')

    # ---- IAM — Permissions (API 2.0) ----

    def get_permissions(self, object_type: str, object_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/permissions/{object_type}/{object_id}')

    def set_permissions(self, object_type: str, object_id: str, access_control_list: list) -> dict:
        return self._http_request('PUT', f'/api/2.0/permissions/{object_type}/{object_id}',
                                  json_data={'access_control_list': access_control_list})

    def update_permissions(self, object_type: str, object_id: str,
                           access_control_list: list) -> dict:
        return self._http_request('PATCH', f'/api/2.0/permissions/{object_type}/{object_id}',
                                  json_data={'access_control_list': access_control_list})

    # ---- Tokens (API 2.0) ----

    def list_tokens(self) -> dict:
        return self._http_request('GET', '/api/2.0/token/list')

    def create_token(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/token/create', json_data=assign_params(**kwargs))

    def update_token(self, token_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/token/{token_id}',
                                  json_data=assign_params(**kwargs))

    def delete_token(self, token_id: str) -> dict:
        return self._http_request('POST', '/api/2.0/token/delete', json_data={'token_id': token_id})

    # ---- Secrets (API 2.0) ----

    def put_secret(self, scope: str, key: str, string_value: str = None) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/put',
                                  json_data=assign_params(scope=scope, key=key,
                                                          string_value=string_value))

    def delete_secret(self, scope: str, key: str) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/delete',
                                  json_data={'scope': scope, 'key': key})

    def list_secrets(self, scope: str) -> dict:
        return self._http_request('GET', '/api/2.0/secrets/list', params={'scope': scope})

    def create_secret_scope(self, scope: str, initial_manage_principal: str = None) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/scopes/create',
                                  json_data=assign_params(scope=scope,
                                                          initial_manage_principal=initial_manage_principal))

    def list_secret_scopes(self) -> dict:
        return self._http_request('GET', '/api/2.0/secrets/scopes/list')

    def delete_secret_scope(self, scope: str) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/scopes/delete',
                                  json_data={'scope': scope})

    def get_secret_acl(self, scope: str, principal: str) -> dict:
        return self._http_request('GET', '/api/2.0/secrets/acls/get',
                                  params={'scope': scope, 'principal': principal})

    def list_secret_acls(self, scope: str) -> dict:
        return self._http_request('GET', '/api/2.0/secrets/acls/list', params={'scope': scope})

    def put_secret_acl(self, scope: str, principal: str, permission: str) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/acls/put',
                                  json_data={'scope': scope, 'principal': principal,
                                             'permission': permission})

    def delete_secret_acl(self, scope: str, principal: str) -> dict:
        return self._http_request('POST', '/api/2.0/secrets/acls/delete',
                                  json_data={'scope': scope, 'principal': principal})

    # ---- Dashboards (API 2.0 — Lakeview) ----

    def get_dashboard(self, dashboard_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/lakeview/dashboards/{dashboard_id}')

    def list_dashboards(self, **kwargs) -> dict:
        return self._http_request('GET', '/api/2.0/lakeview/dashboards',
                                  params=assign_params(**kwargs))

    def create_dashboard(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/lakeview/dashboards',
                                  json_data=assign_params(**kwargs))

    def update_dashboard(self, dashboard_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/lakeview/dashboards/{dashboard_id}',
                                  json_data=assign_params(**kwargs))

    def delete_dashboard(self, dashboard_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/lakeview/dashboards/{dashboard_id}')

    def migrate_dashboard(self, source_dashboard_id: str) -> dict:
        return self._http_request('POST', '/api/2.0/lakeview/dashboards/migrate',
                                  json_data={'source_dashboard_id': source_dashboard_id})

    def publish_dashboard(self, dashboard_id: str, **kwargs) -> dict:
        return self._http_request('POST', f'/api/2.0/lakeview/dashboards/{dashboard_id}/published',
                                  json_data=assign_params(**kwargs))

    # ---- Global Init Scripts (API 2.0) ----

    def get_global_init_script(self, script_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/global-init-scripts/{script_id}')

    def list_global_init_scripts(self) -> dict:
        return self._http_request('GET', '/api/2.0/global-init-scripts')

    def create_global_init_script(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/global-init-scripts',
                                  json_data=assign_params(**kwargs))

    def update_global_init_script(self, script_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/global-init-scripts/{script_id}',
                                  json_data=assign_params(**kwargs))

    def delete_global_init_script(self, script_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/global-init-scripts/{script_id}')

    # ---- IP Access Lists (API 2.0) ----

    def get_ip_access_list(self, ip_access_list_id: str) -> dict:
        return self._http_request('GET', f'/api/2.0/ip-access-lists/{ip_access_list_id}')

    def list_ip_access_lists(self) -> dict:
        return self._http_request('GET', '/api/2.0/ip-access-lists')

    def create_ip_access_list(self, **kwargs) -> dict:
        return self._http_request('POST', '/api/2.0/ip-access-lists',
                                  json_data=assign_params(**kwargs))

    def update_ip_access_list(self, ip_access_list_id: str, **kwargs) -> dict:
        return self._http_request('PATCH', f'/api/2.0/ip-access-lists/{ip_access_list_id}',
                                  json_data=assign_params(**kwargs))

    def delete_ip_access_list(self, ip_access_list_id: str) -> dict:
        return self._http_request('DELETE', f'/api/2.0/ip-access-lists/{ip_access_list_id}')


# =====================================================================
# Command Functions
# =====================================================================

# ---- Cluster Commands ----

def cluster_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    result = client.get_cluster(cluster_id)
    return CommandResults(
        readable_output=tableToMarkdown('Cluster', result,
            headers=['cluster_id', 'cluster_name', 'state', 'creator_user_name',
                     'spark_version', 'node_type_id', 'num_workers',
                     'autotermination_minutes', 'start_time'],
            removeNull=True),
        outputs_prefix='Databricks.Cluster',
        outputs_key_field='cluster_id',
        outputs=result,
    )


def cluster_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_clusters()
    clusters = response.get('clusters', [])
    return CommandResults(
        readable_output=tableToMarkdown('Clusters', clusters,
            headers=['cluster_id', 'cluster_name', 'state', 'creator_user_name',
                     'spark_version', 'node_type_id'],
            removeNull=True),
        outputs_prefix='Databricks.Cluster',
        outputs_key_field='cluster_id',
        outputs=clusters,
    )


def cluster_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        cluster_name=args.get('cluster_name'),
        spark_version=args.get('spark_version'),
        node_type_id=args.get('node_type_id'),
        num_workers=arg_to_number(args.get('num_workers')),
        autotermination_minutes=arg_to_number(args.get('autotermination_minutes')),
        custom_tags=parse_json_arg(args, 'custom_tags'),
    )
    result = client.create_cluster(**kwargs)
    return CommandResults(
        readable_output=f"Cluster created with ID: {result.get('cluster_id')}",
        outputs_prefix='Databricks.Cluster',
        outputs_key_field='cluster_id',
        outputs=result,
    )


def cluster_edit_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        cluster_id=args['cluster_id'],
        cluster_name=args.get('cluster_name'),
        spark_version=args.get('spark_version'),
        node_type_id=args.get('node_type_id'),
        num_workers=arg_to_number(args.get('num_workers')),
        autotermination_minutes=arg_to_number(args.get('autotermination_minutes')),
    )
    client.edit_cluster(**kwargs)
    return CommandResults(readable_output=f"Cluster {args['cluster_id']} updated successfully.")


def cluster_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.delete_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} terminated successfully.')


def cluster_permanent_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.permanent_delete_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} permanently deleted.')


def cluster_start_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.start_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} start initiated.')


def cluster_restart_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.restart_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} restart initiated.')


def cluster_resize_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    kwargs = assign_params(num_workers=arg_to_number(args.get('num_workers')))
    client.resize_cluster(cluster_id, **kwargs)
    return CommandResults(readable_output=f'Cluster {cluster_id} resize initiated.')


def cluster_pin_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.pin_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} pinned.')


def cluster_unpin_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    client.unpin_cluster(cluster_id)
    return CommandResults(readable_output=f'Cluster {cluster_id} unpinned.')


def cluster_change_owner_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.change_cluster_owner(args['cluster_id'], args['owner_username'])
    return CommandResults(
        readable_output=f"Cluster {args['cluster_id']} owner changed to {args['owner_username']}.")


def cluster_list_zones_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.list_zones()
    zones = result.get('zones', [])
    return CommandResults(
        readable_output=tableToMarkdown('Available Zones', [{'zone': z} for z in zones],
                                        headers=['zone']),
        outputs_prefix='Databricks.Zone',
        outputs=zones,
    )


def cluster_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    cluster_id = args['cluster_id']
    kwargs = assign_params(
        cluster_name=args.get('cluster_name'),
        spark_version=args.get('spark_version'),
        node_type_id=args.get('node_type_id'),
        num_workers=arg_to_number(args.get('num_workers')),
    )
    client.update_cluster(cluster_id, **kwargs)
    return CommandResults(readable_output=f'Cluster {cluster_id} updated.')


# ---- Cluster Policy Commands ----

def cluster_policy_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_cluster_policy(args['policy_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Cluster Policy', result,
            headers=['policy_id', 'name', 'creator_user_name', 'created_at_timestamp'],
            removeNull=True),
        outputs_prefix='Databricks.ClusterPolicy',
        outputs_key_field='policy_id',
        outputs=result,
    )


def cluster_policy_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_cluster_policies()
    policies = response.get('policies', [])
    return CommandResults(
        readable_output=tableToMarkdown('Cluster Policies', policies,
            headers=['policy_id', 'name', 'creator_user_name'], removeNull=True),
        outputs_prefix='Databricks.ClusterPolicy',
        outputs_key_field='policy_id',
        outputs=policies,
    )


def cluster_policy_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.create_cluster_policy(args['name'], args['definition'])
    return CommandResults(
        readable_output=f"Cluster policy created with ID: {result.get('policy_id')}",
        outputs_prefix='Databricks.ClusterPolicy',
        outputs_key_field='policy_id',
        outputs=result,
    )


def cluster_policy_edit_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.edit_cluster_policy(args['policy_id'], name=args.get('name'),
                               definition=args.get('definition'))
    return CommandResults(readable_output=f"Cluster policy {args['policy_id']} updated.")


def cluster_policy_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_cluster_policy(args['policy_id'])
    return CommandResults(readable_output=f"Cluster policy {args['policy_id']} deleted.")


# ---- Instance Pool Commands ----

def instance_pool_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_instance_pool(args['instance_pool_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Instance Pool', result,
            headers=['instance_pool_id', 'instance_pool_name', 'node_type_id',
                     'min_idle_instances', 'max_capacity', 'state'],
            removeNull=True),
        outputs_prefix='Databricks.InstancePool',
        outputs_key_field='instance_pool_id',
        outputs=result,
    )


def instance_pool_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_instance_pools()
    pools = response.get('instance_pools', [])
    return CommandResults(
        readable_output=tableToMarkdown('Instance Pools', pools,
            headers=['instance_pool_id', 'instance_pool_name', 'node_type_id', 'state'],
            removeNull=True),
        outputs_prefix='Databricks.InstancePool',
        outputs_key_field='instance_pool_id',
        outputs=pools,
    )


def instance_pool_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        instance_pool_name=args.get('instance_pool_name'),
        node_type_id=args.get('node_type_id'),
        min_idle_instances=arg_to_number(args.get('min_idle_instances')),
        max_capacity=arg_to_number(args.get('max_capacity')),
    )
    result = client.create_instance_pool(**kwargs)
    return CommandResults(
        readable_output=f"Instance pool created with ID: {result.get('instance_pool_id')}",
        outputs_prefix='Databricks.InstancePool',
        outputs_key_field='instance_pool_id',
        outputs=result,
    )


def instance_pool_edit_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        instance_pool_id=args['instance_pool_id'],
        instance_pool_name=args.get('instance_pool_name'),
        node_type_id=args.get('node_type_id'),
        min_idle_instances=arg_to_number(args.get('min_idle_instances')),
        max_capacity=arg_to_number(args.get('max_capacity')),
    )
    client.edit_instance_pool(**kwargs)
    return CommandResults(readable_output=f"Instance pool {args['instance_pool_id']} updated.")


def instance_pool_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_instance_pool(args['instance_pool_id'])
    return CommandResults(readable_output=f"Instance pool {args['instance_pool_id']} deleted.")


# ---- Library Commands ----

def library_cluster_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_library_status(args['cluster_id'])
    statuses = result.get('library_statuses', [])
    return CommandResults(
        readable_output=tableToMarkdown('Library Statuses', statuses,
            headers=['library', 'status', 'is_library_for_all_clusters'], removeNull=True),
        outputs_prefix='Databricks.LibraryStatus',
        outputs=statuses,
    )


def library_all_cluster_statuses_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_all_library_statuses()
    statuses = result.get('statuses', [])
    return CommandResults(
        readable_output=tableToMarkdown('All Cluster Library Statuses', statuses,
            headers=['cluster_id', 'library_statuses'], removeNull=True),
        outputs_prefix='Databricks.LibraryClusterStatus',
        outputs_key_field='cluster_id',
        outputs=statuses,
    )


def library_install_command(client: DatabricksClient, args: dict) -> CommandResults:
    libraries = parse_json_arg(args, 'libraries')
    client.install_libraries(args['cluster_id'], libraries)
    return CommandResults(readable_output=f"Libraries installed on cluster {args['cluster_id']}.")


def library_uninstall_command(client: DatabricksClient, args: dict) -> CommandResults:
    libraries = parse_json_arg(args, 'libraries')
    client.uninstall_libraries(args['cluster_id'], libraries)
    return CommandResults(readable_output=f"Libraries uninstalled from cluster {args['cluster_id']}.")


# ---- Command Execution Commands ----

def context_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.create_context(args['cluster_id'], args['language'])
    return CommandResults(
        readable_output=f"Execution context created with ID: {result.get('id')}",
        outputs_prefix='Databricks.Context',
        outputs_key_field='id',
        outputs=result,
    )


def context_destroy_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.destroy_context(args['cluster_id'], args['context_id'])
    return CommandResults(readable_output=f"Context {args['context_id']} destroyed.")


def context_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_context_status(args['cluster_id'], args['context_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Context Status', result,
            headers=['id', 'status'], removeNull=True),
        outputs_prefix='Databricks.Context',
        outputs_key_field='id',
        outputs=result,
    )


def command_execute_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.execute_command(args['cluster_id'], args['context_id'],
                                    args['language'], args['command'])
    return CommandResults(
        readable_output=f"Command submitted with ID: {result.get('id')}",
        outputs_prefix='Databricks.Command',
        outputs_key_field='id',
        outputs=result,
    )


def command_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_command_status(args['cluster_id'], args['command_id'], args['context_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Command Status', result,
            headers=['id', 'status', 'results'], removeNull=True),
        outputs_prefix='Databricks.Command',
        outputs_key_field='id',
        outputs=result,
    )


def command_cancel_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.cancel_command(args['cluster_id'], args['command_id'], args['context_id'])
    return CommandResults(readable_output=f"Command {args['command_id']} cancelled.")


# ---- Job Commands ----

def job_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_job(args['job_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Job', result,
            headers=['job_id', 'creator_user_name', 'created_time'], removeNull=True),
        outputs_prefix='Databricks.Job',
        outputs_key_field='job_id',
        outputs=result,
    )


def job_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        limit=arg_to_number(args.get('limit')),
        offset=arg_to_number(args.get('offset')),
        name=args.get('name'),
        expand_tasks=argToBoolean(args['expand_tasks']) if args.get('expand_tasks') else None,
    )
    response = client.list_jobs(**kwargs)
    jobs = response.get('jobs', [])
    return CommandResults(
        readable_output=tableToMarkdown('Jobs', jobs,
            headers=['job_id', 'creator_user_name', 'created_time'], removeNull=True),
        outputs_prefix='Databricks.Job',
        outputs_key_field='job_id',
        outputs=jobs,
    )


def job_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        tasks=parse_json_arg(args, 'tasks'),
        schedule=parse_json_arg(args, 'schedule'),
        max_concurrent_runs=arg_to_number(args.get('max_concurrent_runs')),
    )
    result = client.create_job(**kwargs)
    return CommandResults(
        readable_output=f"Job created with ID: {result.get('job_id')}",
        outputs_prefix='Databricks.Job',
        outputs_key_field='job_id',
        outputs=result,
    )


def job_reset_command(client: DatabricksClient, args: dict) -> CommandResults:
    new_settings = parse_json_arg(args, 'new_settings')
    client.reset_job(args['job_id'], new_settings)
    return CommandResults(readable_output=f"Job {args['job_id']} settings replaced.")


def job_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    fields = parse_json_arg(args, 'fields_to_update')
    client.update_job(args['job_id'], fields)
    return CommandResults(readable_output=f"Job {args['job_id']} updated.")


def job_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_job(args['job_id'])
    return CommandResults(readable_output=f"Job {args['job_id']} deleted.")


def job_run_now_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        notebook_params=parse_json_arg(args, 'notebook_params'),
        python_params=parse_json_arg(args, 'python_params'),
        jar_params=parse_json_arg(args, 'jar_params'),
    )
    result = client.run_job_now(args['job_id'], **kwargs)
    return CommandResults(
        readable_output=f"Job run triggered. Run ID: {result.get('run_id')}",
        outputs_prefix='Databricks.JobRun',
        outputs_key_field='run_id',
        outputs=result,
    )


# ---- Pipeline Commands ----

def pipeline_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_pipeline(args['pipeline_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Pipeline', result,
            headers=['pipeline_id', 'name', 'state', 'creator_user_name', 'cluster_id'],
            removeNull=True),
        outputs_prefix='Databricks.Pipeline',
        outputs_key_field='pipeline_id',
        outputs=result,
    )


def pipeline_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        max_results=arg_to_number(args.get('max_results')),
        filter=args.get('filter'),
    )
    response = client.list_pipelines(**kwargs)
    pipelines = response.get('statuses', [])
    return CommandResults(
        readable_output=tableToMarkdown('Pipelines', pipelines,
            headers=['pipeline_id', 'name', 'state', 'creator_user_name'], removeNull=True),
        outputs_prefix='Databricks.Pipeline',
        outputs_key_field='pipeline_id',
        outputs=pipelines,
    )


def pipeline_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    config = parse_json_arg(args, 'configuration')
    kwargs = assign_params(name=args.get('name'), **(config or {}))
    result = client.create_pipeline(**kwargs)
    return CommandResults(
        readable_output=f"Pipeline created with ID: {result.get('pipeline_id')}",
        outputs_prefix='Databricks.Pipeline',
        outputs_key_field='pipeline_id',
        outputs=result,
    )


def pipeline_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    config = parse_json_arg(args, 'configuration') or {}
    client.update_pipeline(args['pipeline_id'], **config)
    return CommandResults(readable_output=f"Pipeline {args['pipeline_id']} updated.")


def pipeline_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_pipeline(args['pipeline_id'])
    return CommandResults(readable_output=f"Pipeline {args['pipeline_id']} deleted.")


def pipeline_clone_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.clone_pipeline(args['pipeline_id'])
    return CommandResults(
        readable_output=f"Pipeline cloned. New ID: {result.get('pipeline_id')}",
        outputs_prefix='Databricks.Pipeline',
        outputs_key_field='pipeline_id',
        outputs=result,
    )


def pipeline_start_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        full_refresh=argToBoolean(args['full_refresh']) if args.get('full_refresh') else None,
    )
    result = client.start_pipeline(args['pipeline_id'], **kwargs)
    return CommandResults(
        readable_output=f"Pipeline {args['pipeline_id']} update started. Update ID: {result.get('update_id')}",
        outputs_prefix='Databricks.PipelineUpdate',
        outputs_key_field='update_id',
        outputs=result,
    )


def pipeline_stop_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.stop_pipeline(args['pipeline_id'])
    return CommandResults(readable_output=f"Pipeline {args['pipeline_id']} stop initiated.")


def pipeline_events_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        max_results=arg_to_number(args.get('max_results')),
        filter=args.get('filter'),
    )
    response = client.get_pipeline_events(args['pipeline_id'], **kwargs)
    events = response.get('events', [])
    return CommandResults(
        readable_output=tableToMarkdown('Pipeline Events', events,
            headers=['id', 'timestamp', 'event_type', 'message', 'level'], removeNull=True),
        outputs_prefix='Databricks.PipelineEvent',
        outputs_key_field='id',
        outputs=events,
    )


def pipeline_list_updates_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(max_results=arg_to_number(args.get('max_results')))
    response = client.list_pipeline_updates(args['pipeline_id'], **kwargs)
    updates = response.get('updates', [])
    return CommandResults(
        readable_output=tableToMarkdown('Pipeline Updates', updates,
            headers=['update_id', 'state', 'creation_time'], removeNull=True),
        outputs_prefix='Databricks.PipelineUpdate',
        outputs_key_field='update_id',
        outputs=updates,
    )


def pipeline_get_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_pipeline_update(args['pipeline_id'], args['update_id'])
    update = result.get('update', result)
    return CommandResults(
        readable_output=tableToMarkdown('Pipeline Update', update,
            headers=['update_id', 'state', 'creation_time'], removeNull=True),
        outputs_prefix='Databricks.PipelineUpdate',
        outputs_key_field='update_id',
        outputs=update,
    )


def pipeline_apply_environment_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.apply_pipeline_environment(args['pipeline_id'])
    return CommandResults(
        readable_output=f"Environment applied to pipeline {args['pipeline_id']}.")


# ---- DBFS Commands ----

def dbfs_get_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.dbfs_get_status(args['path'])
    return CommandResults(
        readable_output=tableToMarkdown('DBFS Status', result,
            headers=['path', 'is_dir', 'file_size', 'modification_time'], removeNull=True),
        outputs_prefix='Databricks.DBFS',
        outputs_key_field='path',
        outputs=result,
    )


def dbfs_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.dbfs_list(args['path'])
    files = response.get('files', [])
    return CommandResults(
        readable_output=tableToMarkdown('DBFS Contents', files,
            headers=['path', 'is_dir', 'file_size', 'modification_time'], removeNull=True),
        outputs_prefix='Databricks.DBFS',
        outputs_key_field='path',
        outputs=files,
    )


def dbfs_read_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.dbfs_read(args['path'],
                               offset=arg_to_number(args.get('offset')),
                               length=arg_to_number(args.get('length')))
    return CommandResults(
        readable_output=tableToMarkdown('DBFS Read', result,
            headers=['bytes_read', 'data'], removeNull=True),
        outputs_prefix='Databricks.DBFSFile',
        outputs=result,
    )


def dbfs_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    overwrite = argToBoolean(args['overwrite']) if args.get('overwrite') else None
    result = client.dbfs_create(args['path'], overwrite=overwrite)
    return CommandResults(
        readable_output=f"DBFS stream created. Handle: {result.get('handle')}",
        outputs_prefix='Databricks.DBFSStream',
        outputs_key_field='handle',
        outputs=result,
    )


def dbfs_add_block_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.dbfs_add_block(arg_to_number(args['handle']), args['data'])
    return CommandResults(readable_output='Block added to DBFS stream.')


def dbfs_close_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.dbfs_close(arg_to_number(args['handle']))
    return CommandResults(readable_output='DBFS stream closed.')


def dbfs_put_command(client: DatabricksClient, args: dict) -> CommandResults:
    overwrite = argToBoolean(args['overwrite']) if args.get('overwrite') else None
    client.dbfs_put(args['path'], contents=args.get('contents'), overwrite=overwrite)
    return CommandResults(readable_output=f"File uploaded to {args['path']}.")


def dbfs_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    recursive = argToBoolean(args['recursive']) if args.get('recursive') else None
    client.dbfs_delete(args['path'], recursive=recursive)
    return CommandResults(readable_output=f"Deleted {args['path']}.")


def dbfs_mkdirs_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.dbfs_mkdirs(args['path'])
    return CommandResults(readable_output=f"Directory created: {args['path']}.")


def dbfs_move_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.dbfs_move(args['source_path'], args['destination_path'])
    return CommandResults(
        readable_output=f"Moved {args['source_path']} to {args['destination_path']}.")


# ---- Workspace Commands ----

def workspace_get_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.workspace_get_status(args['path'])
    return CommandResults(
        readable_output=tableToMarkdown('Workspace Object', result,
            headers=['object_type', 'path', 'object_id', 'language'], removeNull=True),
        outputs_prefix='Databricks.WorkspaceObject',
        outputs_key_field='object_id',
        outputs=result,
    )


def workspace_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.workspace_list(args['path'])
    objects = response.get('objects', [])
    return CommandResults(
        readable_output=tableToMarkdown('Workspace Contents', objects,
            headers=['object_type', 'path', 'object_id', 'language'], removeNull=True),
        outputs_prefix='Databricks.WorkspaceObject',
        outputs_key_field='object_id',
        outputs=objects,
    )


def workspace_export_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.workspace_export(args['path'], format_str=args.get('format'))
    return CommandResults(
        readable_output=f"Exported {args['path']}.",
        outputs_prefix='Databricks.WorkspaceExport',
        outputs=result,
    )


def workspace_import_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        format=args.get('format'),
        language=args.get('language'),
        overwrite=argToBoolean(args['overwrite']) if args.get('overwrite') else None,
    )
    client.workspace_import(args['path'], args['content'], **kwargs)
    return CommandResults(readable_output=f"Imported to {args['path']}.")


def workspace_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    recursive = argToBoolean(args['recursive']) if args.get('recursive') else None
    client.workspace_delete(args['path'], recursive=recursive)
    return CommandResults(readable_output=f"Deleted {args['path']}.")


def workspace_mkdirs_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.workspace_mkdirs(args['path'])
    return CommandResults(readable_output=f"Directory created: {args['path']}.")


# ---- Git Credential Commands ----

def git_credential_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_git_credential(args['credential_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Git Credential', result,
            headers=['credential_id', 'git_username', 'git_provider'], removeNull=True),
        outputs_prefix='Databricks.GitCredential',
        outputs_key_field='credential_id',
        outputs=result,
    )


def git_credential_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_git_credentials()
    creds = response.get('credentials', [])
    return CommandResults(
        readable_output=tableToMarkdown('Git Credentials', creds,
            headers=['credential_id', 'git_username', 'git_provider'], removeNull=True),
        outputs_prefix='Databricks.GitCredential',
        outputs_key_field='credential_id',
        outputs=creds,
    )


def git_credential_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        git_provider=args.get('git_provider'),
        git_username=args.get('git_username'),
        personal_access_token=args.get('personal_access_token'),
    )
    result = client.create_git_credential(**kwargs)
    return CommandResults(
        readable_output=f"Git credential created with ID: {result.get('credential_id')}",
        outputs_prefix='Databricks.GitCredential',
        outputs_key_field='credential_id',
        outputs=result,
    )


def git_credential_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        git_provider=args.get('git_provider'),
        git_username=args.get('git_username'),
        personal_access_token=args.get('personal_access_token'),
    )
    client.update_git_credential(args['credential_id'], **kwargs)
    return CommandResults(readable_output=f"Git credential {args['credential_id']} updated.")


def git_credential_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_git_credential(args['credential_id'])
    return CommandResults(readable_output=f"Git credential {args['credential_id']} deleted.")


# ---- Repo Commands ----

def repo_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_repo(args['repo_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Repo', result,
            headers=['id', 'url', 'provider', 'path', 'branch', 'head_commit_id'],
            removeNull=True),
        outputs_prefix='Databricks.Repo',
        outputs_key_field='id',
        outputs=result,
    )


def repo_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        path_prefix=args.get('path_prefix'),
        next_page_token=args.get('next_page_token'),
    )
    response = client.list_repos(**kwargs)
    repos = response.get('repos', [])
    return CommandResults(
        readable_output=tableToMarkdown('Repos', repos,
            headers=['id', 'url', 'provider', 'path', 'branch'], removeNull=True),
        outputs_prefix='Databricks.Repo',
        outputs_key_field='id',
        outputs=repos,
    )


def repo_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(url=args.get('url'), provider=args.get('provider'),
                           path=args.get('path'))
    result = client.create_repo(**kwargs)
    return CommandResults(
        readable_output=f"Repo created with ID: {result.get('id')}",
        outputs_prefix='Databricks.Repo',
        outputs_key_field='id',
        outputs=result,
    )


def repo_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(branch=args.get('branch'), tag=args.get('tag'))
    client.update_repo(args['repo_id'], **kwargs)
    return CommandResults(readable_output=f"Repo {args['repo_id']} updated.")


# ---- SQL Warehouse Commands ----

def warehouse_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_warehouse(args['warehouse_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Warehouse', result,
            headers=['id', 'name', 'cluster_size', 'state', 'num_clusters',
                     'creator_name', 'num_active_sessions'],
            removeNull=True),
        outputs_prefix='Databricks.Warehouse',
        outputs_key_field='id',
        outputs=result,
    )


def warehouse_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_warehouses()
    warehouses = response.get('warehouses', [])
    return CommandResults(
        readable_output=tableToMarkdown('Warehouses', warehouses,
            headers=['id', 'name', 'cluster_size', 'state', 'num_clusters'], removeNull=True),
        outputs_prefix='Databricks.Warehouse',
        outputs_key_field='id',
        outputs=warehouses,
    )


def warehouse_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        cluster_size=args.get('cluster_size'),
        max_num_clusters=arg_to_number(args.get('max_num_clusters')),
        auto_stop_mins=arg_to_number(args.get('auto_stop_mins')),
        enable_serverless_compute=argToBoolean(args['enable_serverless_compute']) if args.get('enable_serverless_compute') else None,
    )
    result = client.create_warehouse(**kwargs)
    return CommandResults(
        readable_output=f"Warehouse created with ID: {result.get('id')}",
        outputs_prefix='Databricks.Warehouse',
        outputs_key_field='id',
        outputs=result,
    )


def warehouse_edit_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        cluster_size=args.get('cluster_size'),
        max_num_clusters=arg_to_number(args.get('max_num_clusters')),
        auto_stop_mins=arg_to_number(args.get('auto_stop_mins')),
    )
    client.edit_warehouse(args['warehouse_id'], **kwargs)
    return CommandResults(readable_output=f"Warehouse {args['warehouse_id']} updated.")


def warehouse_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_warehouse(args['warehouse_id'])
    return CommandResults(readable_output=f"Warehouse {args['warehouse_id']} deleted.")


def warehouse_start_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.start_warehouse(args['warehouse_id'])
    return CommandResults(readable_output=f"Warehouse {args['warehouse_id']} start initiated.")


def warehouse_stop_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.stop_warehouse(args['warehouse_id'])
    return CommandResults(readable_output=f"Warehouse {args['warehouse_id']} stop initiated.")


def warehouse_get_config_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_warehouse_config()
    return CommandResults(
        readable_output=tableToMarkdown('Warehouse Config', result, removeNull=True),
        outputs_prefix='Databricks.WarehouseConfig',
        outputs=result,
    )


def warehouse_set_config_command(client: DatabricksClient, args: dict) -> CommandResults:
    config = parse_json_arg(args, 'config')
    client.set_warehouse_config(config)
    return CommandResults(readable_output='Warehouse config updated.')


# ---- SQL Statement Commands ----

def sql_statement_execute_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        catalog=args.get('catalog'),
        schema=args.get('schema'),
        wait_timeout=args.get('wait_timeout'),
        disposition=args.get('disposition'),
        row_limit=arg_to_number(args.get('row_limit')),
    )
    result = client.execute_sql_statement(args['warehouse_id'], args['statement'], **kwargs)
    return CommandResults(
        readable_output=tableToMarkdown('SQL Statement', result,
            headers=['statement_id', 'status'], removeNull=True),
        outputs_prefix='Databricks.SQLStatement',
        outputs_key_field='statement_id',
        outputs=result,
    )


def sql_statement_get_status_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_sql_statement_status(args['statement_id'])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Statement Status', result,
            headers=['statement_id', 'status'], removeNull=True),
        outputs_prefix='Databricks.SQLStatement',
        outputs_key_field='statement_id',
        outputs=result,
    )


def sql_statement_get_result_chunk_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_sql_result_chunk(args['statement_id'],
                                          arg_to_number(args['chunk_index']))
    return CommandResults(
        readable_output=tableToMarkdown('SQL Result Chunk', result,
            headers=['chunk_index', 'row_offset', 'row_count'], removeNull=True),
        outputs_prefix='Databricks.SQLResultChunk',
        outputs=result,
    )


def sql_statement_cancel_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.cancel_sql_statement(args['statement_id'])
    return CommandResults(readable_output=f"Statement {args['statement_id']} cancelled.")


# ---- SQL Query Commands ----

def sql_query_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_sql_query(args['query_id'])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Query', result,
            headers=['id', 'name', 'query', 'description', 'warehouse_id', 'parent_path'],
            removeNull=True),
        outputs_prefix='Databricks.SQLQuery',
        outputs_key_field='id',
        outputs=result,
    )


def sql_query_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        page_size=arg_to_number(args.get('page_size')),
        page_token=args.get('page_token'),
    )
    response = client.list_sql_queries(**kwargs)
    queries = response.get('results', [])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Queries', queries,
            headers=['id', 'name', 'description', 'warehouse_id'], removeNull=True),
        outputs_prefix='Databricks.SQLQuery',
        outputs_key_field='id',
        outputs=queries,
    )


def sql_query_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        query=args.get('query'),
        warehouse_id=args.get('warehouse_id'),
        description=args.get('description'),
        parent_path=args.get('parent_path'),
    )
    result = client.create_sql_query(**kwargs)
    return CommandResults(
        readable_output=f"SQL query created with ID: {result.get('id')}",
        outputs_prefix='Databricks.SQLQuery',
        outputs_key_field='id',
        outputs=result,
    )


def sql_query_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        query=args.get('query'),
        description=args.get('description'),
        warehouse_id=args.get('warehouse_id'),
    )
    result = client.update_sql_query(args['query_id'], **kwargs)
    return CommandResults(
        readable_output=f"SQL query {args['query_id']} updated.",
        outputs_prefix='Databricks.SQLQuery',
        outputs_key_field='id',
        outputs=result,
    )


def sql_query_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_sql_query(args['query_id'])
    return CommandResults(readable_output=f"SQL query {args['query_id']} deleted.")


# ---- SQL Alert Commands ----

def sql_alert_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.list_sql_alerts()
    alerts = result if isinstance(result, list) else result.get('results', [])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Alerts', alerts,
            headers=['id', 'display_name', 'query_id', 'state', 'lifecycle_state', 'create_time', 'update_time'],
            removeNull=True),
        outputs_prefix='Databricks.SQLAlert',
        outputs_key_field='id',
        outputs=alerts,
    )


def sql_alert_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_sql_alert(args['alert_id'])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Alert', result,
            headers=['id', 'display_name', 'query_id', 'state', 'lifecycle_state', 'create_time', 'update_time'],
            removeNull=True),
        outputs_prefix='Databricks.SQLAlert',
        outputs_key_field='id',
        outputs=result,
    )


def sql_alert_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        display_name=args.get('display_name') or args.get('name'),
        query_id=args.get('query_id'),
        condition=parse_json_arg(args, 'condition'),
    )
    result = client.create_sql_alert(**kwargs)
    return CommandResults(
        readable_output=f"SQL alert created with ID: {result.get('id')}",
        outputs_prefix='Databricks.SQLAlert',
        outputs_key_field='id',
        outputs=result,
    )


def sql_alert_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        display_name=args.get('display_name') or args.get('name'),
        query_id=args.get('query_id'),
        condition=parse_json_arg(args, 'condition'),
    )
    result = client.update_sql_alert(args['alert_id'], **kwargs)
    return CommandResults(
        readable_output=f"SQL alert {args['alert_id']} updated.",
        outputs_prefix='Databricks.SQLAlert',
        outputs_key_field='id',
        outputs=result,
    )


def sql_alert_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_sql_alert(args['alert_id'])
    return CommandResults(readable_output=f"SQL alert {args['alert_id']} deleted.")


# ---- SQL Query History Command ----

def sql_query_history_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        max_results=arg_to_number(args.get('max_results')),
        page_token=args.get('page_token'),
        include_metrics=argToBoolean(args['include_metrics']) if args.get('include_metrics') else None,
    )
    filter_by = assign_params(
        start_time_ms=arg_to_number(args.get('start_time_ms')),
        end_time_ms=arg_to_number(args.get('end_time_ms')),
        user_ids=argToList(args.get('user_ids')) if args.get('user_ids') else None,
        warehouse_ids=argToList(args.get('warehouse_ids')) if args.get('warehouse_ids') else None,
        statuses=argToList(args.get('statuses')) if args.get('statuses') else None,
    )
    if filter_by:
        kwargs['filter_by'] = filter_by
    response = client.list_sql_query_history(**kwargs)
    queries = response.get('res', [])
    return CommandResults(
        readable_output=tableToMarkdown('SQL Query History', queries,
            headers=['query_id', 'query_text', 'status', 'user_name', 'warehouse_id',
                     'execution_end_time_ms', 'duration'],
            removeNull=True),
        outputs_prefix='Databricks.SQLQueryHistory',
        outputs_key_field='query_id',
        outputs=queries,
    )


# ---- Serving Endpoint Commands ----

def serving_endpoint_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_serving_endpoints()
    endpoints = response.get('endpoints', [])
    return CommandResults(
        readable_output=tableToMarkdown('Serving Endpoints', endpoints,
            headers=['name', 'creator', 'creation_timestamp', 'state'], removeNull=True),
        outputs_prefix='Databricks.ServingEndpoint',
        outputs_key_field='name',
        outputs=endpoints,
    )


def serving_endpoint_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_serving_endpoint(args['name'])
    return CommandResults(
        readable_output=tableToMarkdown('Serving Endpoint', result,
            headers=['name', 'creator', 'creation_timestamp', 'state'], removeNull=True),
        outputs_prefix='Databricks.ServingEndpoint',
        outputs_key_field='name',
        outputs=result,
    )


def serving_endpoint_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        config=parse_json_arg(args, 'config'),
    )
    result = client.create_serving_endpoint(**kwargs)
    return CommandResults(
        readable_output=f"Serving endpoint '{args.get('name')}' created.",
        outputs_prefix='Databricks.ServingEndpoint',
        outputs_key_field='name',
        outputs=result,
    )


def serving_endpoint_update_config_command(client: DatabricksClient, args: dict) -> CommandResults:
    served_entities = parse_json_arg(args, 'served_entities')
    result = client.update_serving_endpoint_config(args['name'], served_entities)
    return CommandResults(
        readable_output=f"Serving endpoint '{args['name']}' config updated.",
        outputs_prefix='Databricks.ServingEndpoint',
        outputs_key_field='name',
        outputs=result,
    )


def serving_endpoint_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_serving_endpoint(args['name'])
    return CommandResults(readable_output=f"Serving endpoint '{args['name']}' deleted.")


def serving_endpoint_query_command(client: DatabricksClient, args: dict) -> CommandResults:
    inputs = parse_json_arg(args, 'inputs')
    result = client.query_serving_endpoint(args['name'], inputs)
    return CommandResults(
        readable_output=tableToMarkdown('Serving Endpoint Response', result, removeNull=True),
        outputs_prefix='Databricks.ServingEndpointResponse',
        outputs=result,
    )


def serving_endpoint_get_logs_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_serving_endpoint_logs(args['name'], args['served_model_name'])
    return CommandResults(
        readable_output=f"Logs for {args['name']}/{args['served_model_name']}:\n{result.get('logs', '')}",
        outputs_prefix='Databricks.ServingEndpointLogs',
        outputs=result,
    )


# ---- Vector Search Commands ----

def vector_search_endpoint_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_vector_search_endpoints()
    endpoints = response.get('endpoints', [])
    return CommandResults(
        readable_output=tableToMarkdown('Vector Search Endpoints', endpoints,
            headers=['name', 'endpoint_type', 'state'], removeNull=True),
        outputs_prefix='Databricks.VectorSearchEndpoint',
        outputs_key_field='name',
        outputs=endpoints,
    )


def vector_search_endpoint_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_vector_search_endpoint(args['name'])
    return CommandResults(
        readable_output=tableToMarkdown('Vector Search Endpoint', result,
            headers=['name', 'endpoint_type', 'state', 'num_indexes', 'creator'],
            removeNull=True),
        outputs_prefix='Databricks.VectorSearchEndpoint',
        outputs_key_field='name',
        outputs=result,
    )


def vector_search_endpoint_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.create_vector_search_endpoint(args['name'], args['endpoint_type'])
    return CommandResults(
        readable_output=f"Vector search endpoint '{args['name']}' created.",
        outputs_prefix='Databricks.VectorSearchEndpoint',
        outputs_key_field='name',
        outputs=result,
    )


def vector_search_endpoint_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_vector_search_endpoint(args['name'])
    return CommandResults(readable_output=f"Vector search endpoint '{args['name']}' deleted.")


def vector_search_endpoint_get_metrics_command(client: DatabricksClient,
                                                args: dict) -> CommandResults:
    result = client.get_vector_search_metrics(args['name'])
    return CommandResults(
        readable_output=tableToMarkdown('Vector Search Metrics', result, removeNull=True),
        outputs_prefix='Databricks.VectorSearchMetrics',
        outputs=result,
    )


# ---- MLflow Commands ----

def mlflow_metric_history_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_mlflow_metric_history(args['run_id'], args['metric_key'])
    metrics = result.get('metrics', [])
    return CommandResults(
        readable_output=tableToMarkdown('MLflow Metric History', metrics,
            headers=['key', 'value', 'timestamp', 'step'], removeNull=True),
        outputs_prefix='Databricks.MLflowMetric',
        outputs=metrics,
    )


def mlflow_model_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        max_results=arg_to_number(args.get('max_results')),
        page_token=args.get('page_token'),
    )
    response = client.list_mlflow_models(**kwargs)
    models = response.get('registered_models', [])
    return CommandResults(
        readable_output=tableToMarkdown('MLflow Models', models,
            headers=['name', 'creation_timestamp', 'last_updated_timestamp',
                     'user_id', 'description'],
            removeNull=True),
        outputs_prefix='Databricks.MLflowModel',
        outputs_key_field='name',
        outputs=models,
    )


def mlflow_model_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_mlflow_model(args['name'])
    model = result.get('registered_model_databricks', result)
    return CommandResults(
        readable_output=tableToMarkdown('MLflow Model', model,
            headers=['name', 'creation_timestamp', 'last_updated_timestamp',
                     'user_id', 'description'],
            removeNull=True),
        outputs_prefix='Databricks.MLflowModel',
        outputs_key_field='name',
        outputs=model,
    )


def mlflow_model_version_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        source=args.get('source'),
        run_id=args.get('run_id'),
        description=args.get('description'),
    )
    result = client.create_mlflow_model_version(**kwargs)
    version = result.get('model_version', result)
    return CommandResults(
        readable_output=f"Model version created: {version.get('name')} v{version.get('version')}",
        outputs_prefix='Databricks.MLflowModelVersion',
        outputs_key_field='version',
        outputs=version,
    )


def mlflow_model_version_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_mlflow_model_version(args['name'], args['version'])
    version = result.get('model_version', result)
    return CommandResults(
        readable_output=tableToMarkdown('MLflow Model Version', version,
            headers=['name', 'version', 'creation_timestamp', 'current_stage',
                     'source', 'run_id', 'status'],
            removeNull=True),
        outputs_prefix='Databricks.MLflowModelVersion',
        outputs_key_field='version',
        outputs=version,
    )


def mlflow_model_version_search_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        filter=args.get('filter'),
        max_results=arg_to_number(args.get('max_results')),
        order_by=args.get('order_by'),
        page_token=args.get('page_token'),
    )
    response = client.search_mlflow_model_versions(**kwargs)
    versions = response.get('model_versions', [])
    return CommandResults(
        readable_output=tableToMarkdown('MLflow Model Versions', versions,
            headers=['name', 'version', 'current_stage', 'status', 'source'],
            removeNull=True),
        outputs_prefix='Databricks.MLflowModelVersion',
        outputs_key_field='version',
        outputs=versions,
    )


def mlflow_model_version_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_mlflow_model_version(args['name'], args['version'])
    return CommandResults(
        readable_output=f"Model version {args['name']} v{args['version']} deleted.")


def mlflow_model_version_transition_stage_command(client: DatabricksClient,
                                                   args: dict) -> CommandResults:
    result = client.transition_mlflow_model_version_stage(args['name'], args['version'],
                                                          args['stage'])
    version = result.get('model_version', result)
    return CommandResults(
        readable_output=f"Model {args['name']} v{args['version']} transitioned to {args['stage']}.",
        outputs_prefix='Databricks.MLflowModelVersion',
        outputs_key_field='version',
        outputs=version,
    )


# ---- Unity Catalog — Catalog Commands ----

def catalog_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_catalog(args['name'])
    return CommandResults(
        readable_output=tableToMarkdown('Catalog', result,
            headers=['name', 'owner', 'comment', 'metastore_id', 'created_at', 'created_by'],
            removeNull=True),
        outputs_prefix='Databricks.Catalog',
        outputs_key_field='name',
        outputs=result,
    )


def catalog_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_catalogs()
    catalogs = response.get('catalogs', [])
    return CommandResults(
        readable_output=tableToMarkdown('Catalogs', catalogs,
            headers=['name', 'owner', 'comment', 'created_at'], removeNull=True),
        outputs_prefix='Databricks.Catalog',
        outputs_key_field='name',
        outputs=catalogs,
    )


def catalog_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(name=args.get('name'), comment=args.get('comment'))
    result = client.create_catalog(**kwargs)
    return CommandResults(
        readable_output=f"Catalog '{args.get('name')}' created.",
        outputs_prefix='Databricks.Catalog',
        outputs_key_field='name',
        outputs=result,
    )


def catalog_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(new_name=args.get('new_name'), comment=args.get('comment'),
                           owner=args.get('owner'))
    result = client.update_catalog(args['name'], **kwargs)
    return CommandResults(
        readable_output=f"Catalog '{args['name']}' updated.",
        outputs_prefix='Databricks.Catalog',
        outputs_key_field='name',
        outputs=result,
    )


def catalog_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    force = argToBoolean(args['force']) if args.get('force') else None
    client.delete_catalog(args['name'], force=force)
    return CommandResults(readable_output=f"Catalog '{args['name']}' deleted.")


# ---- Unity Catalog — Schema Commands ----

def schema_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_schema(args['full_name'])
    return CommandResults(
        readable_output=tableToMarkdown('Schema', result,
            headers=['name', 'catalog_name', 'owner', 'comment', 'full_name', 'created_at'],
            removeNull=True),
        outputs_prefix='Databricks.Schema',
        outputs_key_field='full_name',
        outputs=result,
    )


def schema_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_schemas(args['catalog_name'])
    schemas = response.get('schemas', [])
    return CommandResults(
        readable_output=tableToMarkdown('Schemas', schemas,
            headers=['name', 'catalog_name', 'owner', 'comment', 'full_name'], removeNull=True),
        outputs_prefix='Databricks.Schema',
        outputs_key_field='full_name',
        outputs=schemas,
    )


def schema_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(name=args.get('name'), catalog_name=args.get('catalog_name'),
                           comment=args.get('comment'))
    result = client.create_schema(**kwargs)
    return CommandResults(
        readable_output=f"Schema '{args.get('name')}' created.",
        outputs_prefix='Databricks.Schema',
        outputs_key_field='full_name',
        outputs=result,
    )


def schema_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(new_name=args.get('new_name'), comment=args.get('comment'),
                           owner=args.get('owner'))
    result = client.update_schema(args['full_name'], **kwargs)
    return CommandResults(
        readable_output=f"Schema '{args['full_name']}' updated.",
        outputs_prefix='Databricks.Schema',
        outputs_key_field='full_name',
        outputs=result,
    )


def schema_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_schema(args['full_name'])
    return CommandResults(readable_output=f"Schema '{args['full_name']}' deleted.")


# ---- Unity Catalog — Table Commands ----

def table_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_table(args['full_name'])
    return CommandResults(
        readable_output=tableToMarkdown('Table', result,
            headers=['name', 'catalog_name', 'schema_name', 'table_type',
                     'data_source_format', 'storage_location', 'owner', 'created_at'],
            removeNull=True),
        outputs_prefix='Databricks.Table',
        outputs_key_field='full_name',
        outputs=result,
    )


def table_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        max_results=arg_to_number(args.get('max_results')),
        page_token=args.get('page_token'),
    )
    response = client.list_tables(args['catalog_name'], args['schema_name'], **kwargs)
    tables = response.get('tables', [])
    return CommandResults(
        readable_output=tableToMarkdown('Tables', tables,
            headers=['name', 'catalog_name', 'schema_name', 'table_type',
                     'data_source_format'],
            removeNull=True),
        outputs_prefix='Databricks.Table',
        outputs_key_field='full_name',
        outputs=tables,
    )


def table_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_table(args['full_name'])
    return CommandResults(readable_output=f"Table '{args['full_name']}' deleted.")


def table_exists_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.table_exists(args['full_name'])
    return CommandResults(
        readable_output=f"Table '{args['full_name']}' exists: {result.get('table_exists', False)}",
        outputs_prefix='Databricks.TableExists',
        outputs=result,
    )


def table_summaries_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        schema_name_pattern=args.get('schema_name_pattern'),
        table_name_pattern=args.get('table_name_pattern'),
        max_results=arg_to_number(args.get('max_results')),
        page_token=args.get('page_token'),
    )
    response = client.list_table_summaries(args['catalog_name'], **kwargs)
    summaries = response.get('tables', [])
    return CommandResults(
        readable_output=tableToMarkdown('Table Summaries', summaries,
            headers=['full_name', 'table_type'], removeNull=True),
        outputs_prefix='Databricks.TableSummary',
        outputs_key_field='full_name',
        outputs=summaries,
    )


# ---- Unity Catalog — Volume Commands ----

def volume_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_volume(args['full_name'])
    return CommandResults(
        readable_output=tableToMarkdown('Volume', result,
            headers=['name', 'catalog_name', 'schema_name', 'volume_type',
                     'storage_location', 'owner', 'created_at'],
            removeNull=True),
        outputs_prefix='Databricks.Volume',
        outputs_key_field='full_name',
        outputs=result,
    )


def volume_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_volumes(args['catalog_name'], args['schema_name'])
    volumes = response.get('volumes', [])
    return CommandResults(
        readable_output=tableToMarkdown('Volumes', volumes,
            headers=['name', 'catalog_name', 'schema_name', 'volume_type'],
            removeNull=True),
        outputs_prefix='Databricks.Volume',
        outputs_key_field='full_name',
        outputs=volumes,
    )


def volume_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        catalog_name=args.get('catalog_name'),
        schema_name=args.get('schema_name'),
        volume_type=args.get('volume_type'),
        storage_location=args.get('storage_location'),
    )
    result = client.create_volume(**kwargs)
    return CommandResults(
        readable_output=f"Volume '{args.get('name')}' created.",
        outputs_prefix='Databricks.Volume',
        outputs_key_field='full_name',
        outputs=result,
    )


def volume_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(new_name=args.get('new_name'), comment=args.get('comment'),
                           owner=args.get('owner'))
    result = client.update_volume(args['full_name'], **kwargs)
    return CommandResults(
        readable_output=f"Volume '{args['full_name']}' updated.",
        outputs_prefix='Databricks.Volume',
        outputs_key_field='full_name',
        outputs=result,
    )


def volume_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_volume(args['full_name'])
    return CommandResults(readable_output=f"Volume '{args['full_name']}' deleted.")


# ---- Unity Catalog — Grant Commands ----

def grant_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_grants(args['securable_type'], args['full_name'])
    grants = result.get('privilege_assignments', [])
    return CommandResults(
        readable_output=tableToMarkdown('Grants', grants,
            headers=['principal', 'privileges'], removeNull=True),
        outputs_prefix='Databricks.Grant',
        outputs=grants,
    )


def grant_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    changes = parse_json_arg(args, 'changes')
    client.update_grants(args['securable_type'], args['full_name'], changes)
    return CommandResults(readable_output='Grants updated.')


# ---- IAM — User Commands ----

def user_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_user(args['user_id'])
    return CommandResults(
        readable_output=tableToMarkdown('User', result,
            headers=['id', 'userName', 'displayName', 'active'], removeNull=True),
        outputs_prefix='Databricks.User',
        outputs_key_field='id',
        outputs=result,
    )


def user_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        filter=args.get('filter'),
        count=arg_to_number(args.get('count')),
        startIndex=arg_to_number(args.get('startIndex')),
    )
    response = client.list_users(**kwargs)
    users = response.get('Resources', [])
    return CommandResults(
        readable_output=tableToMarkdown('Users', users,
            headers=['id', 'userName', 'displayName', 'active'], removeNull=True),
        outputs_prefix='Databricks.User',
        outputs_key_field='id',
        outputs=users,
    )


def user_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    schemas = ['urn:ietf:params:scim:schemas:core:2.0:User']
    kwargs = assign_params(
        schemas=schemas,
        userName=args.get('user_name'),
        displayName=args.get('display_name'),
    )
    result = client.create_user(**kwargs)
    return CommandResults(
        readable_output=f"User created with ID: {result.get('id')}",
        outputs_prefix='Databricks.User',
        outputs_key_field='id',
        outputs=result,
    )


def user_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    operations = []
    if args.get('user_name'):
        operations.append({'op': 'replace', 'path': 'userName', 'value': args['user_name']})
    if args.get('display_name'):
        operations.append({'op': 'replace', 'path': 'displayName', 'value': args['display_name']})
    if args.get('active'):
        operations.append({'op': 'replace', 'path': 'active',
                          'value': argToBoolean(args['active'])})
    kwargs = {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations': operations,
    }
    client.update_user(args['user_id'], **kwargs)
    return CommandResults(readable_output=f"User {args['user_id']} updated.")


def user_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_user(args['user_id'])
    return CommandResults(readable_output=f"User {args['user_id']} deleted.")


# ---- IAM — Group Commands ----

def group_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_group(args['group_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Group', result,
            headers=['id', 'displayName', 'members'], removeNull=True),
        outputs_prefix='Databricks.Group',
        outputs_key_field='id',
        outputs=result,
    )


def group_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        filter=args.get('filter'),
        count=arg_to_number(args.get('count')),
        startIndex=arg_to_number(args.get('startIndex')),
    )
    response = client.list_groups(**kwargs)
    groups = response.get('Resources', [])
    return CommandResults(
        readable_output=tableToMarkdown('Groups', groups,
            headers=['id', 'displayName'], removeNull=True),
        outputs_prefix='Databricks.Group',
        outputs_key_field='id',
        outputs=groups,
    )


def group_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        schemas=['urn:ietf:params:scim:schemas:core:2.0:Group'],
        displayName=args.get('display_name'),
    )
    result = client.create_group(**kwargs)
    return CommandResults(
        readable_output=f"Group created with ID: {result.get('id')}",
        outputs_prefix='Databricks.Group',
        outputs_key_field='id',
        outputs=result,
    )


def group_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    operations = []
    if args.get('display_name'):
        operations.append({'op': 'replace', 'path': 'displayName',
                          'value': args['display_name']})
    kwargs = {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations': operations,
    }
    client.update_group(args['group_id'], **kwargs)
    return CommandResults(readable_output=f"Group {args['group_id']} updated.")


def group_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_group(args['group_id'])
    return CommandResults(readable_output=f"Group {args['group_id']} deleted.")


# ---- IAM — Service Principal Commands ----

def service_principal_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_service_principal(args['sp_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Service Principal', result,
            headers=['id', 'applicationId', 'displayName', 'active'], removeNull=True),
        outputs_prefix='Databricks.ServicePrincipal',
        outputs_key_field='id',
        outputs=result,
    )


def service_principal_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        filter=args.get('filter'),
        count=arg_to_number(args.get('count')),
        startIndex=arg_to_number(args.get('startIndex')),
    )
    response = client.list_service_principals(**kwargs)
    sps = response.get('Resources', [])
    return CommandResults(
        readable_output=tableToMarkdown('Service Principals', sps,
            headers=['id', 'applicationId', 'displayName', 'active'], removeNull=True),
        outputs_prefix='Databricks.ServicePrincipal',
        outputs_key_field='id',
        outputs=sps,
    )


def service_principal_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        schemas=['urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal'],
        applicationId=args.get('application_id'),
        displayName=args.get('display_name'),
    )
    result = client.create_service_principal(**kwargs)
    return CommandResults(
        readable_output=f"Service principal created with ID: {result.get('id')}",
        outputs_prefix='Databricks.ServicePrincipal',
        outputs_key_field='id',
        outputs=result,
    )


def service_principal_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    operations = []
    if args.get('display_name'):
        operations.append({'op': 'replace', 'path': 'displayName',
                          'value': args['display_name']})
    if args.get('active'):
        operations.append({'op': 'replace', 'path': 'active',
                          'value': argToBoolean(args['active'])})
    kwargs = {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations': operations,
    }
    client.update_service_principal(args['sp_id'], **kwargs)
    return CommandResults(readable_output=f"Service principal {args['sp_id']} updated.")


def service_principal_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_service_principal(args['sp_id'])
    return CommandResults(readable_output=f"Service principal {args['sp_id']} deleted.")


# ---- IAM — Permissions Commands ----

def permissions_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_permissions(args['object_type'], args['object_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Permissions', result,
            headers=['object_id', 'object_type', 'access_control_list'], removeNull=True),
        outputs_prefix='Databricks.Permission',
        outputs_key_field='object_id',
        outputs=result,
    )


def permissions_set_command(client: DatabricksClient, args: dict) -> CommandResults:
    acl = parse_json_arg(args, 'access_control_list')
    client.set_permissions(args['object_type'], args['object_id'], acl)
    return CommandResults(readable_output='Permissions set.')


def permissions_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    acl = parse_json_arg(args, 'access_control_list')
    client.update_permissions(args['object_type'], args['object_id'], acl)
    return CommandResults(readable_output='Permissions updated.')


# ---- Token Commands ----

def token_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_tokens()
    tokens = response.get('token_infos', [])
    return CommandResults(
        readable_output=tableToMarkdown('Tokens', tokens,
            headers=['token_id', 'creation_time', 'expiry_time', 'comment'], removeNull=True),
        outputs_prefix='Databricks.Token',
        outputs_key_field='token_id',
        outputs=tokens,
    )


def token_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        comment=args.get('comment'),
        lifetime_seconds=arg_to_number(args.get('lifetime_seconds')),
    )
    result = client.create_token(**kwargs)
    return CommandResults(
        readable_output=f"Token created. ID: {result.get('token_info', {}).get('token_id')}",
        outputs_prefix='Databricks.Token',
        outputs_key_field='token_id',
        outputs=result,
    )


def token_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(comment=args.get('comment'))
    client.update_token(args['token_id'], **kwargs)
    return CommandResults(readable_output=f"Token {args['token_id']} updated.")


def token_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_token(args['token_id'])
    return CommandResults(readable_output=f"Token {args['token_id']} revoked.")


# ---- Secret Commands ----

def secret_put_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.put_secret(args['scope'], args['key'], string_value=args.get('string_value'))
    return CommandResults(readable_output=f"Secret '{args['key']}' stored in scope '{args['scope']}'.")


def secret_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_secret(args['scope'], args['key'])
    return CommandResults(readable_output=f"Secret '{args['key']}' deleted from scope '{args['scope']}'.")


def secret_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_secrets(args['scope'])
    secrets = response.get('secrets', [])
    return CommandResults(
        readable_output=tableToMarkdown('Secrets', secrets,
            headers=['key', 'last_updated_timestamp'], removeNull=True),
        outputs_prefix='Databricks.Secret',
        outputs_key_field='key',
        outputs=secrets,
    )


# ---- Secret Scope Commands ----

def secret_scope_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.create_secret_scope(args['scope'],
                                initial_manage_principal=args.get('initial_manage_principal'))
    return CommandResults(readable_output=f"Secret scope '{args['scope']}' created.")


def secret_scope_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_secret_scopes()
    scopes = response.get('scopes', [])
    return CommandResults(
        readable_output=tableToMarkdown('Secret Scopes', scopes,
            headers=['name', 'backend_type'], removeNull=True),
        outputs_prefix='Databricks.SecretScope',
        outputs_key_field='name',
        outputs=scopes,
    )


def secret_scope_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_secret_scope(args['scope'])
    return CommandResults(readable_output=f"Secret scope '{args['scope']}' deleted.")


# ---- Secret ACL Commands ----

def secret_acl_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_secret_acl(args['scope'], args['principal'])
    return CommandResults(
        readable_output=tableToMarkdown('Secret ACL', result,
            headers=['principal', 'permission'], removeNull=True),
        outputs_prefix='Databricks.SecretACL',
        outputs=result,
    )


def secret_acl_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_secret_acls(args['scope'])
    acls = response.get('items', [])
    return CommandResults(
        readable_output=tableToMarkdown('Secret ACLs', acls,
            headers=['principal', 'permission'], removeNull=True),
        outputs_prefix='Databricks.SecretACL',
        outputs=acls,
    )


def secret_acl_put_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.put_secret_acl(args['scope'], args['principal'], args['permission'])
    return CommandResults(readable_output=f"ACL set for '{args['principal']}' on scope '{args['scope']}'.")


def secret_acl_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_secret_acl(args['scope'], args['principal'])
    return CommandResults(
        readable_output=f"ACL deleted for '{args['principal']}' on scope '{args['scope']}'.")


# ---- Dashboard Commands ----

def dashboard_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_dashboard(args['dashboard_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Dashboard', result,
            headers=['dashboard_id', 'display_name', 'warehouse_id', 'path',
                     'create_time', 'update_time'],
            removeNull=True),
        outputs_prefix='Databricks.Dashboard',
        outputs_key_field='dashboard_id',
        outputs=result,
    )


def dashboard_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        page_size=arg_to_number(args.get('page_size')),
        page_token=args.get('page_token'),
    )
    response = client.list_dashboards(**kwargs)
    dashboards = response.get('dashboards', [])
    return CommandResults(
        readable_output=tableToMarkdown('Dashboards', dashboards,
            headers=['dashboard_id', 'display_name', 'warehouse_id', 'path'], removeNull=True),
        outputs_prefix='Databricks.Dashboard',
        outputs_key_field='dashboard_id',
        outputs=dashboards,
    )


def dashboard_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        display_name=args.get('display_name'),
        warehouse_id=args.get('warehouse_id'),
        parent_path=args.get('parent_path'),
        serialized_dashboard=args.get('serialized_dashboard'),
    )
    result = client.create_dashboard(**kwargs)
    return CommandResults(
        readable_output=f"Dashboard created with ID: {result.get('dashboard_id')}",
        outputs_prefix='Databricks.Dashboard',
        outputs_key_field='dashboard_id',
        outputs=result,
    )


def dashboard_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        display_name=args.get('display_name'),
        warehouse_id=args.get('warehouse_id'),
        serialized_dashboard=args.get('serialized_dashboard'),
    )
    result = client.update_dashboard(args['dashboard_id'], **kwargs)
    return CommandResults(
        readable_output=f"Dashboard {args['dashboard_id']} updated.",
        outputs_prefix='Databricks.Dashboard',
        outputs_key_field='dashboard_id',
        outputs=result,
    )


def dashboard_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_dashboard(args['dashboard_id'])
    return CommandResults(readable_output=f"Dashboard {args['dashboard_id']} deleted.")


def dashboard_migrate_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.migrate_dashboard(args['source_dashboard_id'])
    return CommandResults(
        readable_output=f"Dashboard migrated. New ID: {result.get('dashboard_id')}",
        outputs_prefix='Databricks.Dashboard',
        outputs_key_field='dashboard_id',
        outputs=result,
    )


def dashboard_publish_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        warehouse_id=args.get('warehouse_id'),
        embed_credentials=argToBoolean(args['embed_credentials']) if args.get('embed_credentials') else None,
    )
    client.publish_dashboard(args['dashboard_id'], **kwargs)
    return CommandResults(readable_output=f"Dashboard {args['dashboard_id']} published.")


# ---- Global Init Script Commands ----

def global_init_script_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_global_init_script(args['script_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Global Init Script', result,
            headers=['script_id', 'name', 'position', 'enabled', 'created_at', 'created_by'],
            removeNull=True),
        outputs_prefix='Databricks.GlobalInitScript',
        outputs_key_field='script_id',
        outputs=result,
    )


def global_init_script_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_global_init_scripts()
    scripts = response.get('scripts', [])
    return CommandResults(
        readable_output=tableToMarkdown('Global Init Scripts', scripts,
            headers=['script_id', 'name', 'position', 'enabled', 'created_at'], removeNull=True),
        outputs_prefix='Databricks.GlobalInitScript',
        outputs_key_field='script_id',
        outputs=scripts,
    )


def global_init_script_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        script=args.get('script'),
        position=arg_to_number(args.get('position')),
        enabled=argToBoolean(args['enabled']) if args.get('enabled') else None,
    )
    result = client.create_global_init_script(**kwargs)
    return CommandResults(
        readable_output=f"Global init script created with ID: {result.get('script_id')}",
        outputs_prefix='Databricks.GlobalInitScript',
        outputs_key_field='script_id',
        outputs=result,
    )


def global_init_script_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        name=args.get('name'),
        script=args.get('script'),
        position=arg_to_number(args.get('position')),
        enabled=argToBoolean(args['enabled']) if args.get('enabled') else None,
    )
    client.update_global_init_script(args['script_id'], **kwargs)
    return CommandResults(readable_output=f"Global init script {args['script_id']} updated.")


def global_init_script_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_global_init_script(args['script_id'])
    return CommandResults(readable_output=f"Global init script {args['script_id']} deleted.")


# ---- IP Access List Commands ----

def ip_access_list_get_command(client: DatabricksClient, args: dict) -> CommandResults:
    result = client.get_ip_access_list(args['ip_access_list_id'])
    ip_list = result.get('ip_access_list', result)
    return CommandResults(
        readable_output=tableToMarkdown('IP Access List', ip_list,
            headers=['list_id', 'label', 'list_type', 'ip_addresses', 'address_count',
                     'created_at', 'created_by', 'enabled'],
            removeNull=True),
        outputs_prefix='Databricks.IPAccessList',
        outputs_key_field='list_id',
        outputs=ip_list,
    )


def ip_access_list_list_command(client: DatabricksClient, args: dict) -> CommandResults:
    response = client.list_ip_access_lists()
    lists = response.get('ip_access_lists', [])
    return CommandResults(
        readable_output=tableToMarkdown('IP Access Lists', lists,
            headers=['list_id', 'label', 'list_type', 'address_count', 'enabled'],
            removeNull=True),
        outputs_prefix='Databricks.IPAccessList',
        outputs_key_field='list_id',
        outputs=lists,
    )


def ip_access_list_create_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        label=args.get('label'),
        list_type=args.get('list_type'),
        ip_addresses=argToList(args.get('ip_addresses')),
    )
    result = client.create_ip_access_list(**kwargs)
    ip_list = result.get('ip_access_list', result)
    return CommandResults(
        readable_output=f"IP access list created with ID: {ip_list.get('list_id')}",
        outputs_prefix='Databricks.IPAccessList',
        outputs_key_field='list_id',
        outputs=ip_list,
    )


def ip_access_list_update_command(client: DatabricksClient, args: dict) -> CommandResults:
    kwargs = assign_params(
        label=args.get('label'),
        list_type=args.get('list_type'),
        ip_addresses=argToList(args.get('ip_addresses')) if args.get('ip_addresses') else None,
        enabled=argToBoolean(args['enabled']) if args.get('enabled') else None,
    )
    client.update_ip_access_list(args['ip_access_list_id'], **kwargs)
    return CommandResults(readable_output=f"IP access list {args['ip_access_list_id']} updated.")


def ip_access_list_delete_command(client: DatabricksClient, args: dict) -> CommandResults:
    client.delete_ip_access_list(args['ip_access_list_id'])
    return CommandResults(readable_output=f"IP access list {args['ip_access_list_id']} deleted.")


# =====================================================================
# Fetch Incidents
# =====================================================================

def fetch_incidents(client: DatabricksClient, params: dict, last_run: dict) -> tuple:
    max_fetch = arg_to_number(params.get('max_fetch', 50))
    first_fetch = params.get('first_fetch', '3 days')
    fetch_types = argToList(params.get('fetch_types', []))

    last_fetch_time = last_run.get('last_fetch_time')
    if not last_fetch_time:
        first_fetch_dt = dateparser.parse(f'{first_fetch} ago')
        last_fetch_time = int(first_fetch_dt.timestamp() * 1000) if first_fetch_dt else 0

    incidents: list = []
    new_last_fetch = last_fetch_time

    if 'SQL Alerts' in fetch_types or not fetch_types:
        try:
            alerts_response = client.list_sql_alerts()
            alerts = alerts_response if isinstance(alerts_response, list) else alerts_response.get('results', [])
            for alert in alerts:
                alert_time = alert.get('update_time') or alert.get('create_time', '')
                alert_ts = date_to_timestamp(alert_time, date_format='%Y-%m-%dT%H:%M:%SZ') if alert_time else 0
                if alert_ts and alert_ts > last_fetch_time:
                    alert_name = alert.get('display_name') or alert.get('name') or alert.get('id', 'Unknown')
                    incidents.append({
                        'name': f"Databricks SQL Alert: {alert_name}",
                        'occurred': timestamp_to_datestring(alert_ts),
                        'rawJSON': json.dumps(alert),
                        'type': params.get('incidentType', 'Databricks Alert'),
                        'severity': IncidentSeverity.MEDIUM,
                    })
                    new_last_fetch = max(new_last_fetch, alert_ts)
        except Exception:
            demisto.debug('Failed to fetch SQL alerts, skipping.')

    if 'Failed Jobs' in fetch_types or not fetch_types:
        try:
            runs_response = client.list_job_runs(start_time_from=last_fetch_time)
            for run in runs_response.get('runs', []):
                result_state = run.get('state', {}).get('result_state', '')
                if result_state in ('FAILED', 'TIMEDOUT', 'CANCELED'):
                    run_time = run.get('start_time', 0)
                    incidents.append({
                        'name': f"Databricks Job Failed: {run.get('run_name', run.get('run_id', 'Unknown'))}",
                        'occurred': timestamp_to_datestring(run_time),
                        'rawJSON': json.dumps(run),
                        'type': params.get('incidentType', 'Databricks Job Failure'),
                        'severity': IncidentSeverity.MEDIUM,
                    })
                    new_last_fetch = max(new_last_fetch, run_time)
        except Exception:
            demisto.debug('Failed to fetch job runs, skipping.')

    incidents = sorted(incidents, key=lambda x: x.get('occurred', ''))
    incidents = incidents[:max_fetch]
    next_run = {'last_fetch_time': new_last_fetch}
    return next_run, incidents


# =====================================================================
# Test Module
# =====================================================================

def test_module(client: DatabricksClient) -> str:
    try:
        client.list_warehouses()
        return 'ok'
    except Exception as e:
        raise DemistoException(f'Failed to connect to Databricks: {str(e)}')


# =====================================================================
# Main
# =====================================================================

def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get('url', '').rstrip('/')
    api_key_param = params.get('api_key', '')
    api_key = api_key_param.get('password', '') if isinstance(api_key_param, dict) else api_key_param
    verify = not argToBoolean(params.get('insecure', 'false'))
    proxy = argToBoolean(params.get('proxy', 'false'))

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json',
    }

    client = DatabricksClient(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        else:
            commands = {
                # Clusters
                'databricks-cluster-get': cluster_get_command,
                'databricks-cluster-list': cluster_list_command,
                'databricks-cluster-create': cluster_create_command,
                'databricks-cluster-edit': cluster_edit_command,
                'databricks-cluster-delete': cluster_delete_command,
                'databricks-cluster-permanent-delete': cluster_permanent_delete_command,
                'databricks-cluster-start': cluster_start_command,
                'databricks-cluster-restart': cluster_restart_command,
                'databricks-cluster-resize': cluster_resize_command,
                'databricks-cluster-pin': cluster_pin_command,
                'databricks-cluster-unpin': cluster_unpin_command,
                'databricks-cluster-change-owner': cluster_change_owner_command,
                'databricks-cluster-list-zones': cluster_list_zones_command,
                'databricks-cluster-update': cluster_update_command,
                # Cluster Policies
                'databricks-cluster-policy-get': cluster_policy_get_command,
                'databricks-cluster-policy-list': cluster_policy_list_command,
                'databricks-cluster-policy-create': cluster_policy_create_command,
                'databricks-cluster-policy-edit': cluster_policy_edit_command,
                'databricks-cluster-policy-delete': cluster_policy_delete_command,
                # Instance Pools
                'databricks-instance-pool-get': instance_pool_get_command,
                'databricks-instance-pool-list': instance_pool_list_command,
                'databricks-instance-pool-create': instance_pool_create_command,
                'databricks-instance-pool-edit': instance_pool_edit_command,
                'databricks-instance-pool-delete': instance_pool_delete_command,
                # Libraries
                'databricks-library-cluster-status': library_cluster_status_command,
                'databricks-library-all-cluster-statuses': library_all_cluster_statuses_command,
                'databricks-library-install': library_install_command,
                'databricks-library-uninstall': library_uninstall_command,
                # Command Execution
                'databricks-context-create': context_create_command,
                'databricks-context-destroy': context_destroy_command,
                'databricks-context-status': context_status_command,
                'databricks-command-execute': command_execute_command,
                'databricks-command-status': command_status_command,
                'databricks-command-cancel': command_cancel_command,
                # Jobs
                'databricks-job-get': job_get_command,
                'databricks-job-list': job_list_command,
                'databricks-job-create': job_create_command,
                'databricks-job-reset': job_reset_command,
                'databricks-job-update': job_update_command,
                'databricks-job-delete': job_delete_command,
                'databricks-job-run-now': job_run_now_command,
                # Pipelines
                'databricks-pipeline-get': pipeline_get_command,
                'databricks-pipeline-list': pipeline_list_command,
                'databricks-pipeline-create': pipeline_create_command,
                'databricks-pipeline-update': pipeline_update_command,
                'databricks-pipeline-delete': pipeline_delete_command,
                'databricks-pipeline-clone': pipeline_clone_command,
                'databricks-pipeline-start': pipeline_start_command,
                'databricks-pipeline-stop': pipeline_stop_command,
                'databricks-pipeline-events': pipeline_events_command,
                'databricks-pipeline-list-updates': pipeline_list_updates_command,
                'databricks-pipeline-get-update': pipeline_get_update_command,
                'databricks-pipeline-apply-environment': pipeline_apply_environment_command,
                # DBFS
                'databricks-dbfs-get-status': dbfs_get_status_command,
                'databricks-dbfs-list': dbfs_list_command,
                'databricks-dbfs-read': dbfs_read_command,
                'databricks-dbfs-create': dbfs_create_command,
                'databricks-dbfs-add-block': dbfs_add_block_command,
                'databricks-dbfs-close': dbfs_close_command,
                'databricks-dbfs-put': dbfs_put_command,
                'databricks-dbfs-delete': dbfs_delete_command,
                'databricks-dbfs-mkdirs': dbfs_mkdirs_command,
                'databricks-dbfs-move': dbfs_move_command,
                # Workspace
                'databricks-workspace-get-status': workspace_get_status_command,
                'databricks-workspace-list': workspace_list_command,
                'databricks-workspace-export': workspace_export_command,
                'databricks-workspace-import': workspace_import_command,
                'databricks-workspace-delete': workspace_delete_command,
                'databricks-workspace-mkdirs': workspace_mkdirs_command,
                # Git Credentials
                'databricks-git-credential-get': git_credential_get_command,
                'databricks-git-credential-list': git_credential_list_command,
                'databricks-git-credential-create': git_credential_create_command,
                'databricks-git-credential-update': git_credential_update_command,
                'databricks-git-credential-delete': git_credential_delete_command,
                # Repos
                'databricks-repo-get': repo_get_command,
                'databricks-repo-list': repo_list_command,
                'databricks-repo-create': repo_create_command,
                'databricks-repo-update': repo_update_command,
                # SQL Warehouses
                'databricks-warehouse-get': warehouse_get_command,
                'databricks-warehouse-list': warehouse_list_command,
                'databricks-warehouse-create': warehouse_create_command,
                'databricks-warehouse-edit': warehouse_edit_command,
                'databricks-warehouse-delete': warehouse_delete_command,
                'databricks-warehouse-start': warehouse_start_command,
                'databricks-warehouse-stop': warehouse_stop_command,
                'databricks-warehouse-get-config': warehouse_get_config_command,
                'databricks-warehouse-set-config': warehouse_set_config_command,
                # SQL Statements
                'databricks-sql-statement-execute': sql_statement_execute_command,
                'databricks-sql-statement-get-status': sql_statement_get_status_command,
                'databricks-sql-statement-get-result-chunk': sql_statement_get_result_chunk_command,
                'databricks-sql-statement-cancel': sql_statement_cancel_command,
                # SQL Queries
                'databricks-sql-query-get': sql_query_get_command,
                'databricks-sql-query-list': sql_query_list_command,
                'databricks-sql-query-create': sql_query_create_command,
                'databricks-sql-query-update': sql_query_update_command,
                'databricks-sql-query-delete': sql_query_delete_command,
                # SQL Alerts
                'databricks-sql-alert-list': sql_alert_list_command,
                'databricks-sql-alert-get': sql_alert_get_command,
                'databricks-sql-alert-create': sql_alert_create_command,
                'databricks-sql-alert-update': sql_alert_update_command,
                'databricks-sql-alert-delete': sql_alert_delete_command,
                # SQL Query History
                'databricks-sql-query-history-list': sql_query_history_list_command,
                # Serving Endpoints
                'databricks-serving-endpoint-list': serving_endpoint_list_command,
                'databricks-serving-endpoint-get': serving_endpoint_get_command,
                'databricks-serving-endpoint-create': serving_endpoint_create_command,
                'databricks-serving-endpoint-update-config': serving_endpoint_update_config_command,
                'databricks-serving-endpoint-delete': serving_endpoint_delete_command,
                'databricks-serving-endpoint-query': serving_endpoint_query_command,
                'databricks-serving-endpoint-get-logs': serving_endpoint_get_logs_command,
                # Vector Search
                'databricks-vector-search-endpoint-list': vector_search_endpoint_list_command,
                'databricks-vector-search-endpoint-get': vector_search_endpoint_get_command,
                'databricks-vector-search-endpoint-create': vector_search_endpoint_create_command,
                'databricks-vector-search-endpoint-delete': vector_search_endpoint_delete_command,
                'databricks-vector-search-endpoint-get-metrics': vector_search_endpoint_get_metrics_command,
                # MLflow
                'databricks-mlflow-metric-history': mlflow_metric_history_command,
                'databricks-mlflow-model-list': mlflow_model_list_command,
                'databricks-mlflow-model-get': mlflow_model_get_command,
                'databricks-mlflow-model-version-create': mlflow_model_version_create_command,
                'databricks-mlflow-model-version-get': mlflow_model_version_get_command,
                'databricks-mlflow-model-version-search': mlflow_model_version_search_command,
                'databricks-mlflow-model-version-delete': mlflow_model_version_delete_command,
                'databricks-mlflow-model-version-transition-stage': mlflow_model_version_transition_stage_command,
                # Unity Catalog — Catalogs
                'databricks-catalog-get': catalog_get_command,
                'databricks-catalog-list': catalog_list_command,
                'databricks-catalog-create': catalog_create_command,
                'databricks-catalog-update': catalog_update_command,
                'databricks-catalog-delete': catalog_delete_command,
                # Unity Catalog — Schemas
                'databricks-schema-get': schema_get_command,
                'databricks-schema-list': schema_list_command,
                'databricks-schema-create': schema_create_command,
                'databricks-schema-update': schema_update_command,
                'databricks-schema-delete': schema_delete_command,
                # Unity Catalog — Tables
                'databricks-table-get': table_get_command,
                'databricks-table-list': table_list_command,
                'databricks-table-delete': table_delete_command,
                'databricks-table-exists': table_exists_command,
                'databricks-table-summaries': table_summaries_command,
                # Unity Catalog — Volumes
                'databricks-volume-get': volume_get_command,
                'databricks-volume-list': volume_list_command,
                'databricks-volume-create': volume_create_command,
                'databricks-volume-update': volume_update_command,
                'databricks-volume-delete': volume_delete_command,
                # Unity Catalog — Grants
                'databricks-grant-get': grant_get_command,
                'databricks-grant-update': grant_update_command,
                # IAM — Users
                'databricks-user-get': user_get_command,
                'databricks-user-list': user_list_command,
                'databricks-user-create': user_create_command,
                'databricks-user-update': user_update_command,
                'databricks-user-delete': user_delete_command,
                # IAM — Groups
                'databricks-group-get': group_get_command,
                'databricks-group-list': group_list_command,
                'databricks-group-create': group_create_command,
                'databricks-group-update': group_update_command,
                'databricks-group-delete': group_delete_command,
                # IAM — Service Principals
                'databricks-service-principal-get': service_principal_get_command,
                'databricks-service-principal-list': service_principal_list_command,
                'databricks-service-principal-create': service_principal_create_command,
                'databricks-service-principal-update': service_principal_update_command,
                'databricks-service-principal-delete': service_principal_delete_command,
                # IAM — Permissions
                'databricks-permissions-get': permissions_get_command,
                'databricks-permissions-set': permissions_set_command,
                'databricks-permissions-update': permissions_update_command,
                # Tokens
                'databricks-token-list': token_list_command,
                'databricks-token-create': token_create_command,
                'databricks-token-update': token_update_command,
                'databricks-token-delete': token_delete_command,
                # Secrets
                'databricks-secret-put': secret_put_command,
                'databricks-secret-delete': secret_delete_command,
                'databricks-secret-list': secret_list_command,
                # Secret Scopes
                'databricks-secret-scope-create': secret_scope_create_command,
                'databricks-secret-scope-list': secret_scope_list_command,
                'databricks-secret-scope-delete': secret_scope_delete_command,
                # Secret ACLs
                'databricks-secret-acl-get': secret_acl_get_command,
                'databricks-secret-acl-list': secret_acl_list_command,
                'databricks-secret-acl-put': secret_acl_put_command,
                'databricks-secret-acl-delete': secret_acl_delete_command,
                # Dashboards
                'databricks-dashboard-get': dashboard_get_command,
                'databricks-dashboard-list': dashboard_list_command,
                'databricks-dashboard-create': dashboard_create_command,
                'databricks-dashboard-update': dashboard_update_command,
                'databricks-dashboard-delete': dashboard_delete_command,
                'databricks-dashboard-migrate': dashboard_migrate_command,
                'databricks-dashboard-publish': dashboard_publish_command,
                # Global Init Scripts
                'databricks-global-init-script-get': global_init_script_get_command,
                'databricks-global-init-script-list': global_init_script_list_command,
                'databricks-global-init-script-create': global_init_script_create_command,
                'databricks-global-init-script-update': global_init_script_update_command,
                'databricks-global-init-script-delete': global_init_script_delete_command,
                # IP Access Lists
                'databricks-ip-access-list-get': ip_access_list_get_command,
                'databricks-ip-access-list-list': ip_access_list_list_command,
                'databricks-ip-access-list-create': ip_access_list_create_command,
                'databricks-ip-access-list-update': ip_access_list_update_command,
                'databricks-ip-access-list-delete': ip_access_list_delete_command,
            }
            if command in commands:
                return_results(commands[command](client, args))
            else:
                raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}',
                     error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
