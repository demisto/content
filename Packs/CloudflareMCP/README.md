Use the Cloudflare MCP integration to connect securely with a Cloudflare Model Context Protocol (MCP) server and access its tools in real time.

## What does this pack do

This integration provides tools primarily intended for use with Agentix Actions. It enables you to:

- Retrieve a list of available tools in the Cloudflare MCP server.
- Call a specific tool on the Cloudflare MCP server with optional input parameters.

## Available tools (Availability depends on the chosen Server)

### docs - Documentation server

`search_cloudflare_documentation`

### bindings - Workers Bindings server

`accounts_list`  `set_active_account`  `kv_namespaces_list`  `kv_namespace_create`  `kv_namespace_delete`  `kv_namespace_get`  `kv_namespace_update`  `workers_list`  `workers_get_worker`  `workers_get_worker_code`  `r2_buckets_list`  `r2_bucket_create`  `r2_bucket_get`  `r2_bucket_delete`  `d1_databases_list`  `d1_database_create`  `d1_database_delete`  `d1_database_get`  `d1_database_query`  `hyperdrive_configs_list`  `hyperdrive_config_create`  `hyperdrive_config_delete`  `hyperdrive_config_get`  `hyperdrive_config_edit`

### builds - Workers Builds server

`workers_builds_set_active_worker`  `workers_builds_list_builds`  `workers_builds_get_build`  `workers_builds_get_build_logs`

### observability - Observability server

`query_worker_observability`  `observability_keys`  `observability_values`

### radar - Radar server

`get_ai_data`  `list_autonomous_systems`  `get_as_details`  `get_domains_ranking`  `get_domain_rank_details`  `get_dns_data`  `get_email_routing_data`  `get_email_security_data`  `get_http_data`  `get_ip_details`  `get_internet_services_ranking`  `get_internet_quality_data`  `get_internet_speed_data`  `get_l3_attack_data`  `get_l7_attack_data`  `get_traffic_anomalies`  `scan_url`

### containers - Container server

`container_initialize`  `container_ping`  `container_file_write`  `container_files_list`  `container_file_read`  `container_file_delete`  `container_exec`

### browser - Browser rendering server

`get_url_html_content`  `get_url_markdown`  `get_url_screenshot`

### logs - Logpush server

`logpush_jobs_by_account_id`

### ai-gateway - AI Gateway server

`list_gateways`  `list_logs`  `get_log_details`  `get_log_request_body`  `get_log_response_body`

### autorag - AutoRAG server

`list_rags`  `search`  `ai_search`

### auditlogs - Audit Logs server

`auditlogs_by_account_id`

### dns-analytics - DNS Analytics server

`zones_list`  `dns_report`  `show_account_dns_settings`  `show_zone_dns_settings`

### dex - Digital Experience Monitoring server

`dex_test_statistics`  `dex_list_tests`  `dex_http_test_details`  `dex_traceroute_test_details`  `dex_traceroute_test_network_path`  `dex_traceroute_test_result_network_path`  `dex_list_remote_capture_eligible_devices`  `dex_create_remote_pcap`  `dex_create_remote_warp_diag`  `dex_list_remote_captures`  `dex_list_remote_warp_diag_contents`  `dex_explore_remote_warp_diag_output`  `dex_analyze_warp_diag`  `dex_fleet_status_live`  `dex_fleet_status_over_time`  `dex_fleet_status_logs`  `dex_list_warp_change_events`  `dex_list_colos`  

### casb - Cloudflare One CASB server

`accounts_list`  `set_active_account`  `integration_by_id`  `integrations_list`  `assets_search`  `asset_by_id`  `assets_by_integration_id`  `assets_by_category_id`  `assets_list`  `asset_categories_list`  `asset_categories_by_vendor`  `asset_categories_by_type`  `asset_categories_by_vendor_and_type`

### graphql - GraphQL server

`graphql_schema_search`  `graphql_schema_overview`  `graphql_type_details`  `graphql_complete_schema`  `graphql_query`  `graphql_api_explorer`
