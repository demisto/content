# Databricks

Comprehensive integration with Databricks workspace APIs for managing clusters, jobs, SQL, pipelines, Unity Catalog, MLflow, IAM, and more.

## What does this pack do?

This Cortex content pack enables Cortex XSIAM, Cortex XSOAR, and Cortex Cloud to interact with Databricks workspace APIs, providing 193 commands across 34 API groups:

- **Compute Management** -- Create, manage, and monitor clusters, cluster policies, instance pools, and libraries.
- **Job Orchestration** -- Create, schedule, and monitor Databricks jobs and pipelines (DLT) workflows.
- **SQL Analytics** -- Execute SQL statements, manage warehouses, saved queries, and alerts.
- **Data Governance** -- Manage Unity Catalog resources (catalogs, schemas, tables, volumes) and access grants.
- **ML Operations** -- Manage MLflow model registry, serving endpoints, and vector search.
- **Identity & Access** -- Manage users, groups, service principals, permissions, and tokens via SCIM.
- **Security** -- Manage secrets, secret scopes, IP access lists, and global init scripts.
- **Monitoring** -- Fetch SQL alerts and failed job runs as Cortex incidents for automated response.

## Authentication

This integration uses Databricks Personal Access Token (PAT) authentication.

1. Log in to your Databricks workspace.
2. Navigate to **Settings > Developer > Access tokens**.
3. Click **Generate new token**, set a comment and lifetime, and copy the token value.
4. Paste the token into the integration configuration in Cortex XSIAM/XSOAR.

## Use Cases

- **Incident Response** -- Automatically ingest failed job runs and triggered SQL alerts as incidents.
- **Threat Hunting** -- Query Databricks SQL query history and audit logs for suspicious activity.
- **Access Review** -- List and audit users, groups, service principals, permissions, and tokens.
- **Data Governance** -- Monitor Unity Catalog resources, grants, and secret access controls.
- **Operational Monitoring** -- Track cluster states, warehouse health, and pipeline statuses.
