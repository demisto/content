from google.api_core.extended_operation import ExtendedOperation
from google.cloud import compute_v1
from google.oauth2.service_account import Credentials


class InstancesService:

    def __init__(self, creds: str | Credentials, zone: str):
        credentials = creds if isinstance(
            creds, Credentials) else Credentials.from_service_account_file(creds)

        self.zone = zone
        self.project_id = credentials.project_id
        self.instance_client = compute_v1.InstancesClient(
            credentials=credentials)

    def get_all_instances(self) -> dict[str, compute_v1.Instance]:
        all_instances = {}
        # List instances in the specified project and zone with the page token
        instances = self.instance_client.aggregated_list(project=self.project_id,)

        for instances_zone, instance_list in instances:
            if self.zone in instances_zone:
                for instance in instance_list.instances:
                    all_instances[instance.name] = instance

        return all_instances

    def delete_instance(self, instance_name: str) -> ExtendedOperation:
        operation = self.instance_client.delete(project=self.project_id, zone=self.zone, instance=instance_name)
        result = operation.result()
        return result
