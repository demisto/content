import demistomock as demisto
from CommonServerPython import *  # noqa: F401

""" Imports """
# noinspection PyUnresolvedReferences


# noinspection PyUnresolvedReferences


import json
import time
from distutils.util import strtobool

import urllib3
from requests import Session

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

""" Classes """


class IntegrationForAWX:

    def __init__(self, url=None, username=None, password=None, ssl_verify=True):

        self.url = f"{url.rstrip('/')}/api/v2"

        self.session = Session()
        if ssl_verify:
            self.session.verify = ssl_verify

        self.session.auth = (username, password)
        self.session.headers.update({'content-type': 'application/json'})

    def test_method(self):
        response = self.session.get(f"{self.url}/me/")
        if response.status_code != 200:
            raise Exception(response.content)
        return "ok"

    def run_ad_hoc(self, inventory_id=None, credential_id=None, module_name="setup",
                   limit=None, module_args=None, extra_vars=None,
                   timeout=900, asynchronous=False):
        data = {
            "job_type": "run",
            "inventory": inventory_id,
            "limit": limit,
            "credential": credential_id,
            "module_name": module_name,
            "module_args": module_args,
            "forks": 0,
            "verbosity": 0,
            "extra_vars": extra_vars,
            "become_enabled": False,
            "diff_mode": False
        }
        response = self.session.post(f"{self.url}/ad_hoc_commands/", data=json.dumps(data))

        if response.status_code != 201:
            raise Exception(response.content)

        return self.wait_for_job(job_type="ad_hoc_commands", job_id=response.json()["id"],
                                 timeout=timeout, asynchronous=asynchronous)

    def wait_for_job(self, job_type="jobs", job_id=None, timeout=60, increment=5, asynchronous=False):
        timeout = int(timeout)
        increment = int(increment)
        start_time = time.time()
        result = {"status": "pending", "id": job_id, "type": job_type}
        if isinstance(asynchronous, str):
            asynchronous = strtobool(asynchronous.lower())

        if asynchronous:
            return result
        while True:
            response = self.session.get(f"{self.url}/{job_type}/{job_id}")
            if response.status_code != 200:
                raise Exception(response.content)
            response = response.json()
            if response["status"] == "successful":
                result["status"] = response["status"]
                return result

            if response["status"] == "failed":
                result["status"] = response["status"]
                return result

            if (time.time() - start_time) > timeout:
                raise Exception("Time out waiting for job to finish")

            time.sleep(increment)

    def run_template(self, job_type="job", template_id=None, extra_vars=None, timeout=900, asynchronous=False):
        # job or workflow_job
        body = {}
        if extra_vars:
            body.update({"extra_vars": extra_vars})

        response = self.session.post(f"{self.url}/{job_type}_templates/{template_id}/launch/", data=json.dumps(body))

        if response.status_code != 201:
            raise Exception(response.content)

        return self.wait_for_job(job_id=response.json()["id"], timeout=timeout, asynchronous=asynchronous)

    def query(self, query=None, path="job_templates"):
        if isinstance(query, str):
            query = json.loads(query)

        response = self.session.get(f"{self.url}/{path.rstrip('/')}/", params=query)

        if response.status_code != 200:
            raise Exception(response.content)

        return response.json()

    def get_stdout(self, job_id):
        response = self.session.get(f"{self.url}/jobs/{job_id}/stdout/?format=txt")

        if response.status_code != 200:
            raise Exception(response.content)

        return response.text


""" Main Method """


def main():
    try:
        api = IntegrationForAWX(url=demisto.params().get("url"),
                                username=demisto.params().get("credentials")["identifier"],
                                password=demisto.params().get("credentials")["password"],
                                ssl_verify=demisto.params().get("ssl_verify"))
        if demisto.command() == 'test-module':
            demisto.results(api.test_method())
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            last_id = last_run.get("last_id", 0)
            result = api.query(path="jobs", query={"id__gt": last_id})
            incidents = []
            for job in result['results']:
                changed = api.query(path=f"jobs/{job['id']}/job_events")
                has_changed = False

                for event in changed['results']:
                    if event['changed']:
                        has_changed = True
                        break

                if has_changed:
                    incident = {
                        'name': job['name'],
                        'occurred': job['created'],
                        'rawJSON': json.dumps(job)
                    }

                    incidents.append(incident)
                last_id = str(job['id'])

            demisto.incidents(incidents)

            demisto.setLastRun({
                'last_id': last_id
            })
        elif demisto.command() == "awx-launch-template":
            result = api.run_template(job_type=demisto.args().get("type", "job"),
                                      template_id=demisto.args().get("template_id"),
                                      extra_vars=demisto.args().get("extra_vars", {}),
                                      timeout=demisto.args().get("timeout", 900),
                                      asynchronous=demisto.args().get("asynchronous", False))

            markdown = tableToMarkdown('Ansible Job', [result], headers=['id', 'status', 'type'])

            command_result = CommandResults(outputs_prefix="IntegrationForAWX.template",
                                            outputs_key_field="id",
                                            outputs=result,
                                            readable_output=markdown,
                                            raw_response=result, )
            return_results(command_result)
        elif demisto.command() == "awx-launch-adhoc":
            result = api.run_ad_hoc(inventory_id=demisto.args().get("inventory_id"),
                                    credential_id=demisto.args().get("credential_id"),
                                    module_name=demisto.args().get("module_name"),
                                    timeout=demisto.args().get("timeout", 900),
                                    asynchronous=demisto.args().get("asynchronous", False),
                                    extra_vars=demisto.args().get("extra_vars", {})
                                    )
            result.update({"module": demisto.args().get("module_name")})
            markdown = tableToMarkdown('Ansible Ad-Hoc Command', [result], headers=['id', 'status', 'type', "module"])

            command_result = CommandResults(outputs_prefix="IntegrationForAWX.adhoc",
                                            outputs_key_field="id",
                                            outputs=result,
                                            readable_output=markdown,
                                            raw_response=result)
            return_results(command_result)

        elif demisto.command() == "awx-query":
            result = api.query(query=demisto.args().get("query", None),
                               path=demisto.args().get("path", "me"))

            markdown = tableToMarkdown('Ansible API Command', result['results'])

            command_result = CommandResults(outputs_prefix=f"IntegrationForAWX.query.{demisto.args().get('path', 'me')}",
                                            outputs_key_field="results.id",
                                            outputs=result,
                                            readable_output=markdown,
                                            raw_response=result)
            return_results(command_result)

        elif demisto.command() == "awx-stdout":
            result = api.get_stdout(job_id=demisto.args().get("job_id", None))

            markdown = tableToMarkdown('Ansible Stdout', {"job_id": demisto.args().get("job_id", None),
                                                          "result": result})

            command_result = CommandResults(outputs_prefix="IntegrationForAWX.jobout",
                                            outputs_key_field="job_id",
                                            outputs={"job_id": demisto.args().get("job_id", None),
                                                     "result": result},
                                            readable_output=markdown,
                                            raw_response=result)
            return_results(command_result)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
