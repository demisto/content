import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LOG_LINE = "FeedMISPThreatActors -"


''' CLIENT CLASS '''

class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(
        self, base_url: str, verify: bool, proxy: bool, reliability: str
    ):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        self.name = "MISPThreatActors"
        self.reliability = reliability

    def get_threat_actors_galaxy_file(self) -> dict[str, Any]:   # pragma: no cover
        """

        """
        demisto.debug(f"{LOG_LINE} Trying to fetch Threat Actor Galaxy from Github")
        try:
            data = self._http_request(method="GET", raise_on_status=True, url_suffix="threat-actor.json")
        
        except Exception:
            raise
        
        return data

    def test_module(self) -> str:   # pragma: no cover
        """
        Tests API connectivity and authentication'
        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.
        :type client: ``Client``
        :param Client: client to use
        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        """

        try:
            self.get_threat_actors_galaxy_file()

        except DemistoException:
            raise

        return 'ok'


''' HELPER FUNCTIONS '''

def build_relationships(original_ioc: str,
                        related_iocs: list[str],
                        related_iocs_type: str,
                        relationship_name: str) -> list[EntityRelationship]:
    """
    Builds a list of EntityRelationship objects based on the provided original IOC and related IOCs.

    Args:
        original_ioc (str): The original IOC value.
        related_iocs (list[str]): A list of related IOC values.
        related_iocs_type (str): The type of the related IOCs.

    Returns:
        list[EntityRelationship]: A list of EntityRelationship objects.
    """
    relationships = []

    for related_ioc in related_iocs:
        relationships.append(
            EntityRelationship(
                name=relationship_name,
                entity_a=original_ioc,
                entity_a_type="Threat Actor",
                entity_b=related_ioc,
                entity_b_type=related_iocs_type,
            )
        )

    return relationships

def parse_refs(original_ioc: str, refs: list[str]) -> list[dict[str, str]]:
    """
    Parses the references for a given original IOC and builds the correct format to be used in the indicator Publications.

    Args:
        original_ioc (str): The value of the original threat actor.
        refs (list[str]): A list of URLs relevant to the threat actor.

    Returns:
        list[dict[str, str]]: A list of dictionaries containing the parsed references for the original IOC.
    """
    
    parsed_refs = []
    
    for ref in refs:
        parsed_refs.append(
            {
                "title": original_ioc,
                "source": "MISP Threat Actors Galaxy",
                "link": ref,
                "timestamp": datetime.now().strftime(DATE_FORMAT)
            }
        )
    
    return parsed_refs


''' COMMAND FUNCTIONS '''

def fetch_indicators_command(client: Client, feed_tags: str, tlp_color: str) -> tuple[str, list[dict[str, Any]]]:
    indicators = []
    data = client.get_threat_actors_galaxy_file()
    now = datetime.now(timezone.utc)
    version = data["version"]
    latest_version = demisto.getIntegrationContext().get("version", 0)
    
    if int(version) <= int(latest_version):
        demisto.debug(f"{LOG_LINE} No new updates - Exiting")
        return now.strftime(DATE_FORMAT), []
    
    for threat_actor in data["values"]:
        relationships = []
        meta = threat_actor.get("meta", {})
        value = threat_actor["value"]
        
        if len(value.split(" ")) >=2:
            value = value.title()
        
        indicator = {
            "value": value,
            "type": "Threat Actor",
            "reliability": client.reliability,
            "fields": {
                "description": threat_actor.get("description", ""),
                "geocountry": meta.get("country", ""),
                },
            
            "tags": [tag for tag in feed_tags.split(",")+[f'MISP_ID: {(threat_actor.get("uuid"))}'] if tag],
            "tlp_color": tlp_color
        }

        if refs:=meta.get("refs", []):
            indicator["publications"] = parse_refs(threat_actor["value"], refs)
        
        if synonyms := meta.get("synonyms", []):
            indicator["fields"]["aliases"] = synonyms
            relationships.extend(build_relationships(indicator["value"], synonyms, "Threat Actor", "is-also"))
        
        if targets:= meta.get("cfr-suspected-victims", []):
            relationships.extend(build_relationships(indicator["value"], targets, "Location", "targets"))
        
        if sectors := meta.get("cfr-target-category", []):
            relationships.extend(build_relationships(indicator["value"], sectors, "Identity", "targets"))
        
        if goals:=meta.get("cfr-type-of-incident", []):
            indicator["fields"]["goals"] = goals
                
        indicator["relationships"] = relationships
        
        indicators.append(indicator)
    
    demisto.setIntegrationContext = {"version": data["version"]}
    
    return now.strftime(DATE_FORMAT), indicators
    

''' MAIN FUNCTION '''

def main():
    params = demisto.params()
    
    """PARAMS"""
    base_url = params["url"]
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", "")
    reliability = params.get("integrationReliability", "B - Usually reliable")
    tlp_color = params.get('tlp_color') or 'WHITE'
    feed_tags = params.get('feedTags', '')

    if not DBotScoreReliability.is_valid_type(reliability):
        raise Exception(
            "Please provide a valid value for the Source Reliability parameter."
        )

    try:
        command = demisto.command()
        client = Client(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            reliability=reliability,
        )

        commands = {}
        
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = client.test_module()
            return_results(result)

        elif command == 'fetch-indicators':
            run_datetime, res = fetch_indicators_command(
                client=client,
                feed_tags=feed_tags,
                tlp_color=tlp_color,
            )

            for iter_ in batch(res, batch_size=2000):
                demisto.debug(f"{LOG_LINE} {iter_=}")
                demisto.createIndicators(iter_)

            demisto.setLastRun({"last_successful_run": run_datetime})

        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except NotImplementedError:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command. The command not implemented")

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error runnning integration - {err}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
