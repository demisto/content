import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

from polyswarm_api.api import PolyswarmAPI

import socket
import io

""" CONSTANTS """
POLYSWARM_DEMISTO_VERSION = "0.2.0"
ERROR_ENDPOINT = "Error with endpoint: "


# Allows nested keys to be accesible
def makehash():
    import collections

    return collections.defaultdict(makehash)


# Polyswarm-Demisto Interface
class PolyswarmConnector:
    def __init__(self):
        self.config = {}  # type: Dict[str,str]
        self.config["polyswarm_api_key"] = demisto.params().get("api_key")
        self.config["base_url"] = demisto.params().get("base_url")
        self.config["polyswarm_community"] = demisto.params().get("polyswarm_community")

        self.polyswarm_api = PolyswarmAPI(key=self.config["polyswarm_api_key"], uri=self.config["base_url"])

    def _get_results(
        self, object_name: str, title: str, total_scans: int, positives: int, permalink: str, artifact: str, indicator: object
    ) -> object:
        results = {
            "Scan_UUID": artifact,
            "Total": str(total_scans),
            "Positives": str(positives),
            "Permalink": permalink,
            "Artifact": artifact,
        }

        readable_output = tableToMarkdown(title, results)
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"PolySwarm.{object_name}",
            outputs_key_field="Scan_UUID",
            outputs=results,
            indicator=indicator,  # type: ignore
            ignore_auto_extract=True,
        )

    def test_connectivity(self) -> bool:
        EICAR_HASH = "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"  # guardrails-disable-line

        try:
            results = self.polyswarm_api.search(EICAR_HASH)
            for result in results:
                if result.failed:
                    return False
        except Exception:
            return False

        return True

    def get_score(self, polyscore) -> int:
        if float(polyscore) < 0.2:
            return Common.DBotScore.GOOD
        elif 0.2 <= float(polyscore) < 0.7:
            return Common.DBotScore.SUSPICIOUS
        else:  # polyscore is >= 0.7
            return Common.DBotScore.BAD

    def return_hash_results(self, results: list, title: str, error_msg: str) -> object:
        # default values
        total_scans: int = 0
        positives: int = 0
        md5: str = ""
        sha256: str = ""
        sha1: str = ""
        polyscore: int = 0

        for result in results:
            if result.failed:
                return_error(error_msg)

            if not result.assertions:
                return_error("Run Rescan for this hash")

            # iterate for getting positives and total_scan number
            for assertion in result.assertions:
                if assertion.verdict:
                    positives += 1
                total_scans += 1

            demisto.debug(
                "Positives: {positives} - Total Scans: {total_scans}".format(positives=positives, total_scans=total_scans)
            )

            md5 = result.md5
            sha256 = result.sha256
            sha1 = result.sha1

            polyscore = result.polyscore

        dbot_score = Common.DBotScore(
            indicator=md5,
            indicator_type=DBotScoreType.FILE,
            integration_name="PolySwarm",
            score=self.get_score(polyscore),
            reliability=demisto.params().get("integrationReliability"),
        )

        indicator = Common.File(md5=md5, sha1=sha1, sha256=sha256, dbot_score=dbot_score)

        return self._get_results("File", title, total_scans, positives, result.permalink, sha256, indicator)

    def file_reputation(self, hashes: list) -> object:
        command_results = []

        artifacts = argToList(hashes)

        for artifact in artifacts:
            title = "PolySwarm File Reputation for Hash: %s" % artifact

            demisto.debug(f"[file_reputation] {title}")

            try:
                results = self.polyswarm_api.search(artifact)

            except Exception as err:
                return_error("{ERROR_ENDPOINT}{err}".format(ERROR_ENDPOINT=ERROR_ENDPOINT, err=err))

            error_msg = "Error fetching results. Please try again."

            command_results.append(self.return_hash_results(results, title, error_msg))
        return command_results

    def detonate_file(self, entry_id: dict) -> object:
        title = "PolySwarm File Detonation for Entry ID: %s" % entry_id

        demisto.debug(f"[detonate_file] {title}")

        try:
            file_info = demisto.getFilePath(entry_id)
        except Exception:
            return_error(f"File not found - EntryID: {entry_id}")

        try:
            demisto.debug(f"Submit file: {file_info}")
            instance = self.polyswarm_api.submit(file_info["path"], artifact_name=file_info["name"])
            result = self.polyswarm_api.wait_for(instance)

        except Exception as err:
            return_error("{ERROR_ENDPOINT}{err}".format(ERROR_ENDPOINT=ERROR_ENDPOINT, err=err))

        error_msg = "Error submitting File."

        return self.return_hash_results([result], title, error_msg)

    def rescan_file(self, hashes: list) -> object:
        command_results = []

        artifacts = argToList(hashes)

        for artifact in artifacts:
            title = "PolySwarm Rescan for Hash: %s" % artifact

            demisto.debug(f"[rescan_file] {title}")

            try:
                instance = self.polyswarm_api.rescan(artifact)
                result = self.polyswarm_api.wait_for(instance)

            except Exception as err:
                return_error("{ERROR_ENDPOINT}{err}".format(ERROR_ENDPOINT=ERROR_ENDPOINT, err=err))

            error_msg = "Error rescaning File."

            command_results.append(self.return_hash_results([result], title, error_msg))
        return command_results

    def get_file(self, hash_file: str):
        demisto.debug(f"[get_file] Hash: {hash_file}")

        handle_file = io.BytesIO()

        try:
            self.polyswarm_api.download_to_handle(hash_file, handle_file)
            return fileResult(hash_file, handle_file.getvalue())
        except Exception as err:
            return_error("{ERROR_ENDPOINT}{err}".format(ERROR_ENDPOINT=ERROR_ENDPOINT, err=err))

    def url_reputation(self, param: dict, artifact_type: str) -> list:
        command_results = []

        artifacts = argToList(param[artifact_type])

        for artifact in artifacts:
            title = "PolySwarm {} Reputation for: {}".format(artifact_type.upper(), artifact)

            demisto.debug(f"[url_reputation] {title}")

            # default values
            total_scans = 0
            positives = 0
            polyscore = 0

            # IP validation
            if artifact_type == "ip":
                try:
                    socket.inet_aton(artifact)
                except OSError:
                    return_error("Invalid IP Address: {ip}".format(ip=artifact))

            try:
                # PolySwarm API: URL, IP and Domain are artifact_type='url'
                instance = self.polyswarm_api.submit(artifact, artifact_type="url")
                result = self.polyswarm_api.wait_for(instance)

                if result.failed:
                    return demisto.results("Error submitting URL.")

                # iterate for getting positives and total_scan number
                for assertion in result.assertions:
                    if assertion.verdict:
                        positives += 1
                    total_scans += 1

                polyscore = result.polyscore

            except Exception as err:
                return_error("{ERROR_ENDPOINT}{err}".format(ERROR_ENDPOINT=ERROR_ENDPOINT, err=err))

            if artifact_type == "ip":
                object_name = "IP"
                dbot_score_type = DBotScoreType.IP
            elif artifact_type == "url":
                object_name = "URL"
                dbot_score_type = DBotScoreType.URL
            elif artifact_type == "domain":
                object_name = "Domain"
                dbot_score_type = DBotScoreType.DOMAIN
            else:
                dbot_score_type = ""
                object_name = ""
                demisto.debug(f" {artifact_type=} -> {dbot_score_type=} {object_name=}")

            dbot_score = Common.DBotScore(
                indicator=artifact,
                indicator_type=dbot_score_type,
                integration_name="PolySwarm",
                score=self.get_score(polyscore),
                reliability=demisto.params().get("integrationReliability"),
            )

            indicator = None
            if artifact_type == "ip":
                indicator = Common.IP(ip=artifact, dbot_score=dbot_score)
            elif artifact_type == "url":
                indicator = Common.URL(url=artifact, dbot_score=dbot_score)  # type: ignore
            elif artifact_type == "domain":
                indicator = Common.Domain(domain=artifact, dbot_score=dbot_score)  # type: ignore

            results = self._get_results(object_name, title, total_scans, positives, result.permalink, artifact, indicator)
            command_results.append(results)

        return command_results

    def get_report(self, hashes: list) -> object:
        """
        UUID is equal to Hash.
        """
        title = "PolySwarm Report for UUID: %s" % hashes

        demisto.debug(f"[get_report] {title}")

        return self.file_reputation(hashes)


def main():
    """EXECUTION"""
    LOG(f"command is {demisto.command()}")
    try:
        polyswarm = PolyswarmConnector()

        command = demisto.command()
        param = demisto.args()

        if command == "test-module":
            if polyswarm.test_connectivity():
                return_results("ok")
            else:
                return_error("Connection Failed")
        elif command == "file":
            return_results(polyswarm.file_reputation(param["hash"]))
        elif command == "get-file":
            return_results(polyswarm.get_file(param["hash"]))
        elif command == "file-scan":
            return_results(polyswarm.detonate_file(param["entryID"]))
        elif command == "file-rescan":
            return_results(polyswarm.rescan_file(param["hash"]))
        elif command == "url":
            return_results(polyswarm.url_reputation(param, "url"))
        elif command == "url-scan":
            return_results(polyswarm.url_reputation(param, "url"))
        elif command == "ip":
            return_results(polyswarm.url_reputation(param, "ip"))
        elif command == "domain":
            return_results(polyswarm.url_reputation(param, "domain"))
        elif command == "polyswarm-get-report":
            return_results(polyswarm.get_report(param["scan_uuid"]))

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
