import json
import sys
from collections import deque
from copy import copy
from json import JSONDecodeError
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc

import demistomock as demisto  # noqa: F401
import uvicorn
from CommonServerPython import *  # noqa: F401
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name="Authorization")


async def parse_incidents(request: Request) -> list[dict]:
    json_body = await request.json()
    demisto.debug(f"received body {sys.getsizeof(json_body)=}")
    incidents = json_body if isinstance(json_body, list) else [json_body]
    demisto.debug(f"received create incidents request of length {len(incidents)}")
    for incident in incidents:
        raw_json = incident.get("rawJson") or incident.get("raw_json") or copy(incident)
        if not incident.get("rawJson"):
            incident.pop("raw_json", None)
            incident["rawJson"] = raw_json
    return incidents


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
        headers = scope.get("headers", [])
        user_agent_header = list(filter(lambda header: header[0].decode() == "user-agent", headers))
        user_agent = ""
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):
        recordcopy = copy(record)
        scope = recordcopy.__dict__["scope"]
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({"user_agent": user_agent})
        return super().formatMessage(recordcopy)


@app.post("/")
async def handle_post(
    request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth), token: APIKey = Depends(token_auth)
):
    demisto.debug("generic webhook handling request")
    try:
        incidents = await parse_incidents(request)
    except JSONDecodeError as e:
        demisto.error(f"could not decode request {e}")
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST, content="Request, and rawJson field if exists must be in JSON format"
        )
    header_name = None
    request_headers = dict(request.headers)

    credentials_param = demisto.params().get("credentials")

    if credentials_param and (username := credentials_param.get("identifier")):
        password = credentials_param.get("password", "")
        auth_failed = False
        if username.startswith("_header"):
            header_name = username.split(":")[1]
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (
            not (compare_digest(credentials.username, username) and compare_digest(credentials.password, password))
        ):
            auth_failed = True
        if auth_failed:
            secret_header = (header_name or "Authorization").lower()
            if secret_header in request_headers:
                request_headers[secret_header] = "***"
            demisto.debug(f"Authorization failed - request headers {request_headers}")
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Authorization failed.")

    secret_header = (header_name or "Authorization").lower()
    request_headers.pop(secret_header, None)

    for incident in incidents:
        incident.get("rawJson", {})["headers"] = request_headers
        demisto.debug(f"{incident=}")

    incidents = [
        {
            "name": incident.get("name") or "Generic webhook triggered incident",
            "type": incident.get("type") or demisto.params().get("incidentType"),
            "occurred": incident.get("occurred"),
            "rawJSON": json.dumps(incident.get("rawJson")),
        }
        for incident in incidents
    ]

    demisto.debug("creating incidents")
    return_incidents = demisto.createIncidents(incidents)
    demisto.debug("created incidents")
    if demisto.params().get("store_samples"):
        try:
            sample_events_to_store.extend(incidents)
            demisto.debug(f"old events {len(sample_events_to_store)=}")
            integration_context = get_integration_context()
            sample_events = deque(json.loads(integration_context.get("sample_events", "[]")), maxlen=20)
            sample_events += sample_events_to_store
            demisto.debug(f"new events {len(sample_events_to_store)=}")
            integration_context["sample_events"] = list(sample_events)
            set_to_integration_context_with_retries(integration_context)
            demisto.debug("finished setting sample events")
        except Exception as e:
            demisto.error(f"Failed storing sample events - {e}")

    return return_incidents


def get_assets(offset):
    d =  {"0": {
    "meta": {
        "query_time": 3.014921457,
        "pagination": {
            "offset": 0,
            "limit": 100,
            "total": 3
        },
        "powered_by": "cs.cwppcontainersecurityapi",
        "trace_id": "ea25a2dd9ceb45eeb62d6c8780ca1ef9"
    },
    "resources": [
        {
            "severity": "Critical",
            "first_seen_timestamp": "2025-11-26T00:18:23Z",
            "last_seen_timestamp": "2025-12-03T13:23:16Z",
            "detection_name": "PotentialKernelTampering",
            "detection_event_simple_name": "BPFCommandIssued",
            "detection_description": "The eBPF feature has been invoked from within a container. This is a highly unusual activity from within the container and can be used to load a kernel root kit or manipulate kernel behavior or settings effecting the entire host system where the container is running.",
            "containers_impacted_count": "182",
            "containers_impacted_ids": [
                "5cba58e5c1aca0ff64a98fede61324baf64d5586e20b88b7e8e56e5b96e1dd6c",
                "9005b4f27ec61f4dc213020419a73be7efc8b307566f3d720024770cee6060b8",
                "412ff09a3a2c0d53ae35bdd541e04b4418c78bba1df07e4526cade3cd0639f96",
                "4156ea043a6ea3c43b85dc9c7e45886a197394dfc50cb3ae1de218fed1899434",
                "0a1d54d9d7b379308827c7d314be3065f871044e0f52ada489488c32ce73193f",
                "d20393cd6768196bbd129e9823ecee84c2f669dca5014f758b5f3ab9ecd48727",
                "3fe1c0874c37da2851bed74bc54bb5f4a30d24f28a3bab7679c3e51e376c3b3d",
                "e0370b87ba1856c22f7d1f929000e9d2d95e3dfaf5cd39d98939b04076e6371e",
                "fa6e996e00030a4d64525b3c09f8ad3bcb0f741fd06eb1d1d6b6af2a3a6b0325",
                "f7773c924fc6c6c597a25cfc8097a5c9717c0f5715b8fe3cf645e4230e02a28b",
                "ea2804243116c8bf8e6c53f41b802d8fb5887b52e703d6d71be069d35609f361",
                "0a44cd5ea40904edce7f582b7d55f1e609dc2f905e9e7f35c9f786253568de5e",
                "511ffaf8a9ff61187a87faab22d914242d57dbae54159b1ebd135fc1352053e1",
                "3a68d288a11aa302987da675dff2fc13cad0a4c9bd8132934d6ee8a013c097fc",
                "4e113c193f041aaa73a5d200b5ad6ca5650d160ce42adb42e8b960c16818f7ea",
                "94af9e31f00a1d30fa606f7b92510274b863317d5f40ebf649df50e79e163b38",
                "87fddc091f70dac3a730d618354799805afc4f2c154b53888e771d463f78c23f",
                "29f1357b87efd14ebdb3f73055908c7647f2f7684b235fd947db2aa8786b3887",
                "7a56c5900f5456f7cc5ff9f4a4c133bf9731b012dc582bbc4ec7151a50f26b25",
                "52c11fa40af70831f228a4ca030a6da4793d860f3f3e9672e4809bf717257333",
                "7eb0d0f9b9a5402ad6a2b6239aa81c165da97e9543e17f6ef560afafa27fb811",
                "5871f8036881bdee1c1e4ce3636f5f8183d696bff4c939d266dbea34bc5daf3d",
                "ea98787a05aee3f39e7aec5a11af7144f6bb264b25a2d3000a4c2c749e4f44d4",
                "f07d24937a7443e9eb23d9afc68e8332c3d4c10c6517d869f143cff2aa528f9d",
                "eca636f9667ab2ad372a7996dda9ffa0d4f1a05af3557183b10f51e7c8c60e31",
                "405d4291346d3083bb361b24bce64764cd65db32d51f938c15ae1239c0e35d5b",
                "8f42214a80762cefad24210090b480ce3194bb106756097224667e45e37cb311",
                "f8e08c56d77a31cc096a901754b6ae9fc509119c4ce5eb0e6126debedfe7b1dd",
                "f19da149abf7b48d1aacd74ea5a0c3123ed543fd822ccfc7cacda86c744f35aa",
                "d5679ac6f6daf115678b42d96043494c5b05e2f389d15877ffbeb0dcc1a22ab1",
                "52d3ca2fbc39412d68eaf52f3c502b7c25f8fce9eded0a09d370c01ff9e93eb4",
                "ae8c672993c42ba04a5712518ff2a4428db81e29bc7490c30c23f7e6b58a84a5",
                "f2210a089ef28edd33abc3a3edefb05ac5cafe6d3c575cd0a997aec3958ea537",
                "9c0654ced711854cff40fd7b1641748e25f90068d431d91cf875d11f10bb7f88",
                "3abf5900e863f4f86580d3513f8c6955ba8e3d1d66cbf2b1899c337462835c2e",
                "477045a3542e7982fc009c8ad2f459e48b449fe315112646b44c60b2c1fd6901",
                "4d57a51b55d1562324e0a289a0939bab7bc71c7db6ceb6af0928a00f304d11c1",
                "f789bcb0a19fa66648635eef76a42b6c55f4d77b329ee9d1330ad69983848ae1",
                "ae6c2dac182cb14cf8507483ecce13eb7b0317c5d469fc5f45d5f9991dbcf046",
                "2c2c21955b7fdd0476a3ad59fefd470f4c42842cb3fccc203b7b506ed630443d",
                "a7d9825ec395146b07b71bda403c9f53b64c9582f979f54787c984b3b03ea2e8",
                "e181b73d5da397dc642488734917d99f7bd61bd49878badccee85236f7c2f74d",
                "647b4eb39f48a1884bf23949c96484d51cf0e0d71b161d1cb5d41894dacb1ad2",
                "a136e56267a9c167366f2abb29d9874f8d9ad2a0f0153f1f57a5cf0badc49432",
                "f3599de96353ee00ee0f928c71e3c5d2c2f06e98e91d4d9d782ce58e86d5f7f4",
                "0ceb729abb9ecdb9975b0f8b8e8bfdbdfc4acf93ada780ffffd513d12315540c",
                "9af83aa73e1223369e4b23ecf6cefa6dbd10bd52330d17ff51d3ba8cb297d305",
                "1487fb96c056cf20ccef116295a131b6cf16bd3c6018fc56d6eb7a7aeb5309f6",
                "d093e56f8b32d95b56ef21503e20d9cd8cb7242f91ee29638f864bd85a9bcea9",
                "ac29e3f7d0e47deb756ad72dae9f3a983cf6af480502bc317d89460a1a1d0143",
                "8e99cff1163b8bc6842445d6b012166d0e0dfb3ea82b444e0ad2ae88ecb9dc60",
                "707a78ab338822372021f92347b95be31c0923069910680bd29b17a5a321cd17",
                "ee4073af2a6a141c3a4b478fdfcb2b0f68bd2d45ab5778a52048c566af42e9c6",
                "b5fce95c4ac43dd75fabfa23da1305bfafd521ee6ff99caf2151954705aa03ad",
                "453f9a24ba0d21930f7fef2b02bf4a820f03c5f360a83d0a7f4a906b00180592",
                "a66da04464f8c038ee047d1e973843181919cb530a5620bfb9d5db6ef92ba7b5",
                "d0e3276f43b6beb15311a1d48eddd631c0622ce89904bed65c5381ef6db034d2",
                "ab883567724174b62b5e14b686d8612877a30f5eec27e65eeabb78fc151de0d8",
                "c1f67a0de672cd9752e81fea9ba7d321b454f1480ef0bb505762aae8b15520ca",
                "d858d6b4d591404bbe0cba2451eea23626468f8ea41f3ef77753cc162902687c",
                "5cfc853082e12d6a67cf934ba58c6222eb8c9ffb7dd68d21613042494b51d9cd",
                "99bf6c75b0d548e492bd6bb0f0d6f629308d6ec81d3fb59c947988e497ea26a2",
                "2fc6d5c4dac109a5f275b95903aebcb62b71d47df0c0488e06ecaa2127d3ed38",
                "d97030d0bd2d4e85d73ac2f79ff49508f08804b7d3cacbb3266b8d054a84f8d0",
                "c4298ae604ba67da4ce4bf9a3d84e6b0ce97fc751f737ea40a02e77a9a79b4bd",
                "75a8f079e3680e54aa1082f51a6207924cda47eb058be289bde71c53c4654b44",
                "097b58ad955e343945c5702be2af84d92bc0a397d95c6f0ab7574f9262b9f561",
                "c2e6829255537e88fe6e8303d072a69fbbdc8070fd80ce69961931aa6c99becb",
                "71b74b1a7b80d3a5b5d13ab4783c1962ab6de8b2e5b4dd54e8ee2a57707f62b7",
                "0193798cb370f90aa5f754491e75c871e1fc5c6bd4aafaf20029b457ffb195ba",
                "a0cd2cc7f5b88e1e9cf10630a5b6cd49a1bd3243dd18ad0114349da305da6449",
                "6af158d1d2548737a89835180714d333cbebd6d38312de4f83bd9197295e2931",
                "5f90b02c2ec8241a56426c8881aa41b956cc8840acbafa46a6e5c7bac0a676bc",
                "e532fe610c273a3b0c07d1e1d126de0f71a105dd9951653b199bb7b26b63001c",
                "e493f8e3e781c523089c6a629de12db66bb8548b33121cb02af64fc42c42ea1a",
                "9bece1e4b52d2091b98946b17e7298ac9038f6554f0c9a457208f20985bea637",
                "fd9d8a37998a4b3908b56d6acc53a4f20e64740eaa922ec0da79a0f21255ee09",
                "1f31f18ced5113beb528d04d82e0de0b9c561b47c7042bd4fbdfa5d3206e5c3b",
                "46279890ae2952e9862451f2f1a27afbc3daa9d220508629d98d07b843194a80",
                "c6c86d45037dff2623456fee31efca9ed04b9d60c6dc45898f17d668e4adb3de",
                "abe8adfd51bcec54d19f9df72605cbc643abf2bcfaecc99fa49e831c2f2762d2",
                "aa4ec754f1d2629f729c367f17ede8db718d4693b87a00554e05ecb8af27e609",
                "8d250bf5ee466414af0d1a5a1f152acee9290e46c0ebfede936630e3779236c9",
                "8b9fd27c5117fcd09984e2e2d43762401cb55d4778de75511eb3bc0679cda857",
                "65f6ec81763b357d78e164ca095899fc08b3f9569e66a94e6484ac3b0f7a9133",
                "ce11f0f79b612ea04d024f641e3c573a1782a29b2176bb2e5d6b742437cfa702",
                "173cd8d5f9cf78ea12458346d1c45b9ab6e0a673118ce822ecfa2f277b3b5bd3",
                "f88c8738e506b874ab8d121c10be1538fb60c1b6bb12760d431b6bf0a7f1633e",
                "1a8f6c0d4c1d22243c4975b2af612d6684c803cac19ef1a1b7d99376ed8ecd0f",
                "88f169abdf532e8dd539eb51bc0645d2178d6c83d298b858a8c45b233f474559",
                "4343517a301eaa375aeb046a305ea575aee42287ab0c6a4fbe6a4d8d8010266e",
                "7d26b668dadd444155d7591248e0fb64ed52fdf455071eb69c55ac3b1d725191",
                "94f60154dda9c5507c3754e3ee0695208a43f1378ed4566bf6ad5f5e4e3f1cea",
                "ea3c648dfe23ae865d05b3fc46b54cdb2b2002a1827500ec8a458e3d50f240a4",
                "23709767b0521afb11b8042203bf30719e31644ce96659754dd730c9e046b2b2",
                "f851eb328a6e324e4e6740e2fb85e1f3ce2c420ae386c5ae9c05b902e41b6ad2",
                "be92b72b65cb65e8c0a27e5e26d4a7a6c13664b10f5fd1070d714df2859538f4",
                "b385f73e19068f74fc2856eae4e55bbd3bc890a331c8a06d34bb2603bbb67ab7",
                "02da5de4f5c9d4e22bd48c33acc5dce460305bb3115cb3c154f08030669e6d45",
                "d7c47cb5c5bd3477e22bed4c45da8412ffefc69628f6e0fbe2249da9ced8c428",
                "3a9d097e494d10dfd927e8d80f3aeacac80be6f1425b1775ffce22f140196725",
                "d08a35affefff785c90bb2a8263205929f6dc30d337d4fa90f556f9c9d9c9266",
                "bb1728a2bc19530b1d861b8f1a92c91491166a7578566a0116cc5a7e69952a12",
                "be51bb8b3a9507c8b61a0b76a557aae4de6cccc951544314c7300c766d949150",
                "41ba69fdbababcad2cb17709db51f4d3fb1f4dd285e82fc014ffd120935ccbe0",
                "9062ec3a7d4db4da50fb94821a8889403bf5c73de5c5a7eef705e79e810dc357",
                "998c8b5072dbdc312572a5bc8e2013092a1a58996701cf3ab2ccb46fe5d2038c",
                "0b017930f84885267bdbff961be4e3aed0631a6db1b2bc882367e5d6d78bedc5",
                "c661f90b2708d3e09826b02f9879d8b0dce76f864e9f44a97cc385ad920fab1f",
                "bd304c5c3bc416ac79f53ff79ac1125b2dfe3f912a4b0fcfc1a905d9b49c3a7b",
                "12d2acaa2903c041a14192ab103f09dda1fd2240d9adff479467874ed35ab27e",
                "801bc6676ae7448b4cbe136cface5bfc1c5b480322d333dd7967e9c49a3a1078",
                "76704eb508b68d74c56930884f4b42b28fd0be30f35006f7bbec04a738d7b30f",
                "a7afb8c6a625065e1d5aee9ca6f295e55fce0bb655f682213f118bed1e23c9c7",
                "792d63a5db644c7be8ed6866236ba5d8bd6ee2aeb855bf8b5672595f46fb5b17",
                "e6d74d2950a96be4e0306ac9bb720e55fff9e8014eebf1b41f41150b75523d92",
                "cd84276ee38d78a70cb8b95565e97a034b4f66f470cb118d96890fddebe2b91e",
                "5dc6f308e6944b25a4e94264cf1b6804c5170a30bf518f94aaa519bb5e148dcd",
                "62562ba7ff74aaa0216a73a3cbb59693b8b70c35f69f940716bcfd68baf97ea9",
                "c4981622cb49cbf6359a61b44967ace344b8a74dd32aa76929241d691183ead2",
                "e5803aa493325030a9245d8ef69dbed60dbcab20c73db5eca9a2ab29c4a3427e",
                "02748d05c5c7644a4f00782e3656e348d3eda555f46b262473a3ea85cd72a6c9",
                "0ea443cf54c9e5a0f1151ac8ffa6253a1ed6d591ca9277564aa43fe25cb46a63",
                "7b4c3dd2c98c00bded475f3e5b3bb0f727cd4beb341ef5444d97e26dc8ab21aa",
                "a3214198f73d70f17d2975c39ef8c898b3ec09db6c40444ecf72611ab9653a66",
                "8994213c84bf084f58ab7a3429fbd1aa9958501af65d38e674b33ee4a46e089c",
                "6d48e49d55243f1758d59803be0fe9eef0322b3e5cf1366dc699b20498fc571c",
                "cdc5b6501d955d346b45b4c4b9e2dd301f90ff68e4c83fe313ee95bcfb9d5987",
                "dec4fb08fa0f4fa3541edeebf8c534fd6852a57fa6393c15dad29e0912560356",
                "92730e5bc33294852ae353c8152a0cc5950d6c8092504305634803edca20e335",
                "dac46fee09c745bb9f673fba13da4dec2fe8614cb3733b4e20ea35b6d6976b72",
                "574f92ca83ff514edcdd723bdbcaf1c72117a8ff517ad4250a88d826099763de",
                "3e7b523d14ac5b45933f7f9e6c0c208dc249ecc707b3024a243796c6b35aec84",
                "970566ae05380816f8443eef9fb893894aeeb2c0f308154a68e712ce6ec96567",
                "245d18241034bb7bb6a91565d2fe9dad7bbc7a468c65c7b87614ccbc2b6fa539",
                "c0efe8c38762e82d6c9b7288c8dbe1b1c8011d0a061cc73c903bd7224530ae57",
                "10e6345b74daaef89b721252ab51d48937a1dba5de07f85107597158c0d4ffe6",
                "cb27f350766ce1f20cb38c5a09e6f56c3bae92a70487e3897608635961b26f5b",
                "9795fe63e05fe2f3c483de5f3826eff6efd1df00ad68243499cb0661a4013034",
                "f887f52a33cf3ebf3f123b39b30ae49cef709f0f62030132367661ebc02b1da7",
                "9d236ddf37a44ea7337a04441323302a581354beaa7059e9ba3ea076eeb735a7",
                "3a67925bbcb27004710770b22737f8347578eb555acf6dffe80e9c1550b5f88d",
                "a1c48e91fb740a8309ddbbc6efe5ffb876c1b2ad0facd893f13012deab3130ec",
                "396bc6ec90f95979584caf19a6b48f8b69fa4dcddd9a34e4741544ae5bae34dd",
                "57e39d38f9315474b7885e8d0aacc515af9c852a77e3e8d3b690c6e223cf6738",
                "cd8b0ce0a3b0484a923bc38e532b03f21170d3ecaf5e000afc5b7da094c82b9b",
                "71d210fbda6023e67d1abf00027034e62890d7d7c9aa059e15d8087b4ea7b44e",
                "1e3b540afc94b94f605a3f4a986ec38d612991cdb6151aacc4cf33112284256d",
                "c20abed152be23109f393635031887c3defff8c2acbd183a8d21d9c10ea8600a",
                "1049d3b9d18e1c4dcc4a5a5f158d2aab1c3f1347cca0d4d6e223e4a9c11d9ec9",
                "4b267ff560d98bb4adc2f1b393f4ce9aa583ed47c6e185d9626f53c354f57a31",
                "e8894924486aac8bdf982d0babd9f6f538036874280b0a51f80b77bcd7de4312",
                "303db0e9f3a86dac2aca86e046e44186615ba13e0629cba884f5115860d9511c",
                "22fb7f68be8344398357639aac768f19200cbe46cdb78bead4887c8865033c0f",
                "811547e4dc56214baabd8e179c522685773c761e42a03c997b77b42914538ca6",
                "daa45d2a0bdb0c97cafd47d67b2b76f3ad19d031471e3406c91972ea786f0653",
                "9f658cbfcc5617a8b2352599a50c85c3d162a8dc52745a06567ca26a7d913350",
                "83a3cd13ab4f1cea5b35328c9e5edee30189c045e3237e5febde878fccdd693f",
                "35b74e8e0bbbf549917a4b690a9813cf5ae2f105eeecef62e5e6ff7439228fd1",
                "9d231ac02e29c52eb5596c84fef7e82d84635c2b0e3aa633a7bf1ee0917b2490",
                "b04bc681d182742178b4f63ec75f75f5eef73495e7d7985c099e8af4ce866158",
                "5da742d6d98dffc53757cfdd00c7e21a3843f4f927389fed3014d0cf317ddc1b",
                "7457ca3ff2786f005f786347675fc07536211d38d17ef8188c2969dbb9f11eed",
                "825dd966ad61e27f422b86ac690cf3f502bd0d83ffc6dac1b71f3be144a63eff",
                "acc8b71c262a5d353ffe94948be641fd4a91cab7ac7db28b700fc8d38ab8d518",
                "c427f3caaaa036f162d1bbe8d20add6b12437c5384231c2c4b8f2deb44de6298",
                "c2f503cbb883a5f16e6998b6586f3b808e4f0628aa29fab26ee9f8cede1e38ce",
                "50a9693aecadce068cfb1276641d8786807b03bc6d25bf09d3cb4a830dc9c9d1",
                "3c2d54d06a0a645d2adec49fce683b626999d16b3717349eb51fbfe307aeed95",
                "16bb7ced265c231a7dced0c1e59ead7248b7a4ba3f1ab3fe2e3f722b40d820b3",
                "0c1bedb70f207a632e7e1d01b22b50ec72334077339b3bc055524cf37a3f9923",
                "244a69abbd6ba021e9c396f5574842feb323dc77e944dfc88f922a221d7b9de3",
                "fe0c5c71f82ea82a5ca0960993120128bb64494c5b70a743cc01c7d3f30d7a86",
                "42666221bfed592e4ade4e1104e6c19e9cc72ad1329726384e45ef64746445bf",
                "d81c25f43acb412f30a28aea627181cef39a31a0f28322d30012a83164f73cc3",
                "d2310e7df03e31404e214c9f62e269f86e3aca431d737bb97ea2149a20d52234",
                "36e710f55cc90d8ca9ddf707a0c9ab741f791cc61e8c7d8479a7220a38730403",
                "b467bde6d1689e385072c45092df849774d494f40376638ac3b07df70da38979",
                "3c235f2f90ad4959f7450b341cf7a455e4b31b6b917dc27608bb0d63544a4ee8",
                "687fe5623a315609e0c88bcabe1e670ee6058eb75e297830e18a107e499abfa5",
                "d8aa1bb510988ddd3d73a738431505808ba465efc65a9069937166e92d208368",
                "0af46b1e53a29cf75d3a8e0524bd42482ac84522fc3b7e0d448a1033c551b54d"
            ]
        }
    ],
    "errors": []
}, "1": {
    "meta": {
        "query_time": 3.014921457,
        "pagination": {
            "offset": 1,
            "limit": 100,
            "total": 3
        },
        "powered_by": "cs.cwppcontainersecurityapi",
        "trace_id": "ea25a2dd9ceb45eeb62d6c8780ca1ef9"
    },
    "resources": [
        {
            "severity": "Critical",
            "first_seen_timestamp": "2025-11-26T00:18:23Z",
            "last_seen_timestamp": "2025-12-03T13:23:16Z",
            "detection_name": "PotentialKernelTampering1",
            "detection_event_simple_name": "BPFCommandIssued",
            "detection_description": "The eBPF feature has been invoked from within a container. This is a highly unusual activity from within the container and can be used to load a kernel root kit or manipulate kernel behavior or settings effecting the entire host system where the container is running.",
            "containers_impacted_count": "182",
            "containers_impacted_ids": [
                "5cba58e5c1aca0ff64a98fede61324baf64d5586e20b88b7e8e56e5b96e1dd6c",
                "9005b4f27ec61f4dc213020419a73be7efc8b307566f3d720024770cee6060b8",
                "412ff09a3a2c0d53ae35bdd541e04b4418c78bba1df07e4526cade3cd0639f96",
                "4156ea043a6ea3c43b85dc9c7e45886a197394dfc50cb3ae1de218fed1899434",
                "0a1d54d9d7b379308827c7d314be3065f871044e0f52ada489488c32ce73193f",
                "d20393cd6768196bbd129e9823ecee84c2f669dca5014f758b5f3ab9ecd48727",
                "3fe1c0874c37da2851bed74bc54bb5f4a30d24f28a3bab7679c3e51e376c3b3d",
                "e0370b87ba1856c22f7d1f929000e9d2d95e3dfaf5cd39d98939b04076e6371e",
                "fa6e996e00030a4d64525b3c09f8ad3bcb0f741fd06eb1d1d6b6af2a3a6b0325",
                "f7773c924fc6c6c597a25cfc8097a5c9717c0f5715b8fe3cf645e4230e02a28b",
                "ea2804243116c8bf8e6c53f41b802d8fb5887b52e703d6d71be069d35609f361",
                "0a44cd5ea40904edce7f582b7d55f1e609dc2f905e9e7f35c9f786253568de5e",
                "511ffaf8a9ff61187a87faab22d914242d57dbae54159b1ebd135fc1352053e1",
                "3a68d288a11aa302987da675dff2fc13cad0a4c9bd8132934d6ee8a013c097fc",
                "4e113c193f041aaa73a5d200b5ad6ca5650d160ce42adb42e8b960c16818f7ea",
                "94af9e31f00a1d30fa606f7b92510274b863317d5f40ebf649df50e79e163b38",
                "87fddc091f70dac3a730d618354799805afc4f2c154b53888e771d463f78c23f",
                "29f1357b87efd14ebdb3f73055908c7647f2f7684b235fd947db2aa8786b3887",
                "7a56c5900f5456f7cc5ff9f4a4c133bf9731b012dc582bbc4ec7151a50f26b25",
                "52c11fa40af70831f228a4ca030a6da4793d860f3f3e9672e4809bf717257333",
                "7eb0d0f9b9a5402ad6a2b6239aa81c165da97e9543e17f6ef560afafa27fb811",
                "5871f8036881bdee1c1e4ce3636f5f8183d696bff4c939d266dbea34bc5daf3d",
                "ea98787a05aee3f39e7aec5a11af7144f6bb264b25a2d3000a4c2c749e4f44d4",
                "f07d24937a7443e9eb23d9afc68e8332c3d4c10c6517d869f143cff2aa528f9d",
                "eca636f9667ab2ad372a7996dda9ffa0d4f1a05af3557183b10f51e7c8c60e31",
                "405d4291346d3083bb361b24bce64764cd65db32d51f938c15ae1239c0e35d5b",
                "8f42214a80762cefad24210090b480ce3194bb106756097224667e45e37cb311",
                "f8e08c56d77a31cc096a901754b6ae9fc509119c4ce5eb0e6126debedfe7b1dd",
                "f19da149abf7b48d1aacd74ea5a0c3123ed543fd822ccfc7cacda86c744f35aa",
                "d5679ac6f6daf115678b42d96043494c5b05e2f389d15877ffbeb0dcc1a22ab1",
                "52d3ca2fbc39412d68eaf52f3c502b7c25f8fce9eded0a09d370c01ff9e93eb4",
                "ae8c672993c42ba04a5712518ff2a4428db81e29bc7490c30c23f7e6b58a84a5",
                "f2210a089ef28edd33abc3a3edefb05ac5cafe6d3c575cd0a997aec3958ea537",
                "9c0654ced711854cff40fd7b1641748e25f90068d431d91cf875d11f10bb7f88",
                "3abf5900e863f4f86580d3513f8c6955ba8e3d1d66cbf2b1899c337462835c2e",
                "477045a3542e7982fc009c8ad2f459e48b449fe315112646b44c60b2c1fd6901",
                "4d57a51b55d1562324e0a289a0939bab7bc71c7db6ceb6af0928a00f304d11c1",
                "f789bcb0a19fa66648635eef76a42b6c55f4d77b329ee9d1330ad69983848ae1",
                "ae6c2dac182cb14cf8507483ecce13eb7b0317c5d469fc5f45d5f9991dbcf046",
                "2c2c21955b7fdd0476a3ad59fefd470f4c42842cb3fccc203b7b506ed630443d",
                "a7d9825ec395146b07b71bda403c9f53b64c9582f979f54787c984b3b03ea2e8",
                "e181b73d5da397dc642488734917d99f7bd61bd49878badccee85236f7c2f74d",
                "647b4eb39f48a1884bf23949c96484d51cf0e0d71b161d1cb5d41894dacb1ad2",
                "a136e56267a9c167366f2abb29d9874f8d9ad2a0f0153f1f57a5cf0badc49432",
                "f3599de96353ee00ee0f928c71e3c5d2c2f06e98e91d4d9d782ce58e86d5f7f4",
                "0ceb729abb9ecdb9975b0f8b8e8bfdbdfc4acf93ada780ffffd513d12315540c",
                "9af83aa73e1223369e4b23ecf6cefa6dbd10bd52330d17ff51d3ba8cb297d305",
                "1487fb96c056cf20ccef116295a131b6cf16bd3c6018fc56d6eb7a7aeb5309f6",
                "d093e56f8b32d95b56ef21503e20d9cd8cb7242f91ee29638f864bd85a9bcea9",
                "ac29e3f7d0e47deb756ad72dae9f3a983cf6af480502bc317d89460a1a1d0143",
                "8e99cff1163b8bc6842445d6b012166d0e0dfb3ea82b444e0ad2ae88ecb9dc60",
                "707a78ab338822372021f92347b95be31c0923069910680bd29b17a5a321cd17",
                "ee4073af2a6a141c3a4b478fdfcb2b0f68bd2d45ab5778a52048c566af42e9c6",
                "b5fce95c4ac43dd75fabfa23da1305bfafd521ee6ff99caf2151954705aa03ad",
                "453f9a24ba0d21930f7fef2b02bf4a820f03c5f360a83d0a7f4a906b00180592",
                "a66da04464f8c038ee047d1e973843181919cb530a5620bfb9d5db6ef92ba7b5",
                "d0e3276f43b6beb15311a1d48eddd631c0622ce89904bed65c5381ef6db034d2",
                "ab883567724174b62b5e14b686d8612877a30f5eec27e65eeabb78fc151de0d8",
                "c1f67a0de672cd9752e81fea9ba7d321b454f1480ef0bb505762aae8b15520ca",
                "d858d6b4d591404bbe0cba2451eea23626468f8ea41f3ef77753cc162902687c",
                "5cfc853082e12d6a67cf934ba58c6222eb8c9ffb7dd68d21613042494b51d9cd",
                "99bf6c75b0d548e492bd6bb0f0d6f629308d6ec81d3fb59c947988e497ea26a2",
                "2fc6d5c4dac109a5f275b95903aebcb62b71d47df0c0488e06ecaa2127d3ed38",
                "d97030d0bd2d4e85d73ac2f79ff49508f08804b7d3cacbb3266b8d054a84f8d0",
                "c4298ae604ba67da4ce4bf9a3d84e6b0ce97fc751f737ea40a02e77a9a79b4bd",
                "75a8f079e3680e54aa1082f51a6207924cda47eb058be289bde71c53c4654b44",
                "097b58ad955e343945c5702be2af84d92bc0a397d95c6f0ab7574f9262b9f561",
                "c2e6829255537e88fe6e8303d072a69fbbdc8070fd80ce69961931aa6c99becb",
                "71b74b1a7b80d3a5b5d13ab4783c1962ab6de8b2e5b4dd54e8ee2a57707f62b7",
                "0193798cb370f90aa5f754491e75c871e1fc5c6bd4aafaf20029b457ffb195ba",
                "a0cd2cc7f5b88e1e9cf10630a5b6cd49a1bd3243dd18ad0114349da305da6449",
                "6af158d1d2548737a89835180714d333cbebd6d38312de4f83bd9197295e2931",
                "5f90b02c2ec8241a56426c8881aa41b956cc8840acbafa46a6e5c7bac0a676bc",
                "e532fe610c273a3b0c07d1e1d126de0f71a105dd9951653b199bb7b26b63001c",
                "e493f8e3e781c523089c6a629de12db66bb8548b33121cb02af64fc42c42ea1a",
                "9bece1e4b52d2091b98946b17e7298ac9038f6554f0c9a457208f20985bea637",
                "fd9d8a37998a4b3908b56d6acc53a4f20e64740eaa922ec0da79a0f21255ee09",
                "1f31f18ced5113beb528d04d82e0de0b9c561b47c7042bd4fbdfa5d3206e5c3b",
                "46279890ae2952e9862451f2f1a27afbc3daa9d220508629d98d07b843194a80",
                "c6c86d45037dff2623456fee31efca9ed04b9d60c6dc45898f17d668e4adb3de",
                "abe8adfd51bcec54d19f9df72605cbc643abf2bcfaecc99fa49e831c2f2762d2",
                "aa4ec754f1d2629f729c367f17ede8db718d4693b87a00554e05ecb8af27e609",
                "8d250bf5ee466414af0d1a5a1f152acee9290e46c0ebfede936630e3779236c9",
                "8b9fd27c5117fcd09984e2e2d43762401cb55d4778de75511eb3bc0679cda857",
                "65f6ec81763b357d78e164ca095899fc08b3f9569e66a94e6484ac3b0f7a9133",
                "ce11f0f79b612ea04d024f641e3c573a1782a29b2176bb2e5d6b742437cfa702",
                "173cd8d5f9cf78ea12458346d1c45b9ab6e0a673118ce822ecfa2f277b3b5bd3",
                "f88c8738e506b874ab8d121c10be1538fb60c1b6bb12760d431b6bf0a7f1633e",
                "1a8f6c0d4c1d22243c4975b2af612d6684c803cac19ef1a1b7d99376ed8ecd0f",
                "88f169abdf532e8dd539eb51bc0645d2178d6c83d298b858a8c45b233f474559",
                "4343517a301eaa375aeb046a305ea575aee42287ab0c6a4fbe6a4d8d8010266e",
                "7d26b668dadd444155d7591248e0fb64ed52fdf455071eb69c55ac3b1d725191",
                "94f60154dda9c5507c3754e3ee0695208a43f1378ed4566bf6ad5f5e4e3f1cea",
                "ea3c648dfe23ae865d05b3fc46b54cdb2b2002a1827500ec8a458e3d50f240a4",
                "23709767b0521afb11b8042203bf30719e31644ce96659754dd730c9e046b2b2",
                "f851eb328a6e324e4e6740e2fb85e1f3ce2c420ae386c5ae9c05b902e41b6ad2",
                "be92b72b65cb65e8c0a27e5e26d4a7a6c13664b10f5fd1070d714df2859538f4",
                "b385f73e19068f74fc2856eae4e55bbd3bc890a331c8a06d34bb2603bbb67ab7",
                "02da5de4f5c9d4e22bd48c33acc5dce460305bb3115cb3c154f08030669e6d45",
                "d7c47cb5c5bd3477e22bed4c45da8412ffefc69628f6e0fbe2249da9ced8c428",
                "3a9d097e494d10dfd927e8d80f3aeacac80be6f1425b1775ffce22f140196725",
                "d08a35affefff785c90bb2a8263205929f6dc30d337d4fa90f556f9c9d9c9266",
                "bb1728a2bc19530b1d861b8f1a92c91491166a7578566a0116cc5a7e69952a12",
                "be51bb8b3a9507c8b61a0b76a557aae4de6cccc951544314c7300c766d949150",
                "41ba69fdbababcad2cb17709db51f4d3fb1f4dd285e82fc014ffd120935ccbe0",
                "9062ec3a7d4db4da50fb94821a8889403bf5c73de5c5a7eef705e79e810dc357",
                "998c8b5072dbdc312572a5bc8e2013092a1a58996701cf3ab2ccb46fe5d2038c",
                "0b017930f84885267bdbff961be4e3aed0631a6db1b2bc882367e5d6d78bedc5",
                "c661f90b2708d3e09826b02f9879d8b0dce76f864e9f44a97cc385ad920fab1f",
                "bd304c5c3bc416ac79f53ff79ac1125b2dfe3f912a4b0fcfc1a905d9b49c3a7b",
                "12d2acaa2903c041a14192ab103f09dda1fd2240d9adff479467874ed35ab27e",
                "801bc6676ae7448b4cbe136cface5bfc1c5b480322d333dd7967e9c49a3a1078",
                "76704eb508b68d74c56930884f4b42b28fd0be30f35006f7bbec04a738d7b30f",
                "a7afb8c6a625065e1d5aee9ca6f295e55fce0bb655f682213f118bed1e23c9c7",
                "792d63a5db644c7be8ed6866236ba5d8bd6ee2aeb855bf8b5672595f46fb5b17",
                "e6d74d2950a96be4e0306ac9bb720e55fff9e8014eebf1b41f41150b75523d92",
                "cd84276ee38d78a70cb8b95565e97a034b4f66f470cb118d96890fddebe2b91e",
                "5dc6f308e6944b25a4e94264cf1b6804c5170a30bf518f94aaa519bb5e148dcd",
                "62562ba7ff74aaa0216a73a3cbb59693b8b70c35f69f940716bcfd68baf97ea9",
                "c4981622cb49cbf6359a61b44967ace344b8a74dd32aa76929241d691183ead2",
                "e5803aa493325030a9245d8ef69dbed60dbcab20c73db5eca9a2ab29c4a3427e",
                "02748d05c5c7644a4f00782e3656e348d3eda555f46b262473a3ea85cd72a6c9",
                "0ea443cf54c9e5a0f1151ac8ffa6253a1ed6d591ca9277564aa43fe25cb46a63",
                "7b4c3dd2c98c00bded475f3e5b3bb0f727cd4beb341ef5444d97e26dc8ab21aa",
                "a3214198f73d70f17d2975c39ef8c898b3ec09db6c40444ecf72611ab9653a66",
                "8994213c84bf084f58ab7a3429fbd1aa9958501af65d38e674b33ee4a46e089c",
                "6d48e49d55243f1758d59803be0fe9eef0322b3e5cf1366dc699b20498fc571c",
                "cdc5b6501d955d346b45b4c4b9e2dd301f90ff68e4c83fe313ee95bcfb9d5987",
                "dec4fb08fa0f4fa3541edeebf8c534fd6852a57fa6393c15dad29e0912560356",
                "92730e5bc33294852ae353c8152a0cc5950d6c8092504305634803edca20e335",
                "dac46fee09c745bb9f673fba13da4dec2fe8614cb3733b4e20ea35b6d6976b72",
                "574f92ca83ff514edcdd723bdbcaf1c72117a8ff517ad4250a88d826099763de",
                "3e7b523d14ac5b45933f7f9e6c0c208dc249ecc707b3024a243796c6b35aec84",
                "970566ae05380816f8443eef9fb893894aeeb2c0f308154a68e712ce6ec96567",
                "245d18241034bb7bb6a91565d2fe9dad7bbc7a468c65c7b87614ccbc2b6fa539",
                "c0efe8c38762e82d6c9b7288c8dbe1b1c8011d0a061cc73c903bd7224530ae57",
                "10e6345b74daaef89b721252ab51d48937a1dba5de07f85107597158c0d4ffe6",
                "cb27f350766ce1f20cb38c5a09e6f56c3bae92a70487e3897608635961b26f5b",
                "9795fe63e05fe2f3c483de5f3826eff6efd1df00ad68243499cb0661a4013034",
                "f887f52a33cf3ebf3f123b39b30ae49cef709f0f62030132367661ebc02b1da7",
                "9d236ddf37a44ea7337a04441323302a581354beaa7059e9ba3ea076eeb735a7",
                "3a67925bbcb27004710770b22737f8347578eb555acf6dffe80e9c1550b5f88d",
                "a1c48e91fb740a8309ddbbc6efe5ffb876c1b2ad0facd893f13012deab3130ec",
                "396bc6ec90f95979584caf19a6b48f8b69fa4dcddd9a34e4741544ae5bae34dd",
                "57e39d38f9315474b7885e8d0aacc515af9c852a77e3e8d3b690c6e223cf6738",
                "cd8b0ce0a3b0484a923bc38e532b03f21170d3ecaf5e000afc5b7da094c82b9b",
                "71d210fbda6023e67d1abf00027034e62890d7d7c9aa059e15d8087b4ea7b44e",
                "1e3b540afc94b94f605a3f4a986ec38d612991cdb6151aacc4cf33112284256d",
                "c20abed152be23109f393635031887c3defff8c2acbd183a8d21d9c10ea8600a",
                "1049d3b9d18e1c4dcc4a5a5f158d2aab1c3f1347cca0d4d6e223e4a9c11d9ec9",
                "4b267ff560d98bb4adc2f1b393f4ce9aa583ed47c6e185d9626f53c354f57a31",
                "e8894924486aac8bdf982d0babd9f6f538036874280b0a51f80b77bcd7de4312",
                "303db0e9f3a86dac2aca86e046e44186615ba13e0629cba884f5115860d9511c",
                "22fb7f68be8344398357639aac768f19200cbe46cdb78bead4887c8865033c0f",
                "811547e4dc56214baabd8e179c522685773c761e42a03c997b77b42914538ca6",
                "daa45d2a0bdb0c97cafd47d67b2b76f3ad19d031471e3406c91972ea786f0653",
                "9f658cbfcc5617a8b2352599a50c85c3d162a8dc52745a06567ca26a7d913350",
                "83a3cd13ab4f1cea5b35328c9e5edee30189c045e3237e5febde878fccdd693f",
                "35b74e8e0bbbf549917a4b690a9813cf5ae2f105eeecef62e5e6ff7439228fd1",
                "9d231ac02e29c52eb5596c84fef7e82d84635c2b0e3aa633a7bf1ee0917b2490",
                "b04bc681d182742178b4f63ec75f75f5eef73495e7d7985c099e8af4ce866158",
                "5da742d6d98dffc53757cfdd00c7e21a3843f4f927389fed3014d0cf317ddc1b",
                "7457ca3ff2786f005f786347675fc07536211d38d17ef8188c2969dbb9f11eed",
                "825dd966ad61e27f422b86ac690cf3f502bd0d83ffc6dac1b71f3be144a63eff",
                "acc8b71c262a5d353ffe94948be641fd4a91cab7ac7db28b700fc8d38ab8d518",
                "c427f3caaaa036f162d1bbe8d20add6b12437c5384231c2c4b8f2deb44de6298",
                "c2f503cbb883a5f16e6998b6586f3b808e4f0628aa29fab26ee9f8cede1e38ce",
                "50a9693aecadce068cfb1276641d8786807b03bc6d25bf09d3cb4a830dc9c9d1",
                "3c2d54d06a0a645d2adec49fce683b626999d16b3717349eb51fbfe307aeed95",
                "16bb7ced265c231a7dced0c1e59ead7248b7a4ba3f1ab3fe2e3f722b40d820b3",
                "0c1bedb70f207a632e7e1d01b22b50ec72334077339b3bc055524cf37a3f9923",
                "244a69abbd6ba021e9c396f5574842feb323dc77e944dfc88f922a221d7b9de3",
                "fe0c5c71f82ea82a5ca0960993120128bb64494c5b70a743cc01c7d3f30d7a86",
                "42666221bfed592e4ade4e1104e6c19e9cc72ad1329726384e45ef64746445bf",
                "d81c25f43acb412f30a28aea627181cef39a31a0f28322d30012a83164f73cc3",
                "d2310e7df03e31404e214c9f62e269f86e3aca431d737bb97ea2149a20d52234",
                "36e710f55cc90d8ca9ddf707a0c9ab741f791cc61e8c7d8479a7220a38730403",
                "b467bde6d1689e385072c45092df849774d494f40376638ac3b07df70da38979",
                "3c235f2f90ad4959f7450b341cf7a455e4b31b6b917dc27608bb0d63544a4ee8",
                "687fe5623a315609e0c88bcabe1e670ee6058eb75e297830e18a107e499abfa5",
                "d8aa1bb510988ddd3d73a738431505808ba465efc65a9069937166e92d208368",
                "0af46b1e53a29cf75d3a8e0524bd42482ac84522fc3b7e0d448a1033c551b54d"
            ]
        }
    ],
    "errors": []
}, "2": {
    "meta": {
        "query_time": 3.014921457,
        "pagination": {
            "offset": 2,
            "limit": 100,
            "total": 3
        },
        "powered_by": "cs.cwppcontainersecurityapi",
        "trace_id": "ea25a2dd9ceb45eeb62d6c8780ca1ef9"
    },
    "resources": [
        {
            "severity": "Critical",
            "first_seen_timestamp": "2025-11-26T00:18:23Z",
            "last_seen_timestamp": "2025-12-03T13:23:16Z",
            "detection_name": "PotentialKernelTampering2",
            "detection_event_simple_name": "BPFCommandIssued",
            "detection_description": "The eBPF feature has been invoked from within a container. This is a highly unusual activity from within the container and can be used to load a kernel root kit or manipulate kernel behavior or settings effecting the entire host system where the container is running.",
            "containers_impacted_count": "182",
            "containers_impacted_ids": [
                "5cba58e5c1aca0ff64a98fede61324baf64d5586e20b88b7e8e56e5b96e1dd6c",
                "9005b4f27ec61f4dc213020419a73be7efc8b307566f3d720024770cee6060b8",
                "412ff09a3a2c0d53ae35bdd541e04b4418c78bba1df07e4526cade3cd0639f96",
                "4156ea043a6ea3c43b85dc9c7e45886a197394dfc50cb3ae1de218fed1899434",
                "0a1d54d9d7b379308827c7d314be3065f871044e0f52ada489488c32ce73193f",
                "d20393cd6768196bbd129e9823ecee84c2f669dca5014f758b5f3ab9ecd48727",
                "3fe1c0874c37da2851bed74bc54bb5f4a30d24f28a3bab7679c3e51e376c3b3d",
                "e0370b87ba1856c22f7d1f929000e9d2d95e3dfaf5cd39d98939b04076e6371e",
                "fa6e996e00030a4d64525b3c09f8ad3bcb0f741fd06eb1d1d6b6af2a3a6b0325",
                "f7773c924fc6c6c597a25cfc8097a5c9717c0f5715b8fe3cf645e4230e02a28b",
                "ea2804243116c8bf8e6c53f41b802d8fb5887b52e703d6d71be069d35609f361",
                "0a44cd5ea40904edce7f582b7d55f1e609dc2f905e9e7f35c9f786253568de5e",
                "511ffaf8a9ff61187a87faab22d914242d57dbae54159b1ebd135fc1352053e1",
                "3a68d288a11aa302987da675dff2fc13cad0a4c9bd8132934d6ee8a013c097fc",
                "4e113c193f041aaa73a5d200b5ad6ca5650d160ce42adb42e8b960c16818f7ea",
                "94af9e31f00a1d30fa606f7b92510274b863317d5f40ebf649df50e79e163b38",
                "87fddc091f70dac3a730d618354799805afc4f2c154b53888e771d463f78c23f",
                "29f1357b87efd14ebdb3f73055908c7647f2f7684b235fd947db2aa8786b3887",
                "7a56c5900f5456f7cc5ff9f4a4c133bf9731b012dc582bbc4ec7151a50f26b25",
                "52c11fa40af70831f228a4ca030a6da4793d860f3f3e9672e4809bf717257333",
                "7eb0d0f9b9a5402ad6a2b6239aa81c165da97e9543e17f6ef560afafa27fb811",
                "5871f8036881bdee1c1e4ce3636f5f8183d696bff4c939d266dbea34bc5daf3d",
                "ea98787a05aee3f39e7aec5a11af7144f6bb264b25a2d3000a4c2c749e4f44d4",
                "f07d24937a7443e9eb23d9afc68e8332c3d4c10c6517d869f143cff2aa528f9d",
                "eca636f9667ab2ad372a7996dda9ffa0d4f1a05af3557183b10f51e7c8c60e31",
                "405d4291346d3083bb361b24bce64764cd65db32d51f938c15ae1239c0e35d5b",
                "8f42214a80762cefad24210090b480ce3194bb106756097224667e45e37cb311",
                "f8e08c56d77a31cc096a901754b6ae9fc509119c4ce5eb0e6126debedfe7b1dd",
                "f19da149abf7b48d1aacd74ea5a0c3123ed543fd822ccfc7cacda86c744f35aa",
                "d5679ac6f6daf115678b42d96043494c5b05e2f389d15877ffbeb0dcc1a22ab1",
                "52d3ca2fbc39412d68eaf52f3c502b7c25f8fce9eded0a09d370c01ff9e93eb4",
                "ae8c672993c42ba04a5712518ff2a4428db81e29bc7490c30c23f7e6b58a84a5",
                "f2210a089ef28edd33abc3a3edefb05ac5cafe6d3c575cd0a997aec3958ea537",
                "9c0654ced711854cff40fd7b1641748e25f90068d431d91cf875d11f10bb7f88",
                "3abf5900e863f4f86580d3513f8c6955ba8e3d1d66cbf2b1899c337462835c2e",
                "477045a3542e7982fc009c8ad2f459e48b449fe315112646b44c60b2c1fd6901",
                "4d57a51b55d1562324e0a289a0939bab7bc71c7db6ceb6af0928a00f304d11c1",
                "f789bcb0a19fa66648635eef76a42b6c55f4d77b329ee9d1330ad69983848ae1",
                "ae6c2dac182cb14cf8507483ecce13eb7b0317c5d469fc5f45d5f9991dbcf046",
                "2c2c21955b7fdd0476a3ad59fefd470f4c42842cb3fccc203b7b506ed630443d",
                "a7d9825ec395146b07b71bda403c9f53b64c9582f979f54787c984b3b03ea2e8",
                "e181b73d5da397dc642488734917d99f7bd61bd49878badccee85236f7c2f74d",
                "647b4eb39f48a1884bf23949c96484d51cf0e0d71b161d1cb5d41894dacb1ad2",
                "a136e56267a9c167366f2abb29d9874f8d9ad2a0f0153f1f57a5cf0badc49432",
                "f3599de96353ee00ee0f928c71e3c5d2c2f06e98e91d4d9d782ce58e86d5f7f4",
                "0ceb729abb9ecdb9975b0f8b8e8bfdbdfc4acf93ada780ffffd513d12315540c",
                "9af83aa73e1223369e4b23ecf6cefa6dbd10bd52330d17ff51d3ba8cb297d305",
                "1487fb96c056cf20ccef116295a131b6cf16bd3c6018fc56d6eb7a7aeb5309f6",
                "d093e56f8b32d95b56ef21503e20d9cd8cb7242f91ee29638f864bd85a9bcea9",
                "ac29e3f7d0e47deb756ad72dae9f3a983cf6af480502bc317d89460a1a1d0143",
                "8e99cff1163b8bc6842445d6b012166d0e0dfb3ea82b444e0ad2ae88ecb9dc60",
                "707a78ab338822372021f92347b95be31c0923069910680bd29b17a5a321cd17",
                "ee4073af2a6a141c3a4b478fdfcb2b0f68bd2d45ab5778a52048c566af42e9c6",
                "b5fce95c4ac43dd75fabfa23da1305bfafd521ee6ff99caf2151954705aa03ad",
                "453f9a24ba0d21930f7fef2b02bf4a820f03c5f360a83d0a7f4a906b00180592",
                "a66da04464f8c038ee047d1e973843181919cb530a5620bfb9d5db6ef92ba7b5",
                "d0e3276f43b6beb15311a1d48eddd631c0622ce89904bed65c5381ef6db034d2",
                "ab883567724174b62b5e14b686d8612877a30f5eec27e65eeabb78fc151de0d8",
                "c1f67a0de672cd9752e81fea9ba7d321b454f1480ef0bb505762aae8b15520ca",
                "d858d6b4d591404bbe0cba2451eea23626468f8ea41f3ef77753cc162902687c",
                "5cfc853082e12d6a67cf934ba58c6222eb8c9ffb7dd68d21613042494b51d9cd",
                "99bf6c75b0d548e492bd6bb0f0d6f629308d6ec81d3fb59c947988e497ea26a2",
                "2fc6d5c4dac109a5f275b95903aebcb62b71d47df0c0488e06ecaa2127d3ed38",
                "d97030d0bd2d4e85d73ac2f79ff49508f08804b7d3cacbb3266b8d054a84f8d0",
                "c4298ae604ba67da4ce4bf9a3d84e6b0ce97fc751f737ea40a02e77a9a79b4bd",
                "75a8f079e3680e54aa1082f51a6207924cda47eb058be289bde71c53c4654b44",
                "097b58ad955e343945c5702be2af84d92bc0a397d95c6f0ab7574f9262b9f561",
                "c2e6829255537e88fe6e8303d072a69fbbdc8070fd80ce69961931aa6c99becb",
                "71b74b1a7b80d3a5b5d13ab4783c1962ab6de8b2e5b4dd54e8ee2a57707f62b7",
                "0193798cb370f90aa5f754491e75c871e1fc5c6bd4aafaf20029b457ffb195ba",
                "a0cd2cc7f5b88e1e9cf10630a5b6cd49a1bd3243dd18ad0114349da305da6449",
                "6af158d1d2548737a89835180714d333cbebd6d38312de4f83bd9197295e2931",
                "5f90b02c2ec8241a56426c8881aa41b956cc8840acbafa46a6e5c7bac0a676bc",
                "e532fe610c273a3b0c07d1e1d126de0f71a105dd9951653b199bb7b26b63001c",
                "e493f8e3e781c523089c6a629de12db66bb8548b33121cb02af64fc42c42ea1a",
                "9bece1e4b52d2091b98946b17e7298ac9038f6554f0c9a457208f20985bea637",
                "fd9d8a37998a4b3908b56d6acc53a4f20e64740eaa922ec0da79a0f21255ee09",
                "1f31f18ced5113beb528d04d82e0de0b9c561b47c7042bd4fbdfa5d3206e5c3b",
                "46279890ae2952e9862451f2f1a27afbc3daa9d220508629d98d07b843194a80",
                "c6c86d45037dff2623456fee31efca9ed04b9d60c6dc45898f17d668e4adb3de",
                "abe8adfd51bcec54d19f9df72605cbc643abf2bcfaecc99fa49e831c2f2762d2",
                "aa4ec754f1d2629f729c367f17ede8db718d4693b87a00554e05ecb8af27e609",
                "8d250bf5ee466414af0d1a5a1f152acee9290e46c0ebfede936630e3779236c9",
                "8b9fd27c5117fcd09984e2e2d43762401cb55d4778de75511eb3bc0679cda857",
                "65f6ec81763b357d78e164ca095899fc08b3f9569e66a94e6484ac3b0f7a9133",
                "ce11f0f79b612ea04d024f641e3c573a1782a29b2176bb2e5d6b742437cfa702",
                "173cd8d5f9cf78ea12458346d1c45b9ab6e0a673118ce822ecfa2f277b3b5bd3",
                "f88c8738e506b874ab8d121c10be1538fb60c1b6bb12760d431b6bf0a7f1633e",
                "1a8f6c0d4c1d22243c4975b2af612d6684c803cac19ef1a1b7d99376ed8ecd0f",
                "88f169abdf532e8dd539eb51bc0645d2178d6c83d298b858a8c45b233f474559",
                "4343517a301eaa375aeb046a305ea575aee42287ab0c6a4fbe6a4d8d8010266e",
                "7d26b668dadd444155d7591248e0fb64ed52fdf455071eb69c55ac3b1d725191",
                "94f60154dda9c5507c3754e3ee0695208a43f1378ed4566bf6ad5f5e4e3f1cea",
                "ea3c648dfe23ae865d05b3fc46b54cdb2b2002a1827500ec8a458e3d50f240a4",
                "23709767b0521afb11b8042203bf30719e31644ce96659754dd730c9e046b2b2",
                "f851eb328a6e324e4e6740e2fb85e1f3ce2c420ae386c5ae9c05b902e41b6ad2",
                "be92b72b65cb65e8c0a27e5e26d4a7a6c13664b10f5fd1070d714df2859538f4",
                "b385f73e19068f74fc2856eae4e55bbd3bc890a331c8a06d34bb2603bbb67ab7",
                "02da5de4f5c9d4e22bd48c33acc5dce460305bb3115cb3c154f08030669e6d45",
                "d7c47cb5c5bd3477e22bed4c45da8412ffefc69628f6e0fbe2249da9ced8c428",
                "3a9d097e494d10dfd927e8d80f3aeacac80be6f1425b1775ffce22f140196725",
                "d08a35affefff785c90bb2a8263205929f6dc30d337d4fa90f556f9c9d9c9266",
                "bb1728a2bc19530b1d861b8f1a92c91491166a7578566a0116cc5a7e69952a12",
                "be51bb8b3a9507c8b61a0b76a557aae4de6cccc951544314c7300c766d949150",
                "41ba69fdbababcad2cb17709db51f4d3fb1f4dd285e82fc014ffd120935ccbe0",
                "9062ec3a7d4db4da50fb94821a8889403bf5c73de5c5a7eef705e79e810dc357",
                "998c8b5072dbdc312572a5bc8e2013092a1a58996701cf3ab2ccb46fe5d2038c",
                "0b017930f84885267bdbff961be4e3aed0631a6db1b2bc882367e5d6d78bedc5",
                "c661f90b2708d3e09826b02f9879d8b0dce76f864e9f44a97cc385ad920fab1f",
                "bd304c5c3bc416ac79f53ff79ac1125b2dfe3f912a4b0fcfc1a905d9b49c3a7b",
                "12d2acaa2903c041a14192ab103f09dda1fd2240d9adff479467874ed35ab27e",
                "801bc6676ae7448b4cbe136cface5bfc1c5b480322d333dd7967e9c49a3a1078",
                "76704eb508b68d74c56930884f4b42b28fd0be30f35006f7bbec04a738d7b30f",
                "a7afb8c6a625065e1d5aee9ca6f295e55fce0bb655f682213f118bed1e23c9c7",
                "792d63a5db644c7be8ed6866236ba5d8bd6ee2aeb855bf8b5672595f46fb5b17",
                "e6d74d2950a96be4e0306ac9bb720e55fff9e8014eebf1b41f41150b75523d92",
                "cd84276ee38d78a70cb8b95565e97a034b4f66f470cb118d96890fddebe2b91e",
                "5dc6f308e6944b25a4e94264cf1b6804c5170a30bf518f94aaa519bb5e148dcd",
                "62562ba7ff74aaa0216a73a3cbb59693b8b70c35f69f940716bcfd68baf97ea9",
                "c4981622cb49cbf6359a61b44967ace344b8a74dd32aa76929241d691183ead2",
                "e5803aa493325030a9245d8ef69dbed60dbcab20c73db5eca9a2ab29c4a3427e",
                "02748d05c5c7644a4f00782e3656e348d3eda555f46b262473a3ea85cd72a6c9",
                "0ea443cf54c9e5a0f1151ac8ffa6253a1ed6d591ca9277564aa43fe25cb46a63",
                "7b4c3dd2c98c00bded475f3e5b3bb0f727cd4beb341ef5444d97e26dc8ab21aa",
                "a3214198f73d70f17d2975c39ef8c898b3ec09db6c40444ecf72611ab9653a66",
                "8994213c84bf084f58ab7a3429fbd1aa9958501af65d38e674b33ee4a46e089c",
                "6d48e49d55243f1758d59803be0fe9eef0322b3e5cf1366dc699b20498fc571c",
                "cdc5b6501d955d346b45b4c4b9e2dd301f90ff68e4c83fe313ee95bcfb9d5987",
                "dec4fb08fa0f4fa3541edeebf8c534fd6852a57fa6393c15dad29e0912560356",
                "92730e5bc33294852ae353c8152a0cc5950d6c8092504305634803edca20e335",
                "dac46fee09c745bb9f673fba13da4dec2fe8614cb3733b4e20ea35b6d6976b72",
                "574f92ca83ff514edcdd723bdbcaf1c72117a8ff517ad4250a88d826099763de",
                "3e7b523d14ac5b45933f7f9e6c0c208dc249ecc707b3024a243796c6b35aec84",
                "970566ae05380816f8443eef9fb893894aeeb2c0f308154a68e712ce6ec96567",
                "245d18241034bb7bb6a91565d2fe9dad7bbc7a468c65c7b87614ccbc2b6fa539",
                "c0efe8c38762e82d6c9b7288c8dbe1b1c8011d0a061cc73c903bd7224530ae57",
                "10e6345b74daaef89b721252ab51d48937a1dba5de07f85107597158c0d4ffe6",
                "cb27f350766ce1f20cb38c5a09e6f56c3bae92a70487e3897608635961b26f5b",
                "9795fe63e05fe2f3c483de5f3826eff6efd1df00ad68243499cb0661a4013034",
                "f887f52a33cf3ebf3f123b39b30ae49cef709f0f62030132367661ebc02b1da7",
                "9d236ddf37a44ea7337a04441323302a581354beaa7059e9ba3ea076eeb735a7",
                "3a67925bbcb27004710770b22737f8347578eb555acf6dffe80e9c1550b5f88d",
                "a1c48e91fb740a8309ddbbc6efe5ffb876c1b2ad0facd893f13012deab3130ec",
                "396bc6ec90f95979584caf19a6b48f8b69fa4dcddd9a34e4741544ae5bae34dd",
                "57e39d38f9315474b7885e8d0aacc515af9c852a77e3e8d3b690c6e223cf6738",
                "cd8b0ce0a3b0484a923bc38e532b03f21170d3ecaf5e000afc5b7da094c82b9b",
                "71d210fbda6023e67d1abf00027034e62890d7d7c9aa059e15d8087b4ea7b44e",
                "1e3b540afc94b94f605a3f4a986ec38d612991cdb6151aacc4cf33112284256d",
                "c20abed152be23109f393635031887c3defff8c2acbd183a8d21d9c10ea8600a",
                "1049d3b9d18e1c4dcc4a5a5f158d2aab1c3f1347cca0d4d6e223e4a9c11d9ec9",
                "4b267ff560d98bb4adc2f1b393f4ce9aa583ed47c6e185d9626f53c354f57a31",
                "e8894924486aac8bdf982d0babd9f6f538036874280b0a51f80b77bcd7de4312",
                "303db0e9f3a86dac2aca86e046e44186615ba13e0629cba884f5115860d9511c",
                "22fb7f68be8344398357639aac768f19200cbe46cdb78bead4887c8865033c0f",
                "811547e4dc56214baabd8e179c522685773c761e42a03c997b77b42914538ca6",
                "daa45d2a0bdb0c97cafd47d67b2b76f3ad19d031471e3406c91972ea786f0653",
                "9f658cbfcc5617a8b2352599a50c85c3d162a8dc52745a06567ca26a7d913350",
                "83a3cd13ab4f1cea5b35328c9e5edee30189c045e3237e5febde878fccdd693f",
                "35b74e8e0bbbf549917a4b690a9813cf5ae2f105eeecef62e5e6ff7439228fd1",
                "9d231ac02e29c52eb5596c84fef7e82d84635c2b0e3aa633a7bf1ee0917b2490",
                "b04bc681d182742178b4f63ec75f75f5eef73495e7d7985c099e8af4ce866158",
                "5da742d6d98dffc53757cfdd00c7e21a3843f4f927389fed3014d0cf317ddc1b",
                "7457ca3ff2786f005f786347675fc07536211d38d17ef8188c2969dbb9f11eed",
                "825dd966ad61e27f422b86ac690cf3f502bd0d83ffc6dac1b71f3be144a63eff",
                "acc8b71c262a5d353ffe94948be641fd4a91cab7ac7db28b700fc8d38ab8d518",
                "c427f3caaaa036f162d1bbe8d20add6b12437c5384231c2c4b8f2deb44de6298",
                "c2f503cbb883a5f16e6998b6586f3b808e4f0628aa29fab26ee9f8cede1e38ce",
                "50a9693aecadce068cfb1276641d8786807b03bc6d25bf09d3cb4a830dc9c9d1",
                "3c2d54d06a0a645d2adec49fce683b626999d16b3717349eb51fbfe307aeed95",
                "16bb7ced265c231a7dced0c1e59ead7248b7a4ba3f1ab3fe2e3f722b40d820b3",
                "0c1bedb70f207a632e7e1d01b22b50ec72334077339b3bc055524cf37a3f9923",
                "244a69abbd6ba021e9c396f5574842feb323dc77e944dfc88f922a221d7b9de3",
                "fe0c5c71f82ea82a5ca0960993120128bb64494c5b70a743cc01c7d3f30d7a86",
                "42666221bfed592e4ade4e1104e6c19e9cc72ad1329726384e45ef64746445bf",
                "d81c25f43acb412f30a28aea627181cef39a31a0f28322d30012a83164f73cc3",
                "d2310e7df03e31404e214c9f62e269f86e3aca431d737bb97ea2149a20d52234",
                "36e710f55cc90d8ca9ddf707a0c9ab741f791cc61e8c7d8479a7220a38730403",
                "b467bde6d1689e385072c45092df849774d494f40376638ac3b07df70da38979",
                "3c235f2f90ad4959f7450b341cf7a455e4b31b6b917dc27608bb0d63544a4ee8",
                "687fe5623a315609e0c88bcabe1e670ee6058eb75e297830e18a107e499abfa5",
                "d8aa1bb510988ddd3d73a738431505808ba465efc65a9069937166e92d208368",
                "0af46b1e53a29cf75d3a8e0524bd42482ac84522fc3b7e0d448a1033c551b54d"
            ]
        }
    ],
    "errors": []
}}
    return d[offset]

@app.get('/container-security/combined/container-alerts/v1')
def handle_get_request(offset="0", limit=0):
    """handle a regular get response.
    Args:
    Returns:
        Response:response object.
    """
    asset = get_assets(offset)
    return Response(status_code=status.HTTP_200_OK, content=json.dumps(asset), media_type="application/json")

def setup_credentials():
    if credentials_param := demisto.params().get("credentials"):
        username = credentials_param.get("identifier")
        if username and username.startswith("_header:"):
            header_name = username.split(":")[1]
            demisto.debug(f"Overwriting Authorization parameter with {username}")
            token_auth.model.name = header_name


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get("sample_events", "[]"))
    demisto.incidents(sample_events)


def test_module(params: dict):
    """
    Assigns a temporary port for longRunningPort and returns 'ok'.
    """
    if not params.get("longRunningPort"):
        params["longRunningPort"] = "1111"
    return_results("ok")


def main() -> None:
    params = demisto.params()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            return test_module(params)
        try:
            port = int(params.get("longRunningPort"))
        except ValueError as e:
            raise ValueError(f"Invalid listen port - {e}")
        if demisto.command() == "fetch-incidents":
            fetch_samples()
        elif demisto.command() == "long-running-execution":
            while True:
                certificate = demisto.params().get("certificate", "")
                private_key = demisto.params().get("key", "")

                certificate_path = ""
                private_key_path = ""
                try:
                    ssl_args = {}

                    if certificate and private_key:
                        certificate_file = NamedTemporaryFile(delete=False)
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, "utf-8"))
                        certificate_file.close()
                        ssl_args["ssl_certfile"] = certificate_path

                        private_key_file = NamedTemporaryFile(delete=False)
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, "utf-8"))
                        private_key_file.close()
                        ssl_args["ssl_keyfile"] = private_key_path

                        demisto.debug("Starting HTTPS Server")
                    else:
                        demisto.debug("Starting HTTP Server")

                    integration_logger = IntegrationLogger()
                    integration_logger.buffering = False
                    log_config = dict(uvicorn.config.LOGGING_CONFIG)
                    log_config["handlers"]["default"]["stream"] = integration_logger
                    log_config["handlers"]["access"]["stream"] = integration_logger
                    log_config["formatters"]["access"] = {
                        "()": GenericWebhookAccessFormatter,
                        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"',
                    }
                    setup_credentials()
                    uvicorn.run(app, host="0.0.0.0", port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
                except Exception as e:
                    demisto.error(f"An error occurred in the long running loop: {e!s} - {format_exc()}")
                    demisto.updateModuleHealth(f"An error occurred: {e!s}")
                finally:
                    if certificate_path:
                        os.unlink(certificate_path)
                    if private_key_path:
                        os.unlink(private_key_path)
                    time.sleep(5)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f"Failed to execute {demisto.command()} command. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
