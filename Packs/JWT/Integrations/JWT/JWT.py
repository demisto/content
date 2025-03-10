import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import traceback
from typing import Dict
import jwt
import uuid

# Disable insecure warnings
import urllib3

urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    def request_access_token(self, headers, body):
        response = self._http_request("post", headers=headers, json_data=body)
        return response


""" HELPER FUNCTIONS """


def encode_authentication_token(
    secret_key,
    jti=None,
    iss=None,
    aud=None,
    sub=None,
    scp=None,
    iat=None,
    exp=None,
    nbf=None,
    token_timeout=None,
    additional_claims=None,
    algorithm="HS256",
):
    token_id = str(uuid.uuid4())
    jti = jti or token_id

    token_timeout = token_timeout or "300"
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=int(token_timeout))
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    exp = exp or epoch_timeout
    iat = iat or epoch_time

    claims = {"exp": exp, "iat": iat, "jti": jti}

    if iss:
        claims["iss"] = iss
    if aud:
        claims["aud"] = aud
    if sub:
        claims["sub"] = sub
    if scp:
        claims["iss"] = scp
    if scp:
        claims["nbf"] = nbf
    if additional_claims:
        claims.update(json.loads(additional_claims))

    payload = jwt.encode(claims, secret_key, algorithm=algorithm)

    return jti, payload


""" COMMAND FUNCTIONS """


def test_module():
    return "ok"


def jwt_generate_authentication_payload_command(args, params):
    secret_key = params.get("key")
    jti = args.get("jti") or params.get("jti")
    iss = args.get("iss") or params.get("iss", params["url"])
    aud = args.get("aud") or params.get("aud")
    sub = args.get("sub") or params.get("sub")
    scp = args.get("scp") or params.get("scp")
    iat = args.get("iat") or params.get("iat")
    exp = args.get("exp") or params.get("exp")
    nbf = args.get("nbf") or params.get("nbf")
    algorithm = args.get("algorithm") or params.get("algorithm")
    additional_claims = args.get("additionalClaims") or params.get("additionalClaims")
    token_timeout = args.get("tokenTimeout") or params.get("tokenTimeout")

    jti, payload = encode_authentication_token(
        secret_key=secret_key,
        jti=jti,
        iss=iss,
        aud=aud,
        sub=sub,
        scp=scp,
        iat=iat,
        exp=exp,
        nbf=nbf,
        token_timeout=token_timeout,
        additional_claims=additional_claims,
        algorithm=algorithm,
    )
    result = {"ID": jti, "AuthenticationToken": payload}

    return CommandResults(
        outputs_prefix="JWT.Token",
        outputs_key_field="ID",
        outputs=result,
    )


def jwt_generate_access_token_command(client, args, params):
    secret_key = params.get("key")
    jti = args.get("jti") or params.get("jti")
    iss = args.get("iss") or params.get("iss", params["url"])
    aud = args.get("aud") or params.get("aud")
    sub = args.get("sub") or params.get("sub")
    scp = args.get("scp") or params.get("scp")
    iat = args.get("iat") or params.get("iat")
    exp = args.get("exp") or params.get("exp")
    nbf = args.get("nbf") or params.get("nbf")
    algorithm = args.get("algorithm") or params.get("algorithm")
    additional_claims = args.get("additionalClaims") or params.get("additionalClaims")
    token_timeout = args.get("tokenTimeout") or params.get("tokenTimeout")

    jti, payload = encode_authentication_token(
        secret_key=secret_key,
        jti=jti,
        iss=iss,
        aud=aud,
        sub=sub,
        scp=scp,
        iat=iat,
        exp=exp,
        nbf=nbf,
        token_timeout=token_timeout,
        additional_claims=additional_claims,
        algorithm=algorithm,
    )
    payload = {"auth_token": payload}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    res = client.request_access_token(headers=headers, body=payload)
    access_token = res["access_token"]

    result = {"ID": jti, "AuthenticationToken": payload["auth_token"], "AccessToken": access_token}

    return CommandResults(
        outputs_prefix="JWT.Token",
        outputs_key_field="ID",
        outputs=result,
    )


def jwt_decode_token_command(args):
    token = args.get("token")
    secret = args.get("secret", "nosecret")
    result = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_signature": False})
    return CommandResults(
        outputs_prefix="JWT.DecodedToken",
        outputs_key_field="ID",
        outputs=result,
    )


""" MAIN FUNCTION """


def main():
    base_url = demisto.params().get("url")

    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers: Dict = {}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)
        if demisto.command() == "test-module":
            result = test_module()
            return_results(result)

        elif demisto.command() == "jwt-generate-authentication-payload":
            return_results(jwt_generate_authentication_payload_command(demisto.args(), demisto.params()))
        elif demisto.command() == "jwt-generate-access-token":
            return_results(jwt_generate_access_token_command(client, demisto.args(), demisto.params()))
        elif demisto.command() == "jwt-decode-token":
            return_results(jwt_decode_token_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
