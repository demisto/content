import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

import traceback
import dateparser
from datetime import timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple


# Threshold defining "long expiration". When validity_not_after - validity_not_before is greater than
# this value the certificate will be marked as Long Expiration
# We use 398 days here (See https://blog.mozilla.org/security/2020/07/09/reducing-tls-certificate-lifespans-to-398-days/)
LONG_EXPIRATION_DT = timedelta(days=398)


''' STANDALONE FUNCTION '''


class CertificateValidationTag(Enum):
    EXPIRED = 'EXPIRED'
    NOT_VALID_YET = 'NOT_VALID_YET'
    INVALID_VALIDITY_WINDOW = 'INVALID_VALIDITY_WINDOW'
    LONG_EXPIRATION = 'LONG_EXPIRATION'
    WILDCARD_CERTIFICATE = 'WILDCARD_CERTIFICATE'
    SELF_ISSUED = 'SELF_ISSUED'
    DOMAIN_CONTROL_VALIDATED = 'DOMAIN_CONTROL_VALIDATED'
    SELF_SIGNED = 'SELF_SIGNED'
    INVALID_DISTINGUISHED_NAMES = 'INVALID_DISTINGUISHED_NAMES'


def get_indicator_from_value(indicator_value: str):
    try:
        res = demisto.executeCommand("findIndicators", {'query': f'value:"{indicator_value}" and type:Certificate'})
        indicator = res[0]['Contents'][0]

        return indicator
    except BaseException:
        return None


def indicator_set_validation_checks(ivalue: str, checks: List[CertificateValidationTag]) -> None:
    # we call setIndicator for each check because if you pass the full list to setIndicator at once
    # it will just set the field with the stringified version of the list
    for c in checks:
        demisto.executeCommand('setIndicator', {
            "value": ivalue,
            "type": "Certificate",
            "certificatevalidationchecks": c.value
        })


def certificate_fields_to_context(certindicator_fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pem: Optional[str]
    if (pem := certindicator_fields.get('pem')) is None:
        return None

    result = demisto.executeCommand('CertificateExtract', {'pem': pem})
    if len(result) == 0:
        return None

    context = result[0]

    if (entry_context := context.get('EntryContext')) is None:
        return None

    for k in list(entry_context.keys()):
        if k != Common.Certificate.CONTEXT_PATH:
            entry_context.pop(k)

    demisto.debug(f"{entry_context!r}")
    return entry_context


def dbot_context(value: str, certificate_context: Dict[str, Any]
                 ) -> Tuple[List[CertificateValidationTag], List[str], Dict[str, Any]]:
    comments: List[str] = []
    tags: List[CertificateValidationTag] = []
    some_checks_not_performed: bool = False
    current_score = Common.DBotScore.NONE

    # check for validity over time
    now = dateparser.parse('now Z')
    if now is None:
        raise RuntimeError("Dateparser failed parsing 'now Z'")

    validity_not_after = certificate_context.get('ValidityNotAfter')
    parsed_validity_not_after = None
    if validity_not_after is not None:
        parsed_validity_not_after = dateparser.parse(validity_not_after)

    validity_not_before = certificate_context.get('ValidityNotBefore')
    parsed_validity_not_before = None
    if validity_not_before is not None:
        parsed_validity_not_before = dateparser.parse(validity_not_before)

    if parsed_validity_not_after is None:
        comments.append('ValidityNotAfter not specified, expiration check not performed')
        some_checks_not_performed = True
    elif now > parsed_validity_not_after:
        comments.append(f'{CertificateValidationTag.EXPIRED.value} '
                        f'Certificate expired: {now.strftime("%Y-%m-%dT%H:%M:%S.000Z")} > '
                        f'{validity_not_after}')
        tags.append(CertificateValidationTag.EXPIRED)
        current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    if parsed_validity_not_before is None:
        comments.append('ValidityNotBefore not specified, validation check not performed')
        some_checks_not_performed = True
    elif now < parsed_validity_not_before:
        comments.append(f'{CertificateValidationTag.NOT_VALID_YET.value} '
                        f'Certificate not valid yet: {now.strftime("%Y-%m-%dT%H:%M:%S.000Z")} < '
                        f'{validity_not_before}')
        tags.append(CertificateValidationTag.NOT_VALID_YET)
        current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    # check for blatant issues with validity dates and long expiration
    if parsed_validity_not_after is not None and parsed_validity_not_before is not None:
        if parsed_validity_not_before >= parsed_validity_not_after:
            comments.append(f'{CertificateValidationTag.INVALID_VALIDITY_WINDOW.value} '
                            f'Certificate is invalid: Validity not before {validity_not_before} > '
                            f'Validity not after {validity_not_after}')
            tags.append(CertificateValidationTag.INVALID_VALIDITY_WINDOW)
            current_score = Common.DBotScore.BAD

        elif (parsed_validity_not_after - parsed_validity_not_before) > LONG_EXPIRATION_DT:
            comments.append(
                f'{CertificateValidationTag.LONG_EXPIRATION.value} Certificate has long expiration (> {LONG_EXPIRATION_DT})')
            tags.append(CertificateValidationTag.LONG_EXPIRATION)
            current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    # check for wildcard names
    names = certificate_context.get('Name')
    if names is None:
        comments.append('Name not specified')
        some_checks_not_performed = True
    else:
        wildcard_name = next((n for n in names if n.startswith('*.')), None)
        if wildcard_name is not None:
            comments.append(
                f'{CertificateValidationTag.WILDCARD_CERTIFICATE.value} Certificate contains at least one name with wildcard')
            tags.append(CertificateValidationTag.WILDCARD_CERTIFICATE)
            current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    # check on subject and issuer
    subject_dn = certificate_context.get('SubjectDN')
    if subject_dn is None:
        comments.append('SubjectDN not specified')
        some_checks_not_performed = True

    issuer_dn = certificate_context.get('IssuerDN')
    if issuer_dn is None:
        comments.append('IssuerDN not specified')
        some_checks_not_performed = True

    # self-issued iff subject_dn == issuer_dn
    if subject_dn is not None and issuer_dn is not None and subject_dn == issuer_dn:
        comments.append(f'{CertificateValidationTag.SELF_ISSUED.value} Self-Issued certificate')
        tags.append(CertificateValidationTag.SELF_ISSUED)
        current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    # domain control validated:
    # - if there is only a CN element in the subject DN
    # - if there is a OU=Domain Control Validated in the subject DN
    if subject_dn is not None:
        # replace \, and \+ with the long escaping \2c and \2b
        long_escaped_subject_dn = subject_dn.replace("\\,", "\\2c")
        long_escaped_subject_dn = long_escaped_subject_dn.replace("\\+", "\\2b")

        # we then split RDN (separated by ,) and multi-valued RDN (sep by +)
        rdns = long_escaped_subject_dn.replace('+', ',').split(',')

        # check conditions
        dv: bool = len(rdns) == 1 and rdns[0].startswith('CN=')
        dv = dv or next((rdn for rdn in rdns if rdn.strip() == "OU=Domain Control Validated"), None) is not None

        if dv:
            comments.append(f'{CertificateValidationTag.DOMAIN_CONTROL_VALIDATED.value} Certificate is Domain Control Validated')
            tags.append(CertificateValidationTag.DOMAIN_CONTROL_VALIDATED)
            current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

    # self-signed iff subject key identifier == authority key identifier
    extensions = certificate_context.get('Extension')
    if extensions is None:
        comments.append('No Extensions available, some checks could not be performed')
        some_checks_not_performed = True
    else:
        subject_key_identifier = next((e.get('Value') for e in extensions if e.get('OID') == '2.5.29.14'), None)
        authority_key_identifier = next((e.get('Value') for e in extensions if e.get('OID') == '2.5.29.35'), None)

        subject_key_identifier_digest = None
        authority_key_identifier_ki = None
        if subject_key_identifier is None or (subject_key_identifier_digest := subject_key_identifier.get('Digest')) is None:
            some_checks_not_performed = True
            comments.append('Valid SubjectKeyIdentifier Extension not available, some checks not performed')

        if authority_key_identifier is None or (
                authority_key_identifier_ki := authority_key_identifier.get('KeyIdentifier')) is None:
            some_checks_not_performed = True
            comments.append('Valid AuthorityKeyIdentifier Extension not available, some checks not performed')

        if subject_key_identifier_digest is not None and authority_key_identifier_ki is not None:
            if subject_key_identifier_digest == authority_key_identifier_ki:
                comments.append(f'{CertificateValidationTag.SELF_SIGNED.value} Self-Signed Certificate')
                tags.append(CertificateValidationTag.SELF_SIGNED)
                current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

        elif subject_key_identifier_digest is not None and authority_key_identifier_ki is None:
            if subject_dn is not None and issuer_dn is not None and subject_dn == issuer_dn:
                comments.append(f'{CertificateValidationTag.SELF_SIGNED.value} Self-Signed Certificate')
                tags.append(CertificateValidationTag.SELF_SIGNED)
                current_score = max(current_score, Common.DBotScore.SUSPICIOUS)

        # if self-signed we also check this is self-issued
        if CertificateValidationTag.SELF_SIGNED in tags:
            if subject_dn is not None and issuer_dn is not None and subject_dn != issuer_dn:
                comments.append(f'{CertificateValidationTag.INVALID_DISTINGUISHED_NAMES.value}'
                                ' Self-Signed Certificate with different Issuer DN and Subject DN')
                tags.append(CertificateValidationTag.INVALID_DISTINGUISHED_NAMES)
                current_score = Common.DBotScore.BAD

    if not some_checks_not_performed:
        # if we didn't have to skip any check we can mark the cert as good
        # if the current score is not already higher (worse) than GOOD
        current_score = max(current_score, Common.DBotScore.GOOD)

    return tags, comments, {
        'DBotScore': {
            'Score': current_score,
            'Vendor': 'X509Certificate',
            'Type': 'certificate',
            'Indicator': value
        }
    }


''' COMMAND FUNCTION '''


def certificate_reputation_command(args: Dict[str, Any]) -> Dict[str, Any]:
    input_ = args.get('input')
    if input_ is None:
        raise ValueError("input argument is required")

    update_indicator = argToBoolean(args.get('update_indicator', 'true'))

    indicator = get_indicator_from_value(input_)

    if indicator is None:
        return {
            'Type': entryTypes['note'],
            'HumanReadable': '*No matching indicators*',
            'ReadableContentsFormat': formats['markdown']
        }

    comments: List[str] = []

    indicator_value = indicator.get('value')
    if indicator_value is None:
        raise ValueError("Matching indicator has no value (this should not be possible)")

    standard_context = {}
    if (fields := indicator.get('CustomFields')) is not None:
        if 'pem' not in fields:
            comments.append("*PEM field is empty*")

        elif (certificate_context := certificate_fields_to_context(fields)) is not None:
            standard_context.update(certificate_context)

    if (certificate_stdcontext := standard_context.get(Common.Certificate.CONTEXT_PATH)) is not None:
        demisto.debug(f"{certificate_stdcontext!r}")
        if isinstance(certificate_stdcontext, list):
            certificate_stdcontext = certificate_stdcontext[0] if certificate_stdcontext else {}
        demisto.debug(f"{certificate_stdcontext!r}")
        tags, check_comments, dbot_score = dbot_context(indicator_value, certificate_stdcontext)

    standard_context.update(dbot_score)

    if update_indicator:
        # we use this because it seems that enrichIndicators is ignoring additional context
        # in the output
        indicator_set_validation_checks(indicator_value, tags)

    readable_output = f"Score for {indicator_value} is {standard_context['DBotScore']['Score']}\n"
    readable_output += "## Notes\n"
    readable_output += '\n'.join(comments)
    readable_output += '\n'
    readable_output += '\n'.join(check_comments)

    return {
        'Type': entryTypes['note'],
        'EntryContext': standard_context,
        'Contents': standard_context['DBotScore']['Score'],
        'ContentsFormat': formats['text'],
        'HumanReadable': readable_output,
        'ReadableContentsFormat': formats['markdown'],
        'IgnoreAutoExtract': True
    }


''' MAIN FUNCTION '''


def main():
    try:
        return_results(certificate_reputation_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CertificateReputation. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
