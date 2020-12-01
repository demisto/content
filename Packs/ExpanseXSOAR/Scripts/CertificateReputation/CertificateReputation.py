"""
outputs:
- contextPath: Certificate.Name
  description: Name (CN or SAN) appearing in the certificate.
  type: String
- contextPath: Certificate.SubjectDN
  description: |
    The Subject Distinguished Name of the certificate.
    This field includes the Common Name of the certificate.
  type: String
- contextPath: Certificate.PEM
  description: Certificate in PEM format.
  type: String
- contextPath: Certificate.IssuerDN
  description: The Issuer Distinguished Name of the certificate.
  type: String
- contextPath: Certificate.SerialNumber
  description: The Serial Number of the certificate.
  type: String
- contextPath: Certificate.ValidityNotAfter
  description: End of certificate validity period.
  type: Date
- contextPath: Certificate.ValidityNotBefore
  description: Start of certificate validity period.
  type: Date
- contextPath: Certificate.SubjectAlternativeName.Type
  description: Type of the SAN.
  type: String
- contextPath: Certificate.SubjectAlternativeName.Name
  description: Name of the SAN.
  type: String
- contextPath: Certificate.SHA256
  description: SHA256 Fingerprint of the certificate in DER format.
  type: String
- contextPath: Certificate.SHA1
  description: SHA1 Fingerprint of the certificate in DER format.
  type: String
- contextPath: Certificate.MD5
  description: MD5 Fingerprint of the certificate in DER format.
  type: String
- contextPath: Certificate.PEMMD5
  description: MD5 Fingerprint of the certificate in PEM format. Used by Expanse.
  type: String
- contextPath: Certificate.PublicKey.Algorithm
  description: Algorithm used for public key of the certificate.
  type: String
- contextPath: Certificate.PublicKey.Length
  description: Length in bits of the public key of the certificate.
  type: Number
- contextPath: Certificate.PublicKey.Modulus
  description: Modulus of the public key for RSA keys.
  type: String
- contextPath: Certificate.PublicKey.Exponent
  description: Exponent of the public key for RSA keys.
  type: Number
- contextPath: Certificate.PublicKey.PublicKey
  description: The public key for DSA/Unknown keys.
  type: String
- contextPath: Certificate.PublicKey.P
  description: The P parameter for DSA keys.
  type: String
- contextPath: Certificate.PublicKey.Q
  description: The Q parameter for DSA keys.
  type: String
- contextPath: Certificate.PublicKey.G
  description: The G parameter for DSA keys.
  type: String
- contextPath: Certificate.PublicKey.X
  description: The X parameter for EC keys.
  type: String
- contextPath: Certificate.PublicKey.Y
  description: The Y parameter for EC keys.
  type: String
- contextPath: Certificate.PublicKey.Curve
  description: Curve of the Public Key for EC keys.
  type: String
- contextPath: Certificate.SPKISHA256
  description: SHA256 fingerprint of the certificate Subject Public Key Info.
  type: String
- contextPath: Certificate.Signature.Algorithm
  description: Algorithm used in the signature of the certificate.
  type: String
- contextPath: Certificate.Signature.Signature
  description: Signature of the certificate.
  type: String
- contextPath: Certificate.Extension.Critical
  description: Critical flag of the certificate extension.
  type: Bool
- contextPath: Certificate.Extension.OID
  description: OID of the certificate extension.
  type: String
- contextPath: Certificate.Extension.Name
  description: Name of the certificate extension.
  type: String
- contextPath: Certificate.Extension.Value
  description: Value of the certificate extension.
  type: Unknown
  """

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

import traceback
from typing import Dict, Any, Union, Optional, cast

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import (
    hashes,
    asymmetric,
    serialization
)
from cryptography import x509
from cryptography.x509 import (
    oid,
    extensions,
    general_name,
    certificate_transparency
)


_GENERAL_NAME_INSTANCE_TO_TYPE = {
    general_name.OtherName: 'otherName',
    general_name.RFC822Name: 'rfc822Name',
    general_name.DNSName: 'DNS',
    general_name.DirectoryName: 'directoryName',
    general_name.UniformResourceIdentifier: 'URI',
    general_name.IPAddress: 'IP',
    general_name.RegisteredID: 'registeredID'
}


_SCT_LOG_ENTRY_TYPE_NAME = {
    certificate_transparency.LogEntryType.PRE_CERTIFICATE: 'PreCertificate',
    certificate_transparency.LogEntryType.X509_CERTIFICATE: 'X509Certificate'
}


_CERTIFICATE_CONTEXT_PATH = ('Certificate(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || '
                             'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512)')


''' STANDALONE FUNCTION '''


def get_indicator_from_value(indicator_value: str):
    try:
        res = demisto.executeCommand("findIndicators", {'query': f'value:"{indicator_value}" and type:Certificate'})
        indicator = res[0]['Contents'][0]

        return indicator
    except BaseException:
        return None


def oid_name(oid: oid.ObjectIdentifier) -> str:
    n = oid._name
    if n.startswith('Unknown'):
        return oid.dotted_string

    return n


def repr_or_str(o: Any) -> Optional[str]:
    if isinstance(o, str):
        return o
    elif isinstance(o, bytes):
        return o.hex()
    elif o is None:
        return None

    return repr(o)


def int_to_comma_hex(n: int, blength: Optional[int] = None) -> str:
    bhex = f'{n:x}'
    if len(bhex) % 2 == 1:
        bhex = '0' + bhex

    if blength is not None:
        bhex = '00' * max(blength - len(bhex), 0) + bhex

    return ':'.join([bhex[i:i + 2] for i in range(0, len(bhex), 2)])


def public_key_to_context(pkey: Any) -> Dict[str, Any]:
    if isinstance(pkey, asymmetric.dsa.DSAPublicKey):
        return {
            'Algorithm': 'DSA',
            'Length': pkey.key_size,
            'PublicKey': int_to_comma_hex(pkey.public_numbers().y),
            'P': int_to_comma_hex(pkey.public_numbers().parameter_numbers.p),
            'Q': int_to_comma_hex(pkey.public_numbers().parameter_numbers.q),
            'G': int_to_comma_hex(pkey.public_numbers().parameter_numbers.g),
        }

    elif isinstance(pkey, asymmetric.rsa.RSAPublicKey):
        return {
            'Algorithm': 'RSA',
            'Length': pkey.key_size,
            'Modulus': int_to_comma_hex(pkey.public_numbers().n),
            'Exponent': pkey.public_numbers().e
        }

    elif isinstance(pkey, asymmetric.ec.EllipticCurvePublicKey):
        return {
            'Algorithm': 'EC',
            'Length': pkey.key_size,
            'X': int_to_comma_hex(pkey.public_numbers().x),
            'Y': int_to_comma_hex(pkey.public_numbers().y),
            'Curve': pkey.curve.name
        }

    return {
        'Algorithm': 'Unknown Algorithm',
        'PublicKey': pkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    }


def general_name_to_context(gn: Any) -> Dict[str, Any]:
    if gn is None:
        return {
            'Type': None,
            'Value': 'None'
        }

    itype = next((t for t in _GENERAL_NAME_INSTANCE_TO_TYPE.keys() if isinstance(gn, t)), None)
    if itype is not None:
        return {
            'Type': _GENERAL_NAME_INSTANCE_TO_TYPE[itype],
            'Value': str(gn.value)
        }

    return {
        'Type': 'Unknown',
        'Value': str(gn.value)
    }


def extension_value_to_context(extension_value: Any) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    if isinstance(extension_value, extensions.SubjectAlternativeName):
        return [general_name_to_context(gn) for gn in extension_value._general_names]
    elif isinstance(extension_value, extensions.AuthorityKeyIdentifier):
        return {
            'Issuer': None if extension_value.authority_cert_issuer is None else [
                general_name_to_context(n) for n in list(
                    extension_value.authority_cert_issuer)],
            'SerialNumber': extension_value.authority_cert_serial_number,
            'KeyIdentifier': extension_value.key_identifier.hex()}
    elif isinstance(extension_value, extensions.SubjectKeyIdentifier):
        return {
            'Digest': extension_value.digest.hex()
        }
    elif isinstance(extension_value, extensions.KeyUsage):
        return {
            'DigitalSignature': extension_value.digital_signature,
            'ContentCommitment': extension_value.content_commitment,
            'KeyEncipherment': extension_value.key_encipherment,
            'DataEncipherment': extension_value.data_encipherment,
            'KeyAgreement': extension_value.key_agreement,
            'KeyCertSign': extension_value.key_cert_sign,
            'CrlSign': extension_value.crl_sign,
        }
    elif isinstance(extension_value, extensions.ExtendedKeyUsage):
        return {'Usages': [oid_name(o) for o in extension_value]}
    elif isinstance(extension_value, extensions.CRLDistributionPoints):
        distribution_points = []
        dp: extensions.DistributionPoint
        for dp in extension_value:
            distribution_points.append({
                'FullName': None if dp.full_name is None else [general_name_to_context(fn) for fn in list(dp.full_name)],
                'RelativeName': None if dp.relative_name is None else dp.relative_name.rfc4514_string(),
                'CRLIssuer': None if dp.crl_issuer is None else [general_name_to_context(ci) for ci in list(dp.crl_issuer)],
                'Reasons': None if dp.reasons is None else [repr_or_str(r) for r in dp.reasons],
            })
        return distribution_points
    elif isinstance(extension_value, extensions.CertificatePolicies):
        policies = []
        p: extensions.PolicyInformation
        for p in extension_value:
            policies.append({
                'PolicyIdentifier': None if p.policy_identifier is None else oid_name(p.policy_identifier),
                'PolicyQualifiers': None if p.policy_qualifiers is None else [repr_or_str(pq) for pq in p.policy_qualifiers],
            })
        return policies
    elif isinstance(extension_value, extensions.AuthorityInformationAccess):
        descriptions = []
        d: extensions.AccessDescription
        for d in extension_value:
            descriptions.append({
                'AccessMethod': None if d.access_method is None else oid_name(d.access_method),
                'AccessLocation': None if d.access_location is None else general_name_to_context(d.access_location)
            })
        return descriptions
    elif isinstance(extension_value, extensions.BasicConstraints):
        return {
            'CA': None if extension_value.ca is None else extension_value.ca,
            'PathLength': None if extension_value.path_length is None else extension_value.path_length
        }
    elif isinstance(extension_value, extensions.PrecertificateSignedCertificateTimestamps) or isinstance(extension_value, extensions.SignedCertificateTimestamps):
        sigcerttimestamps = []
        sct: certificate_transparency.SignedCertificateTimestamp
        for sct in extension_value:
            sigcerttimestamps.append({
                'Version': sct.version.value,
                'LogId': sct.log_id.hex(),
                'Timestamp': sct.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                'EntryType': _SCT_LOG_ENTRY_TYPE_NAME.get(sct.entry_type, sct.entry_type.value)
            })
        return sigcerttimestamps

    return {
        'Repr': repr(extension_value)
    }


def certificate_fields_to_context(certindicator_fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pem: Optional[str]
    if (pem := certindicator_fields.get('pem')) is None:
        return None

    certificate = x509.load_pem_x509_certificate(pem.encode('ascii'), backends.default_backend())

    context: Dict[str, Any] = {}

    # Basic Info
    context['SubjectDN'] = certificate.subject.rfc4514_string()
    context['Name'] = [a.value for a in certificate.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)]
    context['IssuerDN'] = certificate.issuer.rfc4514_string()
    context['SerialNumber'] = str(certificate.serial_number)
    context['ValidityNotAfter'] = certificate.not_valid_after.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    context['ValidityNotBefore'] = certificate.not_valid_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Fingerprint
    context['SHA512'] = certificate.fingerprint(hashes.SHA512()).hex()
    context['SHA256'] = certificate.fingerprint(hashes.SHA256()).hex()
    context['SHA1'] = certificate.fingerprint(hashes.SHA1()).hex()
    context['MD5'] = certificate.fingerprint(hashes.MD5()).hex()

    # Public Key
    context['PublicKey'] = public_key_to_context(certificate.public_key())
    spkisha256 = hashes.Hash(hashes.SHA256(), backends.default_backend())
    spkisha256.update(
        certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    context['SPKISHA256'] = spkisha256.finalize().hex()

    # Signature
    context['Signature'] = {
        'Algorithm': certificate.signature_hash_algorithm.name,
        'Signature': certificate.signature.hex()
    }

    # SubjectAlternativeName
    # Extension
    context['SubjectAlternativeName'] = []
    context['Extension'] = []
    for extension in certificate.extensions:
        if extension.oid == oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san = cast(extensions.SubjectAlternativeName, extension.value)
            for gn in san._general_names:
                gn_ctx = general_name_to_context(gn)
                context['SubjectAlternativeName'].append(gn_ctx)
                if gn_ctx['Type'] in ('IP', 'DNS'):
                    if gn_ctx['Value'] in context['Name']:
                        continue
                    context['Name'].append(gn_ctx['Value'])

        extension_oid = cast(oid.ObjectIdentifier, extension.oid)
        context['Extension'].append({
            'OID': extension_oid.dotted_string,
            'Name': extension_oid._name,
            'Critical': extension.critical,
            'Value': extension_value_to_context(extension.value)
        })

    return {
        _CERTIFICATE_CONTEXT_PATH: context
    }


def dbot_context(value: Optional[str], fields: Dict[str, Any], certificate_context: Dict[str, Any]) -> Dict[str, Any]:
    if value is None:
        return {}

    return {
        'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
        'val.Vendor == obj.Vendor && val.Type == obj.Type)': {
            'Score': Common.DBotScore.NONE,
            'Vendor': 'ExpanseV2',
            'Type': 'Certificate',
                    'Indicator': value
        }
    }


''' COMMAND FUNCTION '''


def certificate_reputation_command(args: Dict[str, Any]) -> CommandResults:
    input_ = args.get('input')
    if input_ is None:
        raise ValueError("input argument is required")

    indicator = get_indicator_from_value(input_)

    if indicator is None:
        return CommandResults(
            readable_output="No indicators found",
            outputs=None,
            outputs_key_field=None
        )

    standard_context = {}
    if (fields := indicator.get('CustomFields')) is not None:
        if (certificate_context := certificate_fields_to_context(fields)) is not None:
            standard_context.update(certificate_context)

    standard_context.update(dbot_context(indicator.get('value'), fields, standard_context))

    result = CommandResults(
        readable_output="## Yes",
        outputs=standard_context,
        outputs_key_field=None,
        outputs_prefix=None,
        ignore_auto_extract=True,
    )
    demisto.debug(json.dumps(result.to_context(), indent=4))

    return result


''' MAIN FUNCTION '''


def main():
    demisto.log("CALLED CALLED CALLED! CertificateReputation CALLED!")
    try:
        return_results(certificate_reputation_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CertificateReputation. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
