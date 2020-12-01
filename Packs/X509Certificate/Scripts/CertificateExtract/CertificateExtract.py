import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

from typing import Dict

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
from typing import Union, Any, Optional, cast, List


_INSTANCE_TO_TYPE = {
    general_name.OtherName: 'otherName',
    general_name.RFC822Name: 'rfc822Name',
    general_name.DNSName: 'dNSName',
    general_name.DirectoryName: 'directoryName',
    general_name.UniformResourceIdentifier: 'uniformResourceIdentifier',
    general_name.IPAddress: 'iPAddress',
    general_name.RegisteredID: 'registeredID'
}

_SCT_LOG_ENTRY_TYPE_NAME = {
    certificate_transparency.LogEntryType.PRE_CERTIFICATE: 'PreCertificate',
    certificate_transparency.LogEntryType.X509_CERTIFICATE: 'X509Certificate'
}


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


def repr_or_str(o: Any) -> str:
    if isinstance(o, str):
        return o
    elif isinstance(o, bytes):
        return o.hex()
    elif o is None:
        return ''

    return repr(o)


def load_certificate(path: str) -> x509.Certificate:
    with open(path, 'rb') as f:
        contents = f.read()

    try:
        certificate = x509.load_pem_x509_certificate(contents, backends.default_backend())

    except Exception as e:
        demisto.debug(f"Error loading certificate as PEM, trying with DER. Error was: {e!r}")
        certificate = x509.load_der_x509_certificate(contents, backends.default_backend())

    return certificate


def int_to_comma_hex(n: int, blength: Optional[int] = None) -> str:
    bhex = f'{n:x}'
    if len(bhex) % 2 == 1:
        bhex = '0' + bhex

    if blength is not None:
        bhex = '00' * max(blength - len(bhex), 0) + bhex

    return ':'.join([bhex[i:i + 2] for i in range(0, len(bhex), 2)])


def public_key_context2(pkey: Union[asymmetric.dsa.DSAPublicKey,
                                    asymmetric.rsa.RSAPublicKey,
                                    asymmetric.ec.EllipticCurvePublicKey,
                                    asymmetric.ed25519.Ed25519PublicKey,
                                    asymmetric.ed448.Ed448PublicKey]) -> Common.CertificatePublicKey:
    if isinstance(pkey, asymmetric.dsa.DSAPublicKey):
        return Common.CertificatePublicKey(
            algorithm=Common.CertificatePublicKey.Algorithm.DSA,
            length=pkey.key_size,
            publickey=int_to_comma_hex(pkey.public_numbers().y),
            p=int_to_comma_hex(pkey.public_numbers().parameter_numbers.p),
            q=int_to_comma_hex(pkey.public_numbers().parameter_numbers.q),
            g=int_to_comma_hex(pkey.public_numbers().parameter_numbers.g)
        )

    elif isinstance(pkey, asymmetric.rsa.RSAPublicKey):
        return Common.CertificatePublicKey(
            algorithm=Common.CertificatePublicKey.Algorithm.RSA,
            length=pkey.key_size,
            modulus=int_to_comma_hex(pkey.public_numbers().n),
            exponent=pkey.public_numbers().e
        )

    elif isinstance(pkey, asymmetric.ec.EllipticCurvePublicKey):
        return Common.CertificatePublicKey(
            algorithm=Common.CertificatePublicKey.Algorithm.EC,
            length=pkey.key_size,
            x=int_to_comma_hex(pkey.public_numbers().x),
            y=int_to_comma_hex(pkey.public_numbers().y),
            curve=pkey.curve.name
        )

    return Common.CertificatePublicKey(
        algorithm=Common.CertificatePublicKey.Algorithm.UNKNOWN,
        length=0,
        publickey=pkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    )


def map_gn(gn: Any) -> Common.GeneralName:
    # print(f'gg: {gn!r}')
    if gn is None:
        raise ValueError('gn cannot be None')

    itype = next((t for t in _INSTANCE_TO_TYPE.keys() if isinstance(gn, t)), None)
    if itype is not None:
        # print(f'gn_type: {_INSTANCE_TO_TYPE[itype]}')
        return Common.GeneralName(
            gn_type=_INSTANCE_TO_TYPE[itype],
            gn_value=str(gn.value)
        )
    raise ValueError('general name must be a valid type')


def extension_context(oid: str, extension_name: str, critical: bool, extension_value: Any) -> Common.CertificateExtension:
    if isinstance(extension_value, extensions.SubjectAlternativeName):
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME,
            oid=oid, extension_name=extension_name, critical=critical,
            subject_alternative_names=[
                Common.CertificateExtension.SubjectAlternativeName(
                    gn=map_gn(gn)
                ) for gn in extension_value._general_names if gn is not None
            ]
        )
    elif (isinstance(extension_value, extensions.AuthorityKeyIdentifier)):
        authority_key_identifier = Common.CertificateExtension.AuthorityKeyIdentifier(
            issuer=[map_gn(n) for n in list(extension_value.authority_cert_issuer)] if (
                extension_value.authority_cert_issuer) else None,
            serial_number=extension_value.authority_cert_serial_number,
            key_identifier=extension_value.key_identifier.hex()
        )
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.AUTHORITYKEYIDENTIFIER,
            oid=oid, extension_name=extension_name, critical=critical,
            authority_key_identifier=authority_key_identifier
        )
    elif isinstance(extension_value, extensions.SubjectKeyIdentifier):
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.SUBJECTKEYIDENTIFIER,
            oid=oid, extension_name=extension_name, critical=critical,
            digest=extension_value.digest.hex()
        )
    elif isinstance(extension_value, extensions.KeyUsage):
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.KEYUSAGE,
            oid=oid, extension_name=extension_name, critical=critical,
            digital_signature=extension_value.digital_signature,
            content_commitment=extension_value.content_commitment,
            key_encipherment=extension_value.key_encipherment,
            data_encipherment=extension_value.data_encipherment,
            key_agreement=extension_value.key_agreement,
            key_cert_sign=extension_value.key_cert_sign,
            crl_sign=extension_value.crl_sign,
        )
    elif isinstance(extension_value, extensions.ExtendedKeyUsage):
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.EXTENDEDKEYUSAGE,
            oid=oid, extension_name=extension_name, critical=critical,
            usages=[oid_name(o) for o in extension_value]
        )
    elif isinstance(extension_value, extensions.CRLDistributionPoints):
        distribution_points: List[Common.CertificateExtension.DistributionPoint] = []
        dp: extensions.DistributionPoint
        for dp in extension_value:
            distribution_points.append(Common.CertificateExtension.DistributionPoint(
                full_name=None if dp.full_name is None else [map_gn(fn) for fn in list(dp.full_name)],
                relative_name=None if dp.relative_name is None else dp.relative_name.rfc4514_string(),
                crl_issuer=None if dp.crl_issuer is None else [map_gn(ci) for ci in list(dp.crl_issuer)],
                reasons=None if dp.reasons is None else [repr_or_str(r) for r in dp.reasons]
            ))
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.CRLDISTRIBUTIONPOINTS,
            oid=oid, extension_name=extension_name, critical=critical,
            distribution_points=distribution_points
        )
    elif isinstance(extension_value, extensions.CertificatePolicies):
        policies: List[Common.CertificateExtension.CertificatePolicy] = []
        p: extensions.PolicyInformation
        for p in extension_value:
            policies.append(Common.CertificateExtension.CertificatePolicy(
                policy_identifier=oid_name(p.policy_identifier),
                policy_qualifiers=None if not p.policy_qualifiers else [repr_or_str(pq) for pq in p.policy_qualifiers],
            ))
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.CERTIFICATEPOLICIES,
            oid=oid, extension_name=extension_name, critical=critical,
            certificate_policies=policies
        )
    elif isinstance(extension_value, extensions.AuthorityInformationAccess):
        descriptions: List[Common.CertificateExtension.AuthorityInformationAccess] = []
        d: extensions.AccessDescription
        for d in extension_value:
            descriptions.append(Common.CertificateExtension.AuthorityInformationAccess(
                access_method=oid_name(d.access_method),
                access_location=map_gn(d.access_location)
            ))

        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.AUTHORITYINFORMATIONACCESS,
            oid=oid, extension_name=extension_name, critical=critical,
            authority_information_access=descriptions
        )
    elif isinstance(extension_value, extensions.BasicConstraints):
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.BASICCONSTRAINTS,
            oid=oid, extension_name=extension_name, critical=critical,
            basic_constraints=Common.CertificateExtension.BasicConstraints(
                ca=extension_value.ca,
                path_length=None if extension_value.path_length is None else extension_value.path_length
            )
        )
    elif (
        isinstance(extension_value, extensions.PrecertificateSignedCertificateTimestamps)
        or isinstance(extension_value, extensions.SignedCertificateTimestamps)
    ):
        sigcerttimestamps: List[Common.CertificateExtension.SignedCertificateTimestamp] = []
        sct: extensions.SignedCertificateTimestamp
        for sct in extension_value:
            sigcerttimestamps.append(Common.CertificateExtension.SignedCertificateTimestamp(
                entry_type=_SCT_LOG_ENTRY_TYPE_NAME.get(sct.entry_type, sct.entry_type.value),
                version=sct.version.value,
                log_id=sct.log_id.hex(),
                timestamp=sct.timestamp.strftime(format="%Y-%m-%dT%H:%M:%S.000Z"),
            ))
        return Common.CertificateExtension(
            extension_type=Common.CertificateExtension.ExtensionType.SIGNEDCERTIFICATETIMESTAMPS,
            oid=oid, extension_name=extension_name, critical=critical,
            signed_certificate_timestamps=sigcerttimestamps
        )

    return Common.CertificateExtension(
        extension_type=Common.CertificateExtension.ExtensionType.OTHER,
        oid=oid, extension_name=extension_name, critical=critical,
        value=repr(extension_value)
    )


def certificate_to_context(certificate: x509.Certificate) -> Dict[str, Any]:
    spkisha256 = hashes.Hash(hashes.SHA256(), backends.default_backend())
    spkisha256.update(
        certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

    extensions_contexts: List[Common.CertificateExtension] = []
    for extension in certificate.extensions:
        extension_oid = cast(oid.ObjectIdentifier, extension.oid)
        extensions_contexts.append(extension_context(
            oid=extension_oid.dotted_string,
            extension_name=extension_oid._name,
            critical=extension.critical,
            extension_value=extension.value
        ))

    indicator = certificate.fingerprint(hashes.SHA256()).hex()
    cert = Common.Certificate(
        subject_dn=certificate.subject.rfc4514_string(),
        issuer_dn=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        validity_not_before=certificate.not_valid_before.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        validity_not_after=certificate.not_valid_after.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        sha1=certificate.fingerprint(hashes.SHA1()).hex(),
        md5=certificate.fingerprint(hashes.MD5()).hex(),
        spki_sha256=spkisha256.finalize().hex(),
        extensions=extensions_contexts,
        signature_algorithm=certificate.signature_hash_algorithm.name,
        signature=certificate.signature.hex(),
        publickey=public_key_context2(certificate.public_key()),
        dbot_score=Common.DBotScore(
            indicator=indicator,
            indicator_type=DBotScoreType.CERTIFICATE,
            integration_name="X509Certificate",
            score=Common.DBotScore.NONE
        ),
        pem=certificate.public_bytes(serialization.Encoding.PEM).decode('ascii')
    )

    return cert.to_context()


''' COMMAND FUNCTION '''


def certificate_extract_command(args: Dict[str, Any]) -> Dict[str, Any]:
    pem: Optional[str] = args.get('pem')
    input_: Optional[str] = args.get('input')

    if pem is None and input_ is None:
        raise ValueError("You should specify pem or input")

    if pem is not None and input_ is not None:
        raise ValueError("Only one of pem and input should be specified")

    certificate: x509.Certificate
    if input_ is not None:
        res_path = demisto.getFilePath(input_)
        if not res_path:
            raise ValueError("Invalid input - not found")

        input_path = res_path['path']

        certificate = load_certificate(input_path)

    if pem is not None:
        certificate = x509.load_pem_x509_certificate(pem.encode('ascii'), backends.default_backend())

    standard_context = certificate_to_context(certificate)
    readable_output = "Certificate decoded"

    return {
        'Type': entryTypes['note'],
        'EntryContext': standard_context,
        'Contents': Common.DBotScore.NONE,
        'ContentsFormat': formats['text'],
        'HumanReadable': readable_output,
        'ReadableContentsFormat': formats['markdown'],
        'IgnoreAutoExtract': True
    }


''' MAIN FUNCTION '''


def main():
    try:
        return_results(certificate_extract_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CertificateExtract. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
