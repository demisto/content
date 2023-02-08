import demistomock as demisto
from CommonServerPython import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def main():
    try:
        # Generate a key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        toWarRoom = demisto.getArg('OutputToWarRoom')
        cn = demisto.getArg('cn')
        email = demisto.getArg('email')
        organization = demisto.getArg('org')
        organizational_unit = demisto.getArg('orgUnit')
        country = demisto.getArg('country')
        state = demisto.getArg('state')
        locality = demisto.getArg('locality')

        cert_attributes = [x509.NameAttribute(x509.OID_COMMON_NAME, cn)]

        # Generate the CSR
        builder = x509.CertificateSigningRequestBuilder()

        # Build CSR Attributes for CertificateSigningRequestBuilder Object
        if email:
            cert_attributes.append(x509.NameAttribute(x509.OID_EMAIL_ADDRESS, email))

        if organization:
            cert_attributes.append(x509.NameAttribute(x509.OID_ORGANIZATION_NAME, organization))

        if organizational_unit:
            cert_attributes.append(x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, organizational_unit))

        if country:
            cert_attributes.append(x509.NameAttribute(x509.OID_COUNTRY_NAME, country))

        if state:
            cert_attributes.append(x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, state))

        if locality:
            cert_attributes.append(x509.NameAttribute(x509.OID_LOCALITY_NAME, locality))

        builder = builder.subject_name(x509.Name(cert_attributes))

        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)

        csr = builder.sign(key, hashes.SHA256(), default_backend())

        pem_req = csr.public_bytes(serialization.Encoding.PEM)

        pem_text = pem_req.decode('utf8')

        results = [
            fileResult(
                filename="request.csr",
                data=pem_text
            ),
        ]

        if toWarRoom == "True":
            results.append(pem_text)

        return_results(results)

    except Exception as ex:
        return_error(f'An Error occured: {ex}', error=ex)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
