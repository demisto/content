import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.exceptions import InvalidSignature
from cryptography.x509.extensions import CRLDistributionPoints, AuthorityInformationAccess
import os
from datetime import datetime


SUSPICIOUS_KEYWORDS = [
    keyword.lower()
    for keyword in [
        "Microsoft",
        "Google",
        "Apple",
        "Adobe",
        "Facebook",
        "Amazon",
        "NVIDIA",
        "Cisco",
        "Intel",
        "Oracle",
        "Symantec",
    ]
]


def get_cn(cert_name_object):
    for attr in cert_name_object:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return ""


def is_self_signed(cert):
    try:
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_oid._name,
            cert.signature_hash_algorithm,
        )
        return cert.issuer == cert.subject
    except InvalidSignature:
        return False
    except Exception:
        return False


def analyze_pfx_file(pfx_data: bytes, pfx_password: Optional[str] = None) -> dict:
    reasons = []
    extension_missing_flags = {
        "CRL": False,
        "AIA": False,
        "CertPolicy": False,
    }

    pfx_output = {
        "Private Key Present": False,
        "Key Type": "N/A",
        "Key Size": "N/A",
        "Certificate Present": False,
        "Common Name": "N/A",
        "Issuer": "N/A",
        "Validity Start": "N/A",
        "Validity End": "N/A",
        "Validity Days": "N/A",
        "Self-Signed": False,
        "CRL URIs": [],
        "OCSP URIs": [],
        "Suspicious Keywords in CN": False,
        "Reasons": [],
        "is_pfx_suspicious": False,
    }

    password_bytes = pfx_password.encode("utf-8") if pfx_password else None

    try:
        if password_bytes is not None:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password=password_bytes)
        else:
            try:
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password=None)
            except ValueError:
                try:
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password=b"")
                except ValueError:
                    raise ValueError("Password required or unknown password.")
    except Exception as e:
        raise ValueError(f"Unable to parse .pfx file: {str(e)}")

    now = datetime.utcnow()

    if private_key:
        pfx_output["Private Key Present"] = True
        reasons.append("Private key is present")
        if isinstance(private_key, rsa.RSAPrivateKey):
            pfx_output["Key Type"] = "RSA"
            pfx_output["Key Size"] = private_key.key_size
            if private_key.key_size < 2048:
                reasons.append(f"Weak RSA key size ({private_key.key_size} bits)")
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            pfx_output["Key Type"] = "ECC"
            pfx_output["Key Size"] = private_key.curve.name
            if private_key.curve.name in ["secp192r1", "secp224r1", "prime192v1", "prime239v1"]:
                reasons.append(f"Weak ECC curve ({private_key.curve.name})")
        else:
            pfx_output["Key Type"] = str(type(private_key))

    if cert:
        pfx_output["Certificate Present"] = True
        pfx_output["Common Name"] = get_cn(cert.subject)
        pfx_output["Issuer"] = get_cn(cert.issuer)
        pfx_output["Validity Start"] = cert.not_valid_before.isoformat() + "Z"
        pfx_output["Validity End"] = cert.not_valid_after.isoformat() + "Z"

        if is_self_signed(cert):
            pfx_output["Self-Signed"] = True
            reasons.append("Certificate is self-signed")

        if cert.not_valid_after < now:
            reasons.append("Certificate is expired")
        if cert.not_valid_before > now:
            reasons.append("Certificate not valid yet (starts in the future)")

        try:
            validity_days = (cert.not_valid_after - cert.not_valid_before).days
            pfx_output["Validity Days"] = validity_days
            if validity_days > 731:
                reasons.append(f"Certificate has an unusually long validity period ({validity_days} days)")
            if validity_days < 0:
                reasons.append("Invalid validity period calculation (negative days)")
        except Exception:
            reasons.append("Could not calculate certificate validity duration")

        cn = pfx_output["Common Name"]

        if cn and any(keyword in str(cn).lower() for keyword in SUSPICIOUS_KEYWORDS):
            pfx_output["Suspicious Keywords in CN"] = True
            reasons.append(f"Suspicious keyword in Common Name: '{cn}'")

        try:
            policy_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            if not getattr(policy_ext.value, "policy_information", []):
                reasons.append("Certificate Policy extension found but no policy information (unusual)")
        except x509.ExtensionNotFound:
            extension_missing_flags["CertPolicy"] = True
        except Exception as ex:
            reasons.append(f"Error processing Certificate Policies: {ex}")

        try:
            crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            if isinstance(crl_ext.value, CRLDistributionPoints):
                crl_uris = []
                for dp in crl_ext.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            if hasattr(name, "value") and name.value.startswith("http"):
                                crl_uris.append(name.value)
                if crl_uris:
                    pfx_output["CRL URIs"] = crl_uris
                else:
                    reasons.append("CRL Distribution Points extension present but no URIs (suspicious)")
            else:
                reasons.append("Unexpected structure in CRL Distribution Points")
        except x509.ExtensionNotFound:
            extension_missing_flags["CRL"] = True
        except Exception as ex:
            reasons.append(f"Error processing CRL Distribution Points: {ex}")

        try:
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if isinstance(aia_ext.value, AuthorityInformationAccess):
                ocsp_uris = [
                    desc.access_location.value
                    for desc in aia_ext.value
                    if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
                    and desc.access_location.value.startswith("http")
                ]
                if ocsp_uris:
                    pfx_output["OCSP URIs"] = ocsp_uris
                else:
                    reasons.append("OCSP URI not found in Authority Information Access (suspicious for public CAs)")
            else:
                reasons.append("Unexpected structure in Authority Information Access extension")
        except x509.ExtensionNotFound:
            extension_missing_flags["AIA"] = True
        except Exception as ex:
            reasons.append(f"Error processing OCSP URIs: {ex}")

        if all(extension_missing_flags.values()):
            reasons.append("Certificate is missing standard extensions: CRL, AIA, and Certificate Policies (suspicious)")

    pfx_output["Reasons"] = reasons
    pfx_output["is_pfx_suspicious"] = len(reasons) > 2

    return pfx_output


def main():
    try:
        args = demisto.args()
        file_entry_id = args.get("fileEntryId")
        pfx_password = args.get("pfxPassword")

        if not file_entry_id:
            raise ValueError("fileEntryId argument is missing.")

        file_path_info = demisto.getFilePath(file_entry_id)
        file_path = file_path_info.get("path")

        if not file_path or not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found at: {file_path}")

        with open(file_path, "rb") as f:
            pfx_bytes = f.read()

        analysis_results = analyze_pfx_file(pfx_bytes, pfx_password)

        readable_output = "## PFX Analysis Results\n"
        for key, value in analysis_results.items():
            if key in ["Reasons", "CRL URIs", "OCSP URIs"] and value:
                readable_output += f"**{key}:**\n" + "".join(f"- {item}\n" for item in value)
            elif key == "Reasons" and not value:
                readable_output += "**Reasons:** None identified.\n"
            else:
                readable_output += f"**{key}:** {value}\n"

        return_results(
            CommandResults(
                readable_output=readable_output,
                outputs=analysis_results,
                output_prefix="PFXAnalysis",
            )
        )

    except Exception as e:
        return_error(f"PFX Analysis failed: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
