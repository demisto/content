import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from copy import copy

import dateparser
import urllib3

from CommonServerUserPython import *


import tempfile
from typing import Any
from collections.abc import Iterator, Iterable
import uuid

from xmltodict import parse

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CA = 'issuer=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\nsubject=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\n-----BEGIN CERTIFICATE-----\nMIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\nGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\nAxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw\nMTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu\nbWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s\naWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/\nWq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+\nDuir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl\n4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF\nmCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp\nwX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj\nwOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH\nAQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh\nL2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v\nbGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es\nb3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti\naW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB\nBjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD\nggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi\nTR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+\n7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH\nvenAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl\nDn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ\nA2EC/0rskqTcLe4qNJMHtyznGI8=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\nissuer=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\n-----BEGIN CERTIFICATE-----\nMIIGQzCCBSugAwIBAgICZAUwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\nGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\nAxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTE4MDgyOTE0MTg0OVoXDTIx\nMDgyOTE0MTc0NFowgY4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy\nbm1lbnQxIzAhBgNVBAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYD\nVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMRwwGgYDVQQLExNVUyBUcmVh\nc3VyeSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6CQE\nWcyYx3xksWrXOylIx7tY6t+ixCqT0WjWi4PCKkDmauxuGt/pI+9UYdrlou12AGkE\n1Uzyv8QbaIVRrgenONkKs1IRNp8igd4ESHe+qK+y8XgurMRYh1CGAgx7N2gInWJN\ntQm38RZz2wToRumIkyXI2m2jqIwh38bXNlgg2632jBKAIpdY9ONCi33R9H65f1bv\nujG8SewSrwiAueKXYmB/74P5Y97rcG6rxE8PNBKmy60mQ8uPA8bzniQeKoOwauYp\n/1cesW5fT0DVQrWq1bRR5LJ7Wwb8gqLMsRa/PkTHo2S3gvZoctvm/nth2/6udXbM\n3GxS2bwHqDlm64+aywIDAQABo4IC3TCCAtkwDwYDVR0TAQH/BAUwAwEB/zCBswYD\nVR0gBIGrMIGoMAwGCmCGSAFlAwIBAwEwDAYKYIZIAWUDAgEDAjAMBgpghkgBZQMC\nAQMGMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDCDAMBgpghkgBZQMCAQMkMAwG\nCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgEDEDAMBgpghkgBZQMCAQMRMAwGCmCGSAFl\nAwIBAycwDAYKYIZIAWUDAgEDKDAMBgpghkgBZQMCAQMpME8GCCsGAQUFBwEBBEMw\nQTA/BggrBgEFBQcwAoYzaHR0cDovL2h0dHAuZnBraS5nb3YvZmNwY2EvY2FDZXJ0\nc0lzc3VlZFRvZmNwY2EucDdjMIHbBgNVHSEEgdMwgdAwGAYKYIZIAWUDAgEDAQYK\nYIZIAWUDAgEFAjAYBgpghkgBZQMCAQMCBgpghkgBZQMCAQUDMBgGCmCGSAFlAwIB\nAwYGCmCGSAFlAwIBAwYwGAYKYIZIAWUDAgEDBgYKYIZIAWUDAgEFBzAYBgpghkgB\nZQMCAQMHBgpghkgBZQMCAQMHMBgGCmCGSAFlAwIBAwcGCmCGSAFlAwIBBQQwGAYK\nYIZIAWUDAgEDEAYKYIZIAWUDAgEDEDAYBgpghkgBZQMCAQMQBgpghkgBZQMCAQUF\nMEAGCCsGAQUFBwELBDQwMjAwBggrBgEFBQcwBYYkaHR0cDovL3BraS50cmVhc3Vy\neS5nb3Yvcm9vdF9zaWEucDdjMAwGA1UdJAQFMAOBAQAwCgYDVR02BAMCAQAwDgYD\nVR0PAQH/BAQDAgEGMB8GA1UdIwQYMBaAFK0MenVc5fOYxHmYDqwo/Zf05wL8MDUG\nA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2ZjcGNh\nLmNybDAdBgNVHQ4EFgQUaIQVSIxUcH8tElgO7Bx47zwuWWQwDQYJKoZIhvcNAQEL\nBQADggEBAGkNU1Q6y2uhdE4RfMMdS68yh3xjANrACzGLHbIBumpK0AOLtunuig7/\nddTtou5rCOPxPGomiInu5HxhG9J+g+T90acXFg+67XuSIrQtDYRkrMr/9AKtHwGn\nzVYy5U92gk2nAS1RD6tW0WB/ava2qTZR/kH9deOtp0AgUZDRLV7AigXLSVaK99nQ\ngYQO2PW4f7Trl2jwvxTmV9jb/wo96KtJmpAGYeK8DscJHqmtOk83225UEPS1Sfqj\nQVbvYbkCG+GvvMwFUn87aQN0EcCnRIN4Z6SksmfPTtN6Viw585vpzrJhKZoqVvvG\nkBGaMG3CZwgMqK1yrPo3waYtA+/Ns+8=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\nissuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIHfzCCBmegAwIBAgIEVw0sATANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTYwNzEzMTMw\nMzI2WhcNMjYwODA1MTQ0NjMwWjCBjjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1\ncnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxHDAaBgNVBAsT\nE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDsPmfNCAYlZsDMUIy/nHudvttnURFsoYR8pUuDtdZPzFOwvwJoi2V1a1MY\nbBuOJMf6xsuaTX2OR8JDtCHKKkwcN+YXEQBr9pNzbydaq5P86a3XIS6dfapArtcD\njaAZgtF+SNxXzCv+BweJ5AMRFQpRJg+j95yvN9wntLvFGkgqqIE+UPmaxYmMEcGy\nBla8ym9Pa1m45TecrjuhDcU1m0dSJSRhS1CJ4xHCTxNDxjR91n6vAnFZOjjgtQmn\niFc+C11JJ74MUMm/6V7w1y/PDVwfyUnyyM+MW8UKN5ZVlUWEML8dHYGqcLu+pxID\nJYLCwho01+fXWSu4sx/ztJR2orBZ4sf7Ek6HmyUpX3X6l57sepRghrA7dssJ4dnZ\nNdB+g3fufbbgh4WDOlHa3h9VEuVhh5m4XFFvi8icIgUzC+Wais5eK1UJ9pl3vVaz\n0Yo7dKDe6v2w28qAF4TsDiablsRVEFLQamj6zov2N1Q9i+vNXVtHHV/gh8jC5JvG\nX3cyfUkss0U9LWcAeFE5zU3NN//VqedWc9a3j3G8l94qYVqDCQwq/fAWprRQcX1M\n7xNhw7mO547B+Idjp70BISVPR6/laTeRqg/nA9Z4/xGGS3UecP2m6K2ACJQ0ewSi\nXuix6ahFB2XOaDmNkTfToobPCNuA11fhA3yIan++3euD7SwVWQIDAQABo4IC4TCC\nAt0wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wSwYIKwYBBQUHAQEE\nPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi9jYWNlcnRz\naXNzdWVkdG90cmNhLnA3YzBABggrBgEFBQcBCwQ0MDIwMAYIKwYBBQUHMAWGJGh0\ndHA6Ly9wa2kudHJlYXN1cnkuZ292L3Jvb3Rfc2lhLnA3YzCB+QYDVR0gBIHxMIHu\nMAwGCmCGSAFlAwIBAwYwDAYKYIZIAWUDAgEDBzAMBgpghkgBZQMCAQMIMAwGCmCG\nSAFlAwIBAw0wDAYKYIZIAWUDAgEDEDAMBgpghkgBZQMCAQMRMAwGCmCGSAFlAwIB\nAyQwDAYKYIZIAWUDAgEDJzAMBgpghkgBZQMCAQMoMAwGCmCGSAFlAwIBAykwDAYK\nYIZIAWUDAgEFAjAMBgpghkgBZQMCAQUDMAwGCmCGSAFlAwIBBQQwDAYKYIZIAWUD\nAgEFBzAMBgpghkgBZQMCAQUKMAwGCmCGSAFlAwIBBQswDAYKYIZIAWUDAgEFDDAf\nBgNVHSMEGDAWgBRohBVIjFRwfy0SWA7sHHjvPC5ZZDAdBgNVHQ4EFgQUF0u4Jrpp\neq0SUFdFMZ5Xu3Sl2i8wge4GA1UdHwSB5jCB4zCBqaCBpqCBo6SBoDCBnTELMAkG\nA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVw\nYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24g\nQXV0aG9yaXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0ExDTALBgNV\nBAMTBENSTDEwNaAzoDGGL2h0dHA6Ly9wa2kudHJlYXN1cnkuZ292L1VTX1RyZWFz\ndXJ5X1Jvb3RfQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQA2/JRVLMwhdhyhlNG5\nBwbSsk9+OpFvOXncyGIxHyHpLxi0ddgFZN2DIu1+bnRCfw3PR8nZ6/lcMRZwyXT8\nQI0rjNEOr5DplepWY/JfYwk+bjmVq7UCQZjT2cIQgcmLRjc/euOejoEga0FsENXK\nAhcKU/4VO8aq/xE4tllvsfjboHCACFn2e97j6j1lNtZfA4RxXZ0xIkIzcVFoeh/g\n5tqB7FjsFpXKnvKUTr3ZgrINSBc8zCh12QyToHwgAUcIQK0GGnWxOo3QHB2RuRXK\nVtb2b1AtmWAaiJbM008+FzF/quvpvBJcqqo5nc3laNGgvkCNzQfM/KJ7WITaOe0g\ndqOC\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\nissuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIHgDCCBWigAwIBAgIEVw0sADANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMDYwODA1MTQx\nNjMwWhcNMjYwODA1MTQ0NjMwWjCBjjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1\ncnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxHDAaBgNVBAsT\nE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDoJARZzJjHfGSxatc7KUjHu1jq36LEKpPRaNaLg8IqQOZq7G4a3+kj71Rh\n2uWi7XYAaQTVTPK/xBtohVGuB6c42QqzUhE2nyKB3gRId76or7LxeC6sxFiHUIYC\nDHs3aAidYk21CbfxFnPbBOhG6YiTJcjabaOojCHfxtc2WCDbrfaMEoAil1j040KL\nfdH0frl/Vu+6MbxJ7BKvCIC54pdiYH/vg/lj3utwbqvETw80EqbLrSZDy48DxvOe\nJB4qg7Bq5in/Vx6xbl9PQNVCtarVtFHksntbBvyCosyxFr8+RMejZLeC9mhy2+b+\ne2Hb/q51dszcbFLZvAeoOWbrj5rLAgMBAAGjggLiMIIC3jAOBgNVHQ8BAf8EBAMC\nAQYwDwYDVR0TAQH/BAUwAwEB/zBLBggrBgEFBQcBAQQ/MD0wOwYIKwYBBQUHMAKG\nL2h0dHA6Ly9wa2kudHJlYXN1cnkuZ292L2NhY2VydHNpc3N1ZWR0b3RyY2EucDdj\nMEAGCCsGAQUFBwELBDQwMjAwBggrBgEFBQcwBYYkaHR0cDovL3BraS50cmVhc3Vy\neS5nb3Yvcm9vdF9zaWEucDdjMIH5BgNVHSAEgfEwge4wDAYKYIZIAWUDAgEDBjAM\nBgpghkgBZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDDTAMBgpghkgB\nZQMCAQMQMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMn\nMAwGCmCGSAFlAwIBAygwDAYKYIZIAWUDAgEDKTAMBgpghkgBZQMCAQUCMAwGCmCG\nSAFlAwIBBQMwDAYKYIZIAWUDAgEFBDAMBgpghkgBZQMCAQUHMAwGCmCGSAFlAwIB\nBQowDAYKYIZIAWUDAgEFCzAMBgpghkgBZQMCAQUMMB8GA1UdIwQYMBaAFBdLuCa6\naXqtElBXRTGeV7t0pdovMB0GA1UdDgQWBBRohBVIjFRwfy0SWA7sHHjvPC5ZZDCB\n7wYDVR0fBIHnMIHkMIGpoIGmoIGjpIGgMIGdMQswCQYDVQQGEwJVUzEYMBYGA1UE\nChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLExpEZXBhcnRtZW50IG9mIHRoZSBU\ncmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEcMBoG\nA1UECxMTVVMgVHJlYXN1cnkgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTA2oDSgMoYw\naHR0cDovL3BraS50cmVhc3VyeS5nb3YvVVNfVHJlYXN1cnlfUm9vdF9DQTEuY3Js\nMA0GCSqGSIb3DQEBCwUAA4ICAQDkJPyJSS87CAuaDXkdJFGsLkgQOrDxCJpNgD1Z\nQ1RmAbBwpO8x94m00gjE2uN9Gj/ezADsK0Yu9z83XdAl/6706GJ3bChBy/0m2xeB\ni/oYhhkXB17Sc2a8O8gA8DLm3bXqvO3T32pVJnyXj/ckUU1P424zQjqhj5d+/xs/\nM96a/jiFc7pFAE4lCBI6ydDeUNBZgRleX9R7Bp23/Uygd59wzEZ0Jvu2ls9x1bBG\nqtp71PsGRhKyU64XFEKTaNknye/0TqRdTqpWzH6foTBjptYvn08cZmGVQNientSb\nqWk+pvgxJtM9piiGDlUaPcizdnL5O3xVfjwYQNRteVPwXepkBSl9yPIG49yknUcH\nfj0S2NCQy1OYqhy+oFYr+2aJG0CON5LFrwkaUU0bvRAXpW33hqN5/+8cApccXAeh\nD42+gKVr+M/vNJGat46KKX6PF1ZflFfrE7jxD3Jza0N4dTXDRCagj30QmegziIA2\nvylt+7jH7FHUVvOfTZaHMqvyZfc9dFKYpqJKrFEaMv6Fqawejir8kF9CUpSAF2O7\nA843vFQuVRgIwp1M+D4xnvxnLbehLzqEZ6ZSSIPoHXzitfz9/oycCfUbIyYE4TW9\n8wEwfpj4wCO1Gldl+2rZYUEb5mjkkltR1O8s5rYqoxVSVKUrAD/fHYdOzteWkNQk\nyiTo/Q==\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of Homeland Security/OU=Certification Authorities/OU=DHS CA4\nissuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIGDTCCBPWgAwIBAgIETjmBKDANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTUwNjEzMTQz\nNTA0WhcNMjUwNjEzMTUwNTA0WjCBhzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEoMCYGA1UECxMfRGVwYXJ0bWVudCBvZiBIb21lbGFuZCBT\nZWN1cml0eTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEQMA4G\nA1UECxMHREhTIENBNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ6z\n5QKA2hjOSvwVu0SWd/TJsJv2Xd2WN7yTo9OCSPiQ+U89oAE8xlIpo+97mMK3DjwU\n4GdeMP0cdpKarcL7BBSPCK2j1f3o5PNiYU6RDJBR6pgfuvE6LJDAmpKZGcJITnLj\nui25aMAy6dlNX0aNFu2JApB9yDE9VrIODNhZsD6LG4iCa1mATxtGQfIqfZhT/aSN\nnfcbzIddZYvhQlYMF53S9+oAJv21XyHLHO91PW75UteWVxWZvxLfQZmkwzeAxJI3\n7YnpRrHGvtjjeRVgtUKi3wj3CpvRSVLMy05CAKlgsG56vvG3lgkeIoJrwiBV+sY4\nG3aoT7+efJgRnJpxCYcCAwEAAaOCAnYwggJyMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MIGXBgNVHSAEgY8wgYwwDAYKYIZIAWUDAgEDBjAMBgpghkgB\nZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMQ\nMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMnMAwGCmCG\nSAFlAwIBAygwDAYKYIZIAWUDAgEDKTBBBggrBgEFBQcBAQQ1MDMwMQYIKwYBBQUH\nMAKGJWh0dHA6Ly9wa2kudHJlYXN1cnkuZ292L2Roc2NhX2FpYS5wN2MwQQYIKwYB\nBQUHAQsENTAzMDEGCCsGAQUFBzAFhiVodHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi9k\naHNjYV9zaWEucDdjMIHuBgNVHR8EgeYwgeMwNaAzoDGGL2h0dHA6Ly9wa2kudHJl\nYXN1cnkuZ292L1VTX1RyZWFzdXJ5X1Jvb3RfQ0EuY3JsMIGpoIGmoIGjpIGgMIGd\nMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQL\nExpEZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNh\ndGlvbiBBdXRob3JpdGllczEcMBoGA1UECxMTVVMgVHJlYXN1cnkgUm9vdCBDQTEN\nMAsGA1UEAxMEQ1JMMTAfBgNVHSMEGDAWgBRohBVIjFRwfy0SWA7sHHjvPC5ZZDAd\nBgNVHQ4EFgQUfMNKXLofNquDUX304OUOkH8cE0EwDQYJKoZIhvcNAQELBQADggEB\nAFOQwIQWhIzLNbzkya8Z+U7BoFSrsg+aVXT4StNJjdWPCZO5fP6KU9OW2gcHAz/G\nylC65JrbFM6Wo7Zn+rrTrZZvDnd7uyjafeUDnnI4VwPwYrPUQllyru7YC9aZjp6f\nMm8S+MUN69Dpb7NMFHt2876CYRco+q0t/ESN1T+YLrqGAhPjwz1+opTyrhY3NSBR\ntJ8xUzNIcDP34r9td0SXtiidmxX/dDLiGi0YvzD90sSWNAKOANl3MyhIPerCuADF\nqpALUkkY5zTa+ZlPHDf/4pfedZN4cJDpv9X49/RterYIj0cGw8UyWFaObSAOVEBr\nYe+Tz+l0RQ3GVQ8mhpBK2YI=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of Homeland Security/OU=Certification Authorities/OU=DHS CA4\nissuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIISDCCBzCgAwIBAgIESmHSkzANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTEwMTIxMTkx\nMTI4WhcNMjEwMTIxMTk0MTI4WjCBhzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEoMCYGA1UECxMfRGVwYXJ0bWVudCBvZiBIb21lbGFuZCBT\nZWN1cml0eTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEQMA4G\nA1UECxMHREhTIENBNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9y\noWjWI1wi+mcwiSsZE0CA+BxGzGv/tXDgDgxFn9LsQmkskzZFVzXkQatY223ccm3n\njNULVNz4a9gYrBHljFuCkXTXxkOQIMH3X4fcbIge1/133nMbE1U23vvQhrE0qMuI\nvcODETxU/NPsDzLgBxLVsQQ1dr3Z6D+XsWHHAeUbZgCUmRi6Rb5HpaMYda6JRu3U\ntL9v1sCI3/U3MXz8qQEpQwVewrj60OPlfquwmFcDNgaguObjrODpEAIptmpizy7i\nXl6MhfFPk/xnI6h4gPQSNmZBLUYem9X0uvTsugaH2qCDps/47/dGhCUVyNWj0+su\nmcMO7G8tcj7qIXN9EjkCAwEAAaOCBLEwggStMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MGsGA1UdIARkMGIwDAYKYIZIAWUDAgEDBjAMBgpghkgBZQMC\nAQMIMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwG\nCmCGSAFlAwIBAxAwDAYKYIZIAWUDAgEPCDCCARAGCCsGAQUFBwEBBIIBAjCB/zAu\nBggrBgEFBQcwAoYiaHR0cDovL3BraS50cmVhcy5nb3YvZGhzY2FfYWlhLnA3YzCB\nzAYIKwYBBQUHMAKGgb9sZGFwOi8vbGRhcC50cmVhcy5nb3Yvb3U9VVMlMjBUcmVh\nc3VyeSUyMFJvb3QlMjBDQSxvdT1DZXJ0aWZpY2F0aW9uJTIwQXV0aG9yaXRpZXMs\nb3U9RGVwYXJ0bWVudCUyMG9mJTIwdGhlJTIwVHJlYXN1cnksbz1VLlMuJTIwR292\nZXJubWVudCxjPVVTP2NBQ2VydGlmaWNhdGU7YmluYXJ5LGNyb3NzQ2VydGlmaWNh\ndGVQYWlyO2JpbmFyeTCCAQcGCCsGAQUFBwELBIH6MIH3MC4GCCsGAQUFBzAFhiJo\ndHRwOi8vcGtpLnRyZWFzLmdvdi9kaHNjYV9zaWEucDdjMIHEBggrBgEFBQcwBYaB\nt2xkYXA6Ly9zc3BsZGFwLnRyZWFzLmdvdi9vdT1ESFMlMjBDQTQsb3U9Q2VydGlm\naWNhdGlvbiUyMEF1dGhvcml0aWVzLG91PURlcGFydG1lbnQlMjBvZiUyMEhvbWVs\nYW5kJTIwU2VjdXJpdHksbz1VLlMuJTIwR292ZXJubWVudCxjPVVTP2NBQ2VydGlm\naWNhdGU7YmluYXJ5LGNyb3NzQ2VydGlmaWNhdGVQYWlyO2JpbmFyeTCCAaEGA1Ud\nHwSCAZgwggGUMDKgMKAuhixodHRwOi8vcGtpLnRyZWFzLmdvdi9VU19UcmVhc3Vy\neV9Sb290X0NBLmNybDCCAVygggFYoIIBVKSBoDCBnTELMAkGA1UEBhMCVVMxGDAW\nBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0\naGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMx\nHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0ExDTALBgNVBAMTBENSTDGGga5s\nZGFwOi8vbGRhcC50cmVhcy5nb3YvY249Q1JMMSxvdT1VUyUyMFRyZWFzdXJ5JTIw\nUm9vdCUyMENBLG91PUNlcnRpZmljYXRpb24lMjBBdXRob3JpdGllcyxvdT1EZXBh\ncnRtZW50JTIwb2YlMjB0aGUlMjBUcmVhc3VyeSxvPVUuUy4lMjBHb3Zlcm5tZW50\nLGM9VVM/YXV0aG9yaXR5UmV2b2NhdGlvbkxpc3QwHwYDVR0jBBgwFoAUaIQVSIxU\ncH8tElgO7Bx47zwuWWQwHQYDVR0OBBYEFPEkMTZYw4w71ennxfYTMiadq9OpMBkG\nCSqGSIb2fQdBAAQMMAobBFY3LjEDAgCBMA0GCSqGSIb3DQEBCwUAA4IBAQAoYJ/q\nVEu4CTn0OKMIca/Q/ljICwRmWqkArH8oSAZWCRLCbS1vn+fobzywosBCT5JIcqB/\nGLBfadmNl+1Cv52O1iH4eqRodXCmbCF3mqQnjx1S4JNMqsTcs++mEtj36Fj7XZPK\ntW9/BOXEsBybi6LvT8E8qSecFXiruKFeKGLs1ohOjpG3GXOrufcFP9egmVc3yAtN\n2iSzLInIQg4gqChi570Oo82ICpKkK6vxfzzjcOXFzBlG9q7qv9+2oRlnPhKT2ttN\nZ38RX/YNfNklph2zFRfkH/8XhLatdDx7iz4a4KGEx0ytdPynvGUCi4UKeNKU4CpH\niymJUztm6HlPAz0g\n-----END CERTIFICATE-----\n'     # noqa: E501


class EmptyData(Exception):
    pass


class TempFile:
    def __init__(self, data, suffix=None):
        _, self.path = tempfile.mkstemp(suffix=suffix)
        with open(self.path, 'w') as temp_file:
            temp_file.write(data)

    def __del__(self):
        os.remove(self.path)


def insert_id(data: str) -> str:
    return data.replace('{ID}', str(uuid.uuid4()))


def fix_rsa_data(rsa_data: str, count: int) -> str:
    rsa_data = rsa_data.strip().split(' ')
    return '{}\n{}\n{}\n'.format(
        ' '.join(rsa_data[:count]),
        '\n'.join(rsa_data[count:-count]),
        ' '.join(rsa_data[-count:])
    )


class TaxiiClient:
    poll_data = '<taxii_11:Poll_Request\nxmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"\nmessage_id="{ID}"\ncollection_name="{COLLECTION}">\n<taxii_11:Exclusive_Begin_Timestamp>{START_TIME}</taxii_11:Exclusive_Begin_Timestamp>\n<taxii_11:Inclusive_End_Timestamp>{END_TIME}</taxii_11:Inclusive_End_Timestamp>\n<taxii_11:Poll_Parameters allow_asynch="false"></taxii_11:Poll_Parameters>\n</taxii_11:Poll_Request>'   # noqa: E501

    _headers = {
        'Content-Type': 'application/xml',
        'X-TAXII-Accept': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1'
    }

    def __init__(self, pem: str, crt: str, collection: str, base_url: str | None = None,
                 verify: str | bool | None = True):

        self.base_url = base_url.strip('/') if base_url else 'https://taxii.dhs.gov:8443'
        self._pem = TempFile(pem, '.pem')
        self._crt = TempFile(crt, '.crt')
        self.cert = (self._crt.path, self._pem.path)
        self._collection = collection

        if verify:
            self.verify: str | bool | None = os.getenv('SSL_CERT_FILE') or os.getenv('REQUESTS_CA_BUNDLE')
            if not self.verify:
                self._verify = TempFile(CA, '.crt')
                self.verify = self._verify.path
        else:
            urllib3.disable_warnings()
            self.verify = verify

    def _request(self, url: str, data: str) -> str:
        data = data.replace('{COLLECTION}', self._collection)
        return requests.post(
            url,
            data=data.encode('utf-8'),
            headers=self._headers,
            verify=self.verify,
            cert=self.cert
        ).text

    def discovery_request(self) -> dict:
        url = f'{self.base_url}/flare/taxii11/discovery'
        data = '<Discovery_Request xmlns = "http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{ID}"/>'
        data = insert_id(data)
        return parse(self._request(url, data))

    def poll_request(self, start: str, end: str) -> dict:
        url = f'{self.base_url}/flare/taxii11/poll'
        data = insert_id(copy(self.poll_data).replace('{START_TIME}', start).replace('{END_TIME}', end))
        return parse(self._request(url, data)).get("taxii_11:Poll_Response", {})


def safe_data_get(data: dict, keys: Iterable[str] | str, prefix: str = '',
                  default: Any | None = None):
    keys = [keys] if isinstance(keys, str) else keys
    if prefix:
        keys = (':'.join([prefix, x]) for x in keys)
    temp_data = data
    try:
        for key in keys:
            if key not in temp_data:
                raise AttributeError
            temp_data = temp_data[key]
        return temp_data
    except AttributeError:
        return default


class Indicators:

    def __init__(self):
        pass

    @staticmethod
    def _tlp_color_from_header(stix_header: dict) -> str:
        try:
            ais = safe_data_get(stix_header.get('stix:Handling', {}), ['Marking', 'Marking_Structure'], 'marking')
            return safe_data_get(ais, ['Not_Proprietary', 'TLPMarking'], 'AIS').get('@color')
        except AttributeError:
            return ''

    @staticmethod
    def _source_from_header(stix_header: dict) -> str:
        info_source = stix_header.get('stix:Information_Source', {})
        info_source = safe_data_get(info_source, ['Contributing_Sources', 'Source', 'Identity'],
                                    'stixCommon', default={})
        info_source = info_source.get('stix-ciq:Specification', {}).get('xpil:PartyName', {})
        return safe_data_get(info_source, ['OrganisationName', 'NameElement'], 'xnl')

    @staticmethod
    def _indicators(block: dict) -> Iterator[dict]:
        indicator = safe_data_get(block, ['Indicators', 'Indicator'], prefix='stix', default={})
        if isinstance(indicator, list):
            yield from indicator
        else:
            yield indicator

    @staticmethod
    def _create_file_indicator(indicator: dict) -> dict:
        indicator = safe_data_get(indicator, ['FileObj:Hashes', 'cyboxCommon:Hash'])
        value = None
        hash_types = {}
        if not isinstance(indicator, list):
            indicator = [indicator]
        for hash_block in indicator:
            hash_types[safe_data_get(hash_block, ['cyboxCommon:Type', '#text'])] =\
                safe_data_get(hash_block, ['cyboxCommon:Simple_Hash_Value', '#text'])

        for hash_type in ['SHA256', 'MD5', 'SHA1', 'SHA512']:
            if hash_type in hash_types:
                value = hash_types[hash_type]
                break
        return {
            'value': value,
            'type': FeedIndicatorType.File,
            'fields': hash_types
        }

    @staticmethod
    def _create_ip_indicator(indicator: dict) -> dict:
        return {
            'value': safe_data_get(indicator, ['AddressObj:Address_Value', '#text']),
            'type': FeedIndicatorType.IP
        }

    @staticmethod
    def _create_url_indicator(indicator: dict) -> dict:
        return {
            'value': safe_data_get(indicator, ['URIObj:Value', '#text']),
            'type': FeedIndicatorType.URL
        }

    @staticmethod
    def _create_email_indicator(indicator: dict) -> dict:
        email = safe_data_get(indicator, ['Header', 'From'], prefix='EmailMessageObj').get(
            'AddressObj:Address_Value', {})
        if isinstance(email, dict):
            email = email.get('#text', '')
        return {
            'value': email,
            'type': FeedIndicatorType.Email
        }

    @staticmethod
    def _create_domain_indicator(indicator: dict) -> dict:
        return {
            'value': indicator.get('DomainNameObj:Value', {}).get('#text', ''),
            'type': FeedIndicatorType.Domain
        }

    @staticmethod
    def _indicator_data(indicator: dict, source: str, tlp_color: str, tags: list[str] | None = None) -> dict:
        indicator_data = safe_data_get(indicator.get('indicator:Observable', {}), ['Object', 'Properties'], 'cybox')
        if not indicator_data:
            return {}
        fields = {}
        for key, val in [('tags', tags), ('reportedby', source), ('trafficlightprotocol', tlp_color)]:
            if val:
                fields[key] = val
        indicator_type = indicator_data.get('@xsi:type')
        indicator = Indicators._get_indicator_by_type(indicator_type, indicator_data)
        fields.update(indicator.get('fields', {}))
        indicator['fields'] = fields
        return indicator

    @staticmethod
    def _get_indicator_by_type(indicator_type: str, indicator_data: dict) -> dict:
        if indicator_type.startswith('Address'):
            indicator = Indicators._create_ip_indicator(indicator_data)
        elif indicator_type.startswith('File'):
            indicator = Indicators._create_file_indicator(indicator_data)
        elif indicator_type.startswith('URI'):
            indicator = Indicators._create_url_indicator(indicator_data)
        elif indicator_type.startswith('EmailMessage'):
            indicator = Indicators._create_email_indicator(indicator_data)
        elif indicator_type.startswith('DomainName'):
            indicator = Indicators._create_domain_indicator(indicator_data)
        else:
            indicator = {}

        indicator['rawJson'] = indicator_data
        return indicator

    @staticmethod
    def _blocks(data: dict) -> list[dict]:
        blocks = safe_data_get(data, 'Content_Block', 'taxii_11', default=[])
        if not isinstance(blocks, list):
            blocks = [blocks]
        return list(filter(None, (safe_data_get(x, ['taxii_11:Content', 'stix:STIX_Package'], default={}) for x in blocks)))

    @staticmethod
    def indicators_from_data(data: dict, filter_tlp_color: str | None = None,
                             tags: list[str] | None = None) -> Iterator[dict]:
        if int(data.get('taxii_11:Record_Count', 0)) == 0:
            raise EmptyData
        for block in Indicators._blocks(data):
            stix_header = block.get('stix:STIX_Header', {})
            tlp_color = Indicators._tlp_color_from_header(stix_header)

            if filter_tlp_color and filter_tlp_color != tlp_color:
                continue
            source = Indicators._source_from_header(stix_header)
            for indicator in Indicators._indicators(block):
                if ready_indicator := Indicators._indicator_data(indicator, source, tlp_color, tags):
                    yield ready_indicator


def header_transform(header: str) -> str:
    return 'reported by' if header == 'reportedby' else header


def indicator_to_context(indicator: dict) -> dict:
    reported_by = safe_data_get(indicator, ['fields', 'reportedby'], default='')
    context_indicator = {
        'value': indicator.get('value', ''),
        'tlp': safe_data_get(indicator, ['fields', 'trafficlightprotocol'], default=''),
        'type': indicator.get('type', '')
    }
    if reported_by:
        context_indicator['reportedby'] = reported_by
    return context_indicator


def ssl_files_checker(public_key: str, private_key: str):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    x509.load_pem_x509_certificate(public_key.encode('utf-8'), default_backend())
    serialization.load_pem_private_key(private_key.encode('utf-8'), None, default_backend())


def command_test_module(client: TaxiiClient, private_key: str, public_key: str, first_fetch: str):
    ssl_files_checker(public_key, private_key)
    get_first_fetch(first_fetch)
    res = client.discovery_request()
    if safe_data_get(res, ['taxii_11:Discovery_Response', 'taxii_11:Service_Instance']):
        return 'ok'
    elif safe_data_get(res, ['taxii_11:Status_Message', '@status_type']) == 'UNAUTHORIZED':
        raise DemistoException('invalid credential.')
    else:
        raise DemistoException('unknown error.')


def fetch_indicators(client: TaxiiClient, tlp_color: str | None = None, hours_back: str = '24 hours',
                     tags: list[str] | None = None):
    time_field = 'time'
    end = datetime.utcnow()
    start = demisto.getLastRun().get(time_field)
    if start is None:
        start = get_first_fetch(hours_back)
    end = end.strftime(TIME_FORMAT)
    data = client.poll_request(start, end)
    try:
        for b in batch(list(Indicators.indicators_from_data(data, tlp_color, tags)), batch_size=2000):
            demisto.createIndicators(b)
        demisto.setLastRun({time_field: end})
    except EmptyData:
        pass


def get_indicators_results(indicators):
    entry_context = list(map(indicator_to_context, indicators))
    human_readable = tableToMarkdown(name='DHS indicators', t=entry_context,
                                     removeNull=True, headerTransform=header_transform)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='DHS',
        outputs=entry_context,
        raw_response=indicators
    )


def batch_time(start_at: datetime, time_frame_size: int, days: int) -> Iterable[tuple[str, str]]:
    i = 0
    hours = days * 24
    while i * time_frame_size < hours:
        start = (start_at - timedelta(hours=(i + 1) * time_frame_size)).strftime(TIME_FORMAT)
        end = (start_at - timedelta(hours=i * time_frame_size)).strftime(TIME_FORMAT)
        yield start, end
        i += 1


def get_indicators(client: TaxiiClient, tlp_color: str | None = None,
                   limit: int = 20, offset: int = 6, days_back: int = 20,
                   tags: list[str] | None = None):
    t_time = datetime.utcnow()
    all_indicators = {}
    # for over the last {days_back} days using the poll_request(start, end) method
    for start, end in batch_time(t_time, offset, days_back):
        data = client.poll_request(start, end)
        try:
            for indicator in reversed(list(Indicators.indicators_from_data(data, tlp_color, tags))):
                all_indicators[indicator['value']] = indicator
        except EmptyData:
            pass
        if len(all_indicators) >= limit:
            break

    if not all_indicators:
        return CommandResults(readable_output='No results')
    return get_indicators_results(all_indicators.values())


def get_first_fetch(first_fetch_string: str) -> str:
    try:
        first_fetch_date = dateparser.parse(first_fetch_string, settings={'TIMEZONE': 'UTC'})
        assert first_fetch_date is not None, f'could not parse {first_fetch_string}'
        return first_fetch_date.strftime(TIME_FORMAT)
    except ValueError:
        raise DemistoException('first_fetch is not in the correct format (e.g. <number> <time unit>).')


def main():
    params = demisto.params()
    key = fix_rsa_data(
        params.get('key_creds', {}).get('password')
        or params.get('key', ''), 4)
    crt = params.get('crt_creds', {}).get('password') or params.get('crt', '')
    collection = params.get('collection')
    tags = argToList(params['tags']) if params.get('tags') else None
    client = TaxiiClient(key, crt, collection, base_url=params.get('base_url'),
                         verify=argToBoolean(params.get('insecure')))
    command = demisto.command()
    handle_proxy()
    try:
        if command == 'fetch-indicators':
            fetch_indicators(client, hours_back=params.get('first_fetch', ''),
                             tlp_color=params.get('tlp_color'), tags=tags)
        elif command == 'dhs-get-indicators':
            args = demisto.args()
            command_results = get_indicators(client, tlp_color=args.get('tlp_color'), limit=int(args.get('limit', 20)),
                                             tags=params.get('tags'))
            return_results(command_results)
        elif command == 'test-module':
            return_results(command_test_module(client, key, crt, params.get('first_fetch', '')))
        else:
            raise DemistoException('not implemented.')

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
