from typing import Text, Iterable

from TAXII2ApiModule import *  # noqa: E402
CA = 'issuer=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\nsubject=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\n-----BEGIN CERTIFICATE-----\nMIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\nGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\nAxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw\nMTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu\nbWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s\naWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/\nWq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+\nDuir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl\n4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF\nmCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp\nwX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj\nwOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH\nAQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh\nL2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v\nbGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es\nb3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti\naW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB\nBjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD\nggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi\nTR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+\n7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH\nvenAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl\nDn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ\nA2EC/0rskqTcLe4qNJMHtyznGI8=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n' \
     'issuer=/C=US/O=U.S. Government/OU=FPKI/CN=Federal Common Policy CA\n-----BEGIN CERTIFICATE-----\nMIIGQzCCBSugAwIBAgICZAUwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\nGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\nAxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTE4MDgyOTE0MTg0OVoXDTIx\nMDgyOTE0MTc0NFowgY4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy\nbm1lbnQxIzAhBgNVBAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYD\nVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMRwwGgYDVQQLExNVUyBUcmVh\nc3VyeSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6CQE\nWcyYx3xksWrXOylIx7tY6t+ixCqT0WjWi4PCKkDmauxuGt/pI+9UYdrlou12AGkE\n1Uzyv8QbaIVRrgenONkKs1IRNp8igd4ESHe+qK+y8XgurMRYh1CGAgx7N2gInWJN\ntQm38RZz2wToRumIkyXI2m2jqIwh38bXNlgg2632jBKAIpdY9ONCi33R9H65f1bv\nujG8SewSrwiAueKXYmB/74P5Y97rcG6rxE8PNBKmy60mQ8uPA8bzniQeKoOwauYp\n/1cesW5fT0DVQrWq1bRR5LJ7Wwb8gqLMsRa/PkTHo2S3gvZoctvm/nth2/6udXbM\n3GxS2bwHqDlm64+aywIDAQABo4IC3TCCAtkwDwYDVR0TAQH/BAUwAwEB/zCBswYD\nVR0gBIGrMIGoMAwGCmCGSAFlAwIBAwEwDAYKYIZIAWUDAgEDAjAMBgpghkgBZQMC\nAQMGMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDCDAMBgpghkgBZQMCAQMkMAwG\nCmCGSAFlAwIBAw0wDAYKYIZIAWUDAgEDEDAMBgpghkgBZQMCAQMRMAwGCmCGSAFl\nAwIBAycwDAYKYIZIAWUDAgEDKDAMBgpghkgBZQMCAQMpME8GCCsGAQUFBwEBBEMw\nQTA/BggrBgEFBQcwAoYzaHR0cDovL2h0dHAuZnBraS5nb3YvZmNwY2EvY2FDZXJ0\nc0lzc3VlZFRvZmNwY2EucDdjMIHbBgNVHSEEgdMwgdAwGAYKYIZIAWUDAgEDAQYK\nYIZIAWUDAgEFAjAYBgpghkgBZQMCAQMCBgpghkgBZQMCAQUDMBgGCmCGSAFlAwIB\nAwYGCmCGSAFlAwIBAwYwGAYKYIZIAWUDAgEDBgYKYIZIAWUDAgEFBzAYBgpghkgB\nZQMCAQMHBgpghkgBZQMCAQMHMBgGCmCGSAFlAwIBAwcGCmCGSAFlAwIBBQQwGAYK\nYIZIAWUDAgEDEAYKYIZIAWUDAgEDEDAYBgpghkgBZQMCAQMQBgpghkgBZQMCAQUF\nMEAGCCsGAQUFBwELBDQwMjAwBggrBgEFBQcwBYYkaHR0cDovL3BraS50cmVhc3Vy\neS5nb3Yvcm9vdF9zaWEucDdjMAwGA1UdJAQFMAOBAQAwCgYDVR02BAMCAQAwDgYD\nVR0PAQH/BAQDAgEGMB8GA1UdIwQYMBaAFK0MenVc5fOYxHmYDqwo/Zf05wL8MDUG\nA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNhL2ZjcGNh\nLmNybDAdBgNVHQ4EFgQUaIQVSIxUcH8tElgO7Bx47zwuWWQwDQYJKoZIhvcNAQEL\nBQADggEBAGkNU1Q6y2uhdE4RfMMdS68yh3xjANrACzGLHbIBumpK0AOLtunuig7/\nddTtou5rCOPxPGomiInu5HxhG9J+g+T90acXFg+67XuSIrQtDYRkrMr/9AKtHwGn\nzVYy5U92gk2nAS1RD6tW0WB/ava2qTZR/kH9deOtp0AgUZDRLV7AigXLSVaK99nQ\ngYQO2PW4f7Trl2jwvxTmV9jb/wo96KtJmpAGYeK8DscJHqmtOk83225UEPS1Sfqj\nQVbvYbkCG+GvvMwFUn87aQN0EcCnRIN4Z6SksmfPTtN6Viw585vpzrJhKZoqVvvG\nkBGaMG3CZwgMqK1yrPo3waYtA+/Ns+8=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n' \
     'issuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIHfzCCBmegAwIBAgIEVw0sATANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTYwNzEzMTMw\nMzI2WhcNMjYwODA1MTQ0NjMwWjCBjjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1\ncnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxHDAaBgNVBAsT\nE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDsPmfNCAYlZsDMUIy/nHudvttnURFsoYR8pUuDtdZPzFOwvwJoi2V1a1MY\nbBuOJMf6xsuaTX2OR8JDtCHKKkwcN+YXEQBr9pNzbydaq5P86a3XIS6dfapArtcD\njaAZgtF+SNxXzCv+BweJ5AMRFQpRJg+j95yvN9wntLvFGkgqqIE+UPmaxYmMEcGy\nBla8ym9Pa1m45TecrjuhDcU1m0dSJSRhS1CJ4xHCTxNDxjR91n6vAnFZOjjgtQmn\niFc+C11JJ74MUMm/6V7w1y/PDVwfyUnyyM+MW8UKN5ZVlUWEML8dHYGqcLu+pxID\nJYLCwho01+fXWSu4sx/ztJR2orBZ4sf7Ek6HmyUpX3X6l57sepRghrA7dssJ4dnZ\nNdB+g3fufbbgh4WDOlHa3h9VEuVhh5m4XFFvi8icIgUzC+Wais5eK1UJ9pl3vVaz\n0Yo7dKDe6v2w28qAF4TsDiablsRVEFLQamj6zov2N1Q9i+vNXVtHHV/gh8jC5JvG\nX3cyfUkss0U9LWcAeFE5zU3NN//VqedWc9a3j3G8l94qYVqDCQwq/fAWprRQcX1M\n7xNhw7mO547B+Idjp70BISVPR6/laTeRqg/nA9Z4/xGGS3UecP2m6K2ACJQ0ewSi\nXuix6ahFB2XOaDmNkTfToobPCNuA11fhA3yIan++3euD7SwVWQIDAQABo4IC4TCC\nAt0wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wSwYIKwYBBQUHAQEE\nPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi9jYWNlcnRz\naXNzdWVkdG90cmNhLnA3YzBABggrBgEFBQcBCwQ0MDIwMAYIKwYBBQUHMAWGJGh0\ndHA6Ly9wa2kudHJlYXN1cnkuZ292L3Jvb3Rfc2lhLnA3YzCB+QYDVR0gBIHxMIHu\nMAwGCmCGSAFlAwIBAwYwDAYKYIZIAWUDAgEDBzAMBgpghkgBZQMCAQMIMAwGCmCG\nSAFlAwIBAw0wDAYKYIZIAWUDAgEDEDAMBgpghkgBZQMCAQMRMAwGCmCGSAFlAwIB\nAyQwDAYKYIZIAWUDAgEDJzAMBgpghkgBZQMCAQMoMAwGCmCGSAFlAwIBAykwDAYK\nYIZIAWUDAgEFAjAMBgpghkgBZQMCAQUDMAwGCmCGSAFlAwIBBQQwDAYKYIZIAWUD\nAgEFBzAMBgpghkgBZQMCAQUKMAwGCmCGSAFlAwIBBQswDAYKYIZIAWUDAgEFDDAf\nBgNVHSMEGDAWgBRohBVIjFRwfy0SWA7sHHjvPC5ZZDAdBgNVHQ4EFgQUF0u4Jrpp\neq0SUFdFMZ5Xu3Sl2i8wge4GA1UdHwSB5jCB4zCBqaCBpqCBo6SBoDCBnTELMAkG\nA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVw\nYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24g\nQXV0aG9yaXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0ExDTALBgNV\nBAMTBENSTDEwNaAzoDGGL2h0dHA6Ly9wa2kudHJlYXN1cnkuZ292L1VTX1RyZWFz\ndXJ5X1Jvb3RfQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQA2/JRVLMwhdhyhlNG5\nBwbSsk9+OpFvOXncyGIxHyHpLxi0ddgFZN2DIu1+bnRCfw3PR8nZ6/lcMRZwyXT8\nQI0rjNEOr5DplepWY/JfYwk+bjmVq7UCQZjT2cIQgcmLRjc/euOejoEga0FsENXK\nAhcKU/4VO8aq/xE4tllvsfjboHCACFn2e97j6j1lNtZfA4RxXZ0xIkIzcVFoeh/g\n5tqB7FjsFpXKnvKUTr3ZgrINSBc8zCh12QyToHwgAUcIQK0GGnWxOo3QHB2RuRXK\nVtb2b1AtmWAaiJbM008+FzF/quvpvBJcqqo5nc3laNGgvkCNzQfM/KJ7WITaOe0g\ndqOC\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n' \
     'issuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIHgDCCBWigAwIBAgIEVw0sADANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMDYwODA1MTQx\nNjMwWhcNMjYwODA1MTQ0NjMwWjCBjjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1\ncnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxHDAaBgNVBAsT\nE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDoJARZzJjHfGSxatc7KUjHu1jq36LEKpPRaNaLg8IqQOZq7G4a3+kj71Rh\n2uWi7XYAaQTVTPK/xBtohVGuB6c42QqzUhE2nyKB3gRId76or7LxeC6sxFiHUIYC\nDHs3aAidYk21CbfxFnPbBOhG6YiTJcjabaOojCHfxtc2WCDbrfaMEoAil1j040KL\nfdH0frl/Vu+6MbxJ7BKvCIC54pdiYH/vg/lj3utwbqvETw80EqbLrSZDy48DxvOe\nJB4qg7Bq5in/Vx6xbl9PQNVCtarVtFHksntbBvyCosyxFr8+RMejZLeC9mhy2+b+\ne2Hb/q51dszcbFLZvAeoOWbrj5rLAgMBAAGjggLiMIIC3jAOBgNVHQ8BAf8EBAMC\nAQYwDwYDVR0TAQH/BAUwAwEB/zBLBggrBgEFBQcBAQQ/MD0wOwYIKwYBBQUHMAKG\nL2h0dHA6Ly9wa2kudHJlYXN1cnkuZ292L2NhY2VydHNpc3N1ZWR0b3RyY2EucDdj\nMEAGCCsGAQUFBwELBDQwMjAwBggrBgEFBQcwBYYkaHR0cDovL3BraS50cmVhc3Vy\neS5nb3Yvcm9vdF9zaWEucDdjMIH5BgNVHSAEgfEwge4wDAYKYIZIAWUDAgEDBjAM\nBgpghkgBZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDDTAMBgpghkgB\nZQMCAQMQMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMn\nMAwGCmCGSAFlAwIBAygwDAYKYIZIAWUDAgEDKTAMBgpghkgBZQMCAQUCMAwGCmCG\nSAFlAwIBBQMwDAYKYIZIAWUDAgEFBDAMBgpghkgBZQMCAQUHMAwGCmCGSAFlAwIB\nBQowDAYKYIZIAWUDAgEFCzAMBgpghkgBZQMCAQUMMB8GA1UdIwQYMBaAFBdLuCa6\naXqtElBXRTGeV7t0pdovMB0GA1UdDgQWBBRohBVIjFRwfy0SWA7sHHjvPC5ZZDCB\n7wYDVR0fBIHnMIHkMIGpoIGmoIGjpIGgMIGdMQswCQYDVQQGEwJVUzEYMBYGA1UE\nChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLExpEZXBhcnRtZW50IG9mIHRoZSBU\ncmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEcMBoG\nA1UECxMTVVMgVHJlYXN1cnkgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTA2oDSgMoYw\naHR0cDovL3BraS50cmVhc3VyeS5nb3YvVVNfVHJlYXN1cnlfUm9vdF9DQTEuY3Js\nMA0GCSqGSIb3DQEBCwUAA4ICAQDkJPyJSS87CAuaDXkdJFGsLkgQOrDxCJpNgD1Z\nQ1RmAbBwpO8x94m00gjE2uN9Gj/ezADsK0Yu9z83XdAl/6706GJ3bChBy/0m2xeB\ni/oYhhkXB17Sc2a8O8gA8DLm3bXqvO3T32pVJnyXj/ckUU1P424zQjqhj5d+/xs/\nM96a/jiFc7pFAE4lCBI6ydDeUNBZgRleX9R7Bp23/Uygd59wzEZ0Jvu2ls9x1bBG\nqtp71PsGRhKyU64XFEKTaNknye/0TqRdTqpWzH6foTBjptYvn08cZmGVQNientSb\nqWk+pvgxJtM9piiGDlUaPcizdnL5O3xVfjwYQNRteVPwXepkBSl9yPIG49yknUcH\nfj0S2NCQy1OYqhy+oFYr+2aJG0CON5LFrwkaUU0bvRAXpW33hqN5/+8cApccXAeh\nD42+gKVr+M/vNJGat46KKX6PF1ZflFfrE7jxD3Jza0N4dTXDRCagj30QmegziIA2\nvylt+7jH7FHUVvOfTZaHMqvyZfc9dFKYpqJKrFEaMv6Fqawejir8kF9CUpSAF2O7\nA843vFQuVRgIwp1M+D4xnvxnLbehLzqEZ6ZSSIPoHXzitfz9/oycCfUbIyYE4TW9\n8wEwfpj4wCO1Gldl+2rZYUEb5mjkkltR1O8s5rYqoxVSVKUrAD/fHYdOzteWkNQk\nyiTo/Q==\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of Homeland Security/OU=Certification Authorities/OU=DHS CA4\n' \
     'issuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIGDTCCBPWgAwIBAgIETjmBKDANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTUwNjEzMTQz\nNTA0WhcNMjUwNjEzMTUwNTA0WjCBhzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEoMCYGA1UECxMfRGVwYXJ0bWVudCBvZiBIb21lbGFuZCBT\nZWN1cml0eTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEQMA4G\nA1UECxMHREhTIENBNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ6z\n5QKA2hjOSvwVu0SWd/TJsJv2Xd2WN7yTo9OCSPiQ+U89oAE8xlIpo+97mMK3DjwU\n4GdeMP0cdpKarcL7BBSPCK2j1f3o5PNiYU6RDJBR6pgfuvE6LJDAmpKZGcJITnLj\nui25aMAy6dlNX0aNFu2JApB9yDE9VrIODNhZsD6LG4iCa1mATxtGQfIqfZhT/aSN\nnfcbzIddZYvhQlYMF53S9+oAJv21XyHLHO91PW75UteWVxWZvxLfQZmkwzeAxJI3\n7YnpRrHGvtjjeRVgtUKi3wj3CpvRSVLMy05CAKlgsG56vvG3lgkeIoJrwiBV+sY4\nG3aoT7+efJgRnJpxCYcCAwEAAaOCAnYwggJyMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MIGXBgNVHSAEgY8wgYwwDAYKYIZIAWUDAgEDBjAMBgpghkgB\nZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMQ\nMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMnMAwGCmCG\nSAFlAwIBAygwDAYKYIZIAWUDAgEDKTBBBggrBgEFBQcBAQQ1MDMwMQYIKwYBBQUH\nMAKGJWh0dHA6Ly9wa2kudHJlYXN1cnkuZ292L2Roc2NhX2FpYS5wN2MwQQYIKwYB\nBQUHAQsENTAzMDEGCCsGAQUFBzAFhiVodHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi9k\naHNjYV9zaWEucDdjMIHuBgNVHR8EgeYwgeMwNaAzoDGGL2h0dHA6Ly9wa2kudHJl\nYXN1cnkuZ292L1VTX1RyZWFzdXJ5X1Jvb3RfQ0EuY3JsMIGpoIGmoIGjpIGgMIGd\nMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQL\nExpEZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNh\ndGlvbiBBdXRob3JpdGllczEcMBoGA1UECxMTVVMgVHJlYXN1cnkgUm9vdCBDQTEN\nMAsGA1UEAxMEQ1JMMTAfBgNVHSMEGDAWgBRohBVIjFRwfy0SWA7sHHjvPC5ZZDAd\nBgNVHQ4EFgQUfMNKXLofNquDUX304OUOkH8cE0EwDQYJKoZIhvcNAQELBQADggEB\nAFOQwIQWhIzLNbzkya8Z+U7BoFSrsg+aVXT4StNJjdWPCZO5fP6KU9OW2gcHAz/G\nylC65JrbFM6Wo7Zn+rrTrZZvDnd7uyjafeUDnnI4VwPwYrPUQllyru7YC9aZjp6f\nMm8S+MUN69Dpb7NMFHt2876CYRco+q0t/ESN1T+YLrqGAhPjwz1+opTyrhY3NSBR\ntJ8xUzNIcDP34r9td0SXtiidmxX/dDLiGi0YvzD90sSWNAKOANl3MyhIPerCuADF\nqpALUkkY5zTa+ZlPHDf/4pfedZN4cJDpv9X49/RterYIj0cGw8UyWFaObSAOVEBr\nYe+Tz+l0RQ3GVQ8mhpBK2YI=\n-----END CERTIFICATE-----\n\nsubject=/C=US/O=U.S. Government/OU=Department of Homeland Security/OU=Certification Authorities/OU=DHS CA4\n' \
     'issuer=/C=US/O=U.S. Government/OU=Department of the Treasury/OU=Certification Authorities/OU=US Treasury Root CA\n-----BEGIN CERTIFICATE-----\nMIIISDCCBzCgAwIBAgIESmHSkzANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\nVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVu\ndCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9y\naXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTEwMTIxMTkx\nMTI4WhcNMjEwMTIxMTk0MTI4WjCBhzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu\nUy4gR292ZXJubWVudDEoMCYGA1UECxMfRGVwYXJ0bWVudCBvZiBIb21lbGFuZCBT\nZWN1cml0eTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEQMA4G\nA1UECxMHREhTIENBNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9y\noWjWI1wi+mcwiSsZE0CA+BxGzGv/tXDgDgxFn9LsQmkskzZFVzXkQatY223ccm3n\njNULVNz4a9gYrBHljFuCkXTXxkOQIMH3X4fcbIge1/133nMbE1U23vvQhrE0qMuI\nvcODETxU/NPsDzLgBxLVsQQ1dr3Z6D+XsWHHAeUbZgCUmRi6Rb5HpaMYda6JRu3U\ntL9v1sCI3/U3MXz8qQEpQwVewrj60OPlfquwmFcDNgaguObjrODpEAIptmpizy7i\nXl6MhfFPk/xnI6h4gPQSNmZBLUYem9X0uvTsugaH2qCDps/47/dGhCUVyNWj0+su\nmcMO7G8tcj7qIXN9EjkCAwEAAaOCBLEwggStMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MGsGA1UdIARkMGIwDAYKYIZIAWUDAgEDBjAMBgpghkgBZQMC\nAQMIMAwGCmCGSAFlAwIBAwcwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwG\nCmCGSAFlAwIBAxAwDAYKYIZIAWUDAgEPCDCCARAGCCsGAQUFBwEBBIIBAjCB/zAu\nBggrBgEFBQcwAoYiaHR0cDovL3BraS50cmVhcy5nb3YvZGhzY2FfYWlhLnA3YzCB\nzAYIKwYBBQUHMAKGgb9sZGFwOi8vbGRhcC50cmVhcy5nb3Yvb3U9VVMlMjBUcmVh\nc3VyeSUyMFJvb3QlMjBDQSxvdT1DZXJ0aWZpY2F0aW9uJTIwQXV0aG9yaXRpZXMs\nb3U9RGVwYXJ0bWVudCUyMG9mJTIwdGhlJTIwVHJlYXN1cnksbz1VLlMuJTIwR292\nZXJubWVudCxjPVVTP2NBQ2VydGlmaWNhdGU7YmluYXJ5LGNyb3NzQ2VydGlmaWNh\ndGVQYWlyO2JpbmFyeTCCAQcGCCsGAQUFBwELBIH6MIH3MC4GCCsGAQUFBzAFhiJo\ndHRwOi8vcGtpLnRyZWFzLmdvdi9kaHNjYV9zaWEucDdjMIHEBggrBgEFBQcwBYaB\nt2xkYXA6Ly9zc3BsZGFwLnRyZWFzLmdvdi9vdT1ESFMlMjBDQTQsb3U9Q2VydGlm\naWNhdGlvbiUyMEF1dGhvcml0aWVzLG91PURlcGFydG1lbnQlMjBvZiUyMEhvbWVs\nYW5kJTIwU2VjdXJpdHksbz1VLlMuJTIwR292ZXJubWVudCxjPVVTP2NBQ2VydGlm\naWNhdGU7YmluYXJ5LGNyb3NzQ2VydGlmaWNhdGVQYWlyO2JpbmFyeTCCAaEGA1Ud\nHwSCAZgwggGUMDKgMKAuhixodHRwOi8vcGtpLnRyZWFzLmdvdi9VU19UcmVhc3Vy\neV9Sb290X0NBLmNybDCCAVygggFYoIIBVKSBoDCBnTELMAkGA1UEBhMCVVMxGDAW\nBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0\naGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMx\nHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0ExDTALBgNVBAMTBENSTDGGga5s\nZGFwOi8vbGRhcC50cmVhcy5nb3YvY249Q1JMMSxvdT1VUyUyMFRyZWFzdXJ5JTIw\nUm9vdCUyMENBLG91PUNlcnRpZmljYXRpb24lMjBBdXRob3JpdGllcyxvdT1EZXBh\ncnRtZW50JTIwb2YlMjB0aGUlMjBUcmVhc3VyeSxvPVUuUy4lMjBHb3Zlcm5tZW50\nLGM9VVM/YXV0aG9yaXR5UmV2b2NhdGlvbkxpc3QwHwYDVR0jBBgwFoAUaIQVSIxU\ncH8tElgO7Bx47zwuWWQwHQYDVR0OBBYEFPEkMTZYw4w71ennxfYTMiadq9OpMBkG\nCSqGSIb2fQdBAAQMMAobBFY3LjEDAgCBMA0GCSqGSIb3DQEBCwUAA4IBAQAoYJ/q\nVEu4CTn0OKMIca/Q/ljICwRmWqkArH8oSAZWCRLCbS1vn+fobzywosBCT5JIcqB/\nGLBfadmNl+1Cv52O1iH4eqRodXCmbCF3mqQnjx1S4JNMqsTcs++mEtj36Fj7XZPK\ntW9/BOXEsBybi6LvT8E8qSecFXiruKFeKGLs1ohOjpG3GXOrufcFP9egmVc3yAtN\n2iSzLInIQg4gqChi570Oo82ICpKkK6vxfzzjcOXFzBlG9q7qv9+2oRlnPhKT2ttN\nZ38RX/YNfNklph2zFRfkH/8XhLatdDx7iz4a4KGEx0ytdPynvGUCi4UKeNKU4CpH\niymJUztm6HlPAz0g\n-----END CERTIFICATE-----\n'     # noqa: E501


def fix_rsa_data(rsa_data: str, count: int) -> str:
    rsa_data = rsa_data.strip().split(' ')
    return '{}\n{}\n{}\n'.format(
        ' '.join(rsa_data[:count]),
        '\n'.join(rsa_data[count:-count]),
        ' '.join(rsa_data[-count:])
    )


def safe_data_get(data: Dict, keys: Union[Iterable[Text], Text], prefix: str = '',
                  default: Optional[Any] = None):
    keys = [keys] if isinstance(keys, Text) else keys
    if prefix:
        keys = map(lambda x: ':'.join([prefix, x]), keys)
    temp_data = data
    try:
        for key in keys:
            if key not in temp_data:
                raise AttributeError
            temp_data = temp_data[key]
        return temp_data
    except AttributeError:
        return default


def header_transform(header: str) -> str:
    return 'reported by' if header == 'reportedby' else header


def indicator_to_context(indicator: Dict) -> Dict:
    reported_by = safe_data_get(indicator, ['fields', 'reportedby'], default='')
    context_indicator = {
        'value': indicator.get('value', ''),
        'tlp': safe_data_get(indicator, ['fields', 'trafficlightprotocol'], default=''),
        'type': indicator.get('type', '')
    }
    if reported_by:
        context_indicator['reportedby'] = reported_by
    return context_indicator


def command_test_module(client: Taxii2FeedClient, first_fetch: str):
    if client.collections:
        get_first_fetch(first_fetch)
        return 'ok'
    else:
        return 'Could not connect to server'


def fetch_indicators_command(client: Taxii2FeedClient, last_run_ctx: Dict, tlp_color: Optional[str] = None,
                             initial_interval: str = '24 hours') -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param (Optional) tlp_color: Traffic Light Protocol Color to filter by
    :param initial_interval: initial interval in parse_date_range format
    :return: indicators in cortex TIM format
    """
    if initial_interval:
        initial_interval = get_first_fetch(initial_interval)

    if client.collection_to_fetch:
        indicators, last_run_ctx = fetch_one_collection(client, initial_interval, last_run_ctx)
    else:
        indicators, last_run_ctx = fetch_all_collections(client, initial_interval, last_run_ctx)

    if tlp_color:
        indicators = filter_indicators_by_tlp_color(indicators, tlp_color)

    return indicators, last_run_ctx


def fetch_one_collection(client: Taxii2FeedClient, initial_interval: str, last_run_ctx: Dict):
    last_fetch_time = last_run_ctx.get(client.collection_to_fetch.id)
    added_after = last_fetch_time or initial_interval

    indicators = client.build_iterator(added_after=added_after)
    last_run_ctx[client.collection_to_fetch.id] = (
        client.last_fetched_indicator__modified
        if client.last_fetched_indicator__modified
        else added_after
    )
    return indicators, last_run_ctx


def fetch_all_collections(client: Taxii2FeedClient, initial_interval: str, last_run_ctx: Dict):
    if client.collections is None:
        raise DemistoException(ERR_NO_COLL)
    indicators: list = []
    for collection in client.collections:
        client.collection_to_fetch = collection
        added_after = last_run_ctx.get(collection.id) or initial_interval
        fetched_iocs = client.build_iterator(added_after=added_after)
        indicators.extend(fetched_iocs)
        last_run_ctx[collection.id] = client.last_fetched_indicator__modified
    return indicators, last_run_ctx


def get_indicators_results(indicators: List[Dict]):
    entry_context = list(map(indicator_to_context, indicators))
    human_readable = tableToMarkdown(name='DHS indicators', t=entry_context,
                                     removeNull=True, headerTransform=header_transform)
    return CommandResults(
        readable_output=f"Found {len(indicators)} results:\n" + human_readable,
        outputs_prefix='DHS',
        outputs=entry_context,
        raw_response=indicators
    )


def get_indicators_command(client: Taxii2FeedClient, limit: int = 20, added_after: str = '20 days',
                           tlp_color: Optional[str] = None):
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param (Optional) added_after: added after time string in parse_date_range format
    :param (Optional) tlp_color: Traffic Light Protocol Color to filter by
    :return: indicators in cortex TIM format
    """
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)

    if client.collection_to_fetch is None:
        # fetch all collections
        if client.collections is None:
            raise DemistoException(ERR_NO_COLL)
        indicators: list = []
        for collection in client.collections:
            client.collection_to_fetch = collection
            fetched_iocs = client.build_iterator(limit, added_after=added_after)
            indicators.extend(fetched_iocs)
            if limit >= 0:
                limit -= len(fetched_iocs)
                if limit <= 0:
                    break

    else:
        indicators = client.build_iterator(limit, added_after=added_after)

    if tlp_color:
        indicators = filter_indicators_by_tlp_color(indicators, tlp_color)

    if not indicators:
        return CommandResults(readable_output='No results')

    # return get_indicators_results(indicators) # todo check if done in load_stix_objects_from_envelope
    return CommandResults(
        readable_output=f"Found {len(indicators)} results:\n" + tableToMarkdown(name='DHS indicators',
                                                                                t=indicators, removeNull=True),
        outputs_prefix='DHS',
        outputs=indicators,
        raw_response=indicators
    )


def filter_indicators_by_tlp_color(indicators: List[Dict], tlp_color: str):
    # todo check if indicators need to be filtered by tlp_color, or tlp_color needs to be added to indicators
    return [indicator for indicator in indicators if indicator["fields"].get('trafficlightprotocol') == tlp_color]


def get_first_fetch(first_fetch_string: str) -> str:
    try:
        first_fetch_date = dateparser.parse(first_fetch_string, settings={'TIMEZONE': 'UTC'})
        assert first_fetch_date is not None, f'could not parse {first_fetch_string}'
        return first_fetch_date.strftime(TAXII_TIME_FORMAT_NO_MS)
    except ValueError:
        raise DemistoException('first_fetch is not in the correct format (e.g. <number> <time unit>).')


def build_client(base_url, collection, crt, key, proxies, tags, verify_certificate: Union[str, bool]):
    try:
        if not verify_certificate:
            demisto.debug(f'{verify_certificate=}, setting it with env vars')
            verify_certificate = os.getenv('SSL_CERT_FILE') or os.getenv('REQUESTS_CA_BUNDLE')
            if not verify_certificate:
                demisto.debug(f'{verify_certificate=}, setting it with default certificate')
                verify_certificate = Taxii2FeedClient.build_certificate(CA)
        else:
            demisto.debug(f'{verify_certificate=}, running disable_warnings')
            urllib3.disable_warnings()

        client = Taxii2FeedClient(url=base_url,
                                  collection_to_fetch=collection,
                                  proxies=proxies,
                                  verify=verify_certificate,
                                  objects_to_fetch=['indicator'],
                                  tags=tags,
                                  certificate=crt,
                                  key=key)
        client.initialise()

    except Exception as error:
        demisto.debug(f'Got error with given/default certificate, trying with fix_rsa_data on key. {error=}')
        key = fix_rsa_data(key, 4)
        client = Taxii2FeedClient(url=base_url,
                                  collection_to_fetch=collection,
                                  proxies=proxies,
                                  verify=verify_certificate,
                                  objects_to_fetch=['indicator'],
                                  tags=tags,
                                  certificate=crt,
                                  key=key)
        client.initialise()
        demisto.debug(f'fix_rsa_data on key worked, proceeding')

    return client


def main():
    params = demisto.params()
    key = params.get('key', {}).get('password')
    crt = params.get('crt', '')
    collection = params.get('collection')
    tags = argToList(params['tags']) if params.get('tags') else None
    base_url = params.get('base_url', 'https://ais2.cisa.dhs.gov')
    verify_certificate = not params.get('insecure', False)
    tlp_color = params.get('tlp_color')
    proxies = handle_proxy()

    try:
        client = build_client(base_url, collection, crt, key, proxies, tags, verify_certificate)

        command = demisto.command()
        demisto.info(f"Command being called in {CONTEXT_PREFIX} is {command}")

        if command == 'fetch-indicators':
            last_run_indicators = get_feed_last_run()
            indicators, last_run_indicators = fetch_indicators_command(client,
                                                                       last_run_ctx=last_run_indicators,
                                                                       tlp_color=tlp_color,
                                                                       initial_interval=params.get('first_fetch', '24 hours'))
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            set_feed_last_run(last_run_indicators)

        elif command == 'dhs-get-indicators':
            args = demisto.args()
            limit: int = arg_to_number(args.get('limit', 20))  # type: ignore
            command_results = get_indicators_command(client, limit=limit, tlp_color=tlp_color)
            return_results(command_results)

        elif command == 'test-module':
            return_results(command_test_module(client, params.get('first_fetch', '')))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
