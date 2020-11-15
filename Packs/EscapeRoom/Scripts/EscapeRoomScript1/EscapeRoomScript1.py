import rsa

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PRIVATE_KEY = rsa.PrivateKey


def get_key_values():
    return (
        7267245651200808351872044878193676127855460967103831678557765580831038651772452459802256022522947533625496215548708993218278335654344409682891712637483347,
        65537,
        969934505867730757493092093772374156436085220245925441999859247990129164030273608426347632357998515150770869402985522702760924543301536056590844861388209,
        7316977270122926690753071457959022578483121454119769939845634310864677100857163433,
        993203256333023590536020856905136847276072965170279463338530811656757659,
    )


def main(args):
    cipher_base64 = args.get('cipher_text', '')

    nedpq = get_key_values()
    private_key = rsa.PrivateKey(*nedpq)

    try:
        cipher_text = base64.b64decode(cipher_base64)
        plain_text = rsa.decrypt(cipher_text, private_key)
        return_results(plain_text)
    except base64.binascii.Error:
        return_error('failed to parse base64, check your input.')
    except rsa.DecryptionError:
        return_error('failed to decrypt cipher, check your input and private list.')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main(demisto.args())
