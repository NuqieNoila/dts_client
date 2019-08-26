"""
Module to confirm the integrity of the timestamped document
"""
from pyasn1.type import univ
from pyasn1.codec.der import decoder
import hashlib
from rfc3161 import TimeStampResp, TSTInfo

TSR_FILE = 'READ_ME__txt.tsr'
FILE = 'READ_ME_.txt'

digest_algorithms = {
    univ.ObjectIdentifier('1.3.14.3.2.26'): 'sha1',
    univ.ObjectIdentifier('1.2.840.113549.2.5'): 'md5',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1'): 'sha256',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.2'): 'sha384',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.3'): 'sha512'
}


def main(tsr: str, file: str):
    """
    :param tsr: Verified timestamp response filepath
    :param file: Original document path
    :return:
    """
    print('Confirming the integrity of original document...')
    try:
        response, _ = decoder.decode(open(tsr, 'rb').read(), asn1Spec=TimeStampResp())

        e_content = response['timeStampToken']['content']['encapContentInfo']['eContent']
        tst_info, _ = decoder.decode(e_content, asn1Spec=TSTInfo())

        if tst_info['messageImprint']['hashAlgorithm']['algorithm'] in digest_algorithms:
            hash_str = digest_algorithms.get(tst_info['messageImprint']['hashAlgorithm']['algorithm'])
        else:
            print(f'The hash algorithm is not listed', str(tst_info['messageImprint']['hashAlgorithm']['algorithm']))
            return False

        hash_tst = tst_info['messageImprint']['hashedMessage']

        hash_obj = hashlib.new(hash_str)

        with open(file, 'rb') as doc:
            hash_obj.update(doc.read())

        print('TSTInfo hashedMessage: ', hash_tst.asOctets().hex())
        print('Hash of original file: ', hash_obj.digest().hex())

        assert hash_tst.asOctets() == hash_obj.digest()
        return True
    except Exception as e:
        print('The file has changed since the date in TSTInfo', e)

        return False


if __name__ == '__main__':
    main(TSR_FILE, FILE)
