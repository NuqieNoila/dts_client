"""
Module to parse and verify timestamp response
"""
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, useful
from pyasn1_modules import pem, rfc2459
import hashlib
import OpenSSL
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA1 as SHA1
import Crypto.Signature.pkcs1_15 as crypto_signature
import logging

from rfc3161 import TSTInfo, PKIStatusInfo
from rfc3161 import TimeStampResp, TimeStampReq, SigningCertificate, SigningCertificateV2

TSQ_FILE = 'READ_ME__txt.tsq'
TSR_FILE = 'READ_ME__txt.tsr'
TSACERT = 'tsa.crt'
CACERT = 'cacert.pem'

id_contentType = univ.ObjectIdentifier('1.2.840.113549.1.9.3')
id_messageDigest = univ.ObjectIdentifier('1.2.840.113549.1.9.4')
id_signingTime = univ.ObjectIdentifier('1.2.840.113549.1.9.5')
id_aa_signingCertificate = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.12')
id_aa_signingCertificateV2 = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.47')
id_kp_timeStamping = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.8')

digest_algorithm = {
    univ.ObjectIdentifier('1.3.14.3.2.26'): 'sha1',
    univ.ObjectIdentifier('1.2.840.113549.2.5'): 'md5',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1'): 'sha256',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.2'): 'sha384',
    univ.ObjectIdentifier('2.16.840.1.101.3.4.2.3'): 'sha512'
}

GenTime = None


def check_status(status: PKIStatusInfo):
    """
    Verify the status of TimeStampResp

    """
    if status['status'] > univ.Integer('1'):
        text = str(status['statusString'][0])
        logging.error(f'TimeStampResp Status: Failure, {text}\n')
        return False
    else:
        logging.info('TimeStampResp Status: Success\n')
        return True


def check_TSTInfo(tst_info: TSTInfo, request: TimeStampReq):
    """
    Verify the fields within TSTInfo
    """
    logging.info('Checking TSTInfo...')
    logging.info('\n' + str(tst_info))
    global GenTime
    try:
        assert tst_info['version'] == univ.Integer(1)
        assert tst_info['policy'].isValue
        if request['reqPolicy'].isValue:
            assert tst_info['policy'] == request['reqPolicy']
        assert tst_info['messageImprint'] == request['messageImprint']
        logging.info('TSTInfo hashedMessage:\t\t' + str(tst_info['messageImprint']['hashedMessage'].asOctets().hex()))
        logging.info('TSTRequest hashedMessage:\t' + str(request['messageImprint']['hashedMessage'].asOctets().hex()))
        # TODO: check genTime, accuracy, ignore now
        GenTime = tst_info['genTime']
        # TODO: check ordering, ignore now
        if request['nonce'].isValue:
            assert tst_info['nonce'].isValue
            assert tst_info['nonce'] == request['nonce']
            logging.info('TSTInfo nonce:\t' + str(tst_info['nonce']))
            logging.info('TSRequest nonce:\t' + str(request['nonce']))
    except Exception as e:
        logging.error('Check TSTInfo: Failure\n', exc_info=True)
        raise e
    logging.info('Check TSTInfo: Success\n')
    return True


def check_content_type(attr_value, econt_type):
    """
    Verify content type attribute
    """
    logging.info('Attribute Content Type')
    try:
        en_econt_type = encoder.encode(econt_type)
        logging.info('\tAttribute Value:\t\t' + str(attr_value.asOctets().hex()))
        logging.info('\tEncoded eContentType:\t' + str(en_econt_type.hex()))
        assert attr_value.asOctets() == en_econt_type
    except Exception as e:
        logging.error('Check Attribute Content Type: Failure, ', exc_info=True)
        raise e
    logging.info('Check Attribute Content Type: Success\n')
    return True


def check_message_digest(attr_value, raw_econt, hash_oid: univ.ObjectIdentifier):
    """
    Verify message digest attribute
    """
    logging.info('Attribute Message Digest')
    try:
        if hash_oid in digest_algorithm:
            hash_str = digest_algorithm.get(hash_oid)
        else:
            logging.error(f'{str(hash_oid)} is not available in the list of hash algorithms')
            return False
        hash_object = hashlib.new(hash_str)
        hash_object.update(raw_econt)
        encode_raw = encoder.encode(hash_object.digest(), asn1Spec=univ.OctetString())
        logging.info('\tAttribute Value:\t\t\t' + str(attr_value.hex()))
        logging.info('\tEncoded Digest of eContent:\t' + str(encode_raw.hex()))
        assert attr_value == encode_raw
    except Exception as e:
        logging.error('Check Attribute Message Digest: Failure', exc_info=True)
        raise e
    logging.info('Check Attribute Message Digest: Success\n')
    return True


def check_signing_time(attr_value):
    """
    Verify signing time attribute
    """
    logging.info('Attribute Signing Time')
    try:
        signed_time, _ = decoder.decode(attr_value, asn1Spec=useful.UTCTime())
        logging.info('\tAttribute Value:\t' + str(signed_time.asDateTime))
        logging.info('\tGenTime Value:\t\t' + str(GenTime.asDateTime))
        assert signed_time.asDateTime == GenTime.asDateTime
    except Exception as e:
        logging.error('Check Attribute Signing Time: Failure,', exc_info=True)
        raise e
    logging.info('Check Attribute Signing Time: Success\n')
    return True


def check_signer(signer_cert, tsa_cert: str):
    """
    Verify signing certificate attribute
    """
    logging.info("Attribute Signing Certificate")
    try:
        cert_hash = signer_cert['certs'][0]['certHash']
        hash_obj = hashlib.sha1()
        substrate = pem.readPemFromFile(open(tsa_cert))
        hash_obj.update(substrate)
        logging.info("\tAttribute Value:\t" + str(cert_hash.asOctets().hex()))
        logging.info("\tCertificate Hash:\t" + str(hash_obj.digest().hex()))
        assert cert_hash == hash_obj.digest()
    except Exception as e:
        logging.error('Signer certificate hash is not equal to TSA certificate hash')
        logging.error('Check Attribute Signing Certificate: Failure', exc_info=True)
        raise e
    logging.info('Check Attribute Signing Certificate: Success\n')
    return True


def check_signerv2(signer_cert, tsa_cert: str):
    """
    Verify signing certificate attribute
    """
    logging.info("Attribute Signing Certificate")
    try:
        cert_hash = signer_cert['certs'][0]['certHash']
        hash_obj = hashlib.sha256()
        # todo: wrong tsa cert - symantec not freetsa
        substrate = pem.readPemFromFile(open(tsa_cert))
        hash_obj.update(substrate)
        logging.info("\tAttribute Value:\t" + str(cert_hash.asOctets().hex()))
        logging.info("\tCertificate Hash:\t" + str(hash_obj.digest().hex()))
        assert cert_hash == hash_obj.digest()
    except Exception as e:
        logging.error('Signer certificate hash is not equal to TSA certificate hash')
        logging.error('Check Attribute Signing Certificate: Failure', exc_info=True)
        raise e
    logging.info('Check Attribute Signing Certificate: Success\n')
    return True


def check_signed_attrs(content, tsa_cert: str):
    """
    Verify signed attributes within SignerInfo
    """
    logging.info('Checking Signed Attributes...')
    try:
        assert len(content['signerInfos']) == 1
        signed_attrs = content['signerInfos'][0]['signedAttrs']
        for attr in signed_attrs:
            if attr['attrType'] == id_contentType:
                assert len(attr['attrValues']) == 1
                assert check_content_type(attr['attrValues'][0], content['encapContentInfo']['eContentType'])
            elif attr['attrType'] == id_messageDigest:
                assert len(attr['attrValues']) == 1
                hash_oid = content['signerInfos'][0]['digestAlgorithm']['algorithm']
                e_content = content['encapContentInfo']['eContent']
                attr_value = attr['attrValues'][0]
                assert check_message_digest(attr_value.asOctets(), e_content.asOctets(), hash_oid)
            elif attr['attrType'] == id_signingTime:
                assert len(attr['attrValues']) == 1
                assert check_signing_time(attr['attrValues'][0])
            else:
                # Signing Certificate attribute
                if attr['attrType'] == id_aa_signingCertificate:
                    sign_cert, _ = decoder.decode(attr['attrValues'][0], asn1Spec=SigningCertificate())
                    assert check_signer(sign_cert, tsa_cert)
                elif attr['attrType'] == id_aa_signingCertificateV2:
                    sign_cert, _ = decoder.decode(attr['attrValues'][0], asn1Spec=SigningCertificateV2())
                    assert check_signerv2(sign_cert, tsa_cert)
    except Exception as e:
        logging.error('Check Signed Attributes: Failure \n', exc_info=True)
        raise e
    logging.info('Check Signed Attributes: Success\n')
    return True


def check_trust_chain(tsa_cert: str, ca_cert: str):
    """
    Verify timestamp authority certificate trust chain

    :param tsa_cert: TSA certificate filepath
    :param ca_cert: CA of TSA certificate filepath
    """
    try:
        cert_ = open(tsa_cert, 'rb').read()
        ca_cert_ = open(ca_cert, 'rb').read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_)
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert_)

        store = OpenSSL.crypto.X509Store()
        store.add_cert(ca_cert)

        store_context = OpenSSL.crypto.X509StoreContext(store, cert)
        store_context.verify_certificate()
    except Exception as e:
        logging.error('Check Certficate Trust Chain: Failure', exc_info=True)
        raise e
    logging.info('Check Certficate Trust Chain: Success')
    return True


def check_signed_time(cert: str):
    logging.info('Checking Signed Time...')
    try:
        cert_ = open(cert, 'rb').read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_)
        not_after = useful.GeneralizedTime(cert.get_notAfter().decode())
        not_before = useful.GeneralizedTime(cert.get_notBefore().decode())
        logging.info("\tTSA Certificate's not after:\t" + str(not_after.asDateTime))
        logging.info("\tTSA Certificate's not before:\t" + str(not_before.asDateTime))
        logging.info("\tGenTime of TimeStampToken:\t\t" + str(GenTime.asDateTime))
        assert not_before.asDateTime < GenTime.asDateTime < not_after.asDateTime
    except Exception as e:
        logging.error('Check Signed Time: Failure', exc_info=True)
        raise e
    logging.info('Check Signed Time: Success, GenTime is between TSA certificate period of validity')
    return True


def check_extension(tsacert: str):
    try:
        cert_ = open(tsacert, 'rb').read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_)
        count = 0
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name().decode() == 'extendedKeyUsage':
                count += 1
                ext_key_usage, _ = decoder.decode(ext.get_data(), asn1Spec=rfc2459.ExtKeyUsageSyntax())
                assert ext_key_usage[0] == id_kp_timeStamping
        assert count == 1
    except Exception as e:
        logging.error('Checking Extended Key Usage: Failure', exc_info=e)
        raise e
    logging.info('Checking Extended Key Usage: Success')
    return True


def check_tsa_certificate(tsa_cert: str, ca_cert: str):
    logging.info('Checking TSA Certificate...')
    try:
        assert check_trust_chain(tsa_cert, ca_cert)
        assert check_signed_time(tsa_cert)
        assert check_extension(tsa_cert)
    except Exception as e:
        logging.error('Invalid TSA Certificate: Failure,', exc_info=True)
        raise e
    logging.info('Valid TSA Certificate\n')
    return True


def check_signature(tsa_cert: str, signature, data, hash_str):
    # TODO invoke different hash function based on hash_str
    try:
        data_ = encoder.encode(data, asn1Spec=univ.SetOf())  # encode with asn1Spec univ.SetOf()
        with open(tsa_cert, 'r') as pem_file:
            cert_pem = pem.readPemFromFile(pem_file)
        pub_key = RSA.import_key(cert_pem)
        hash_obj = SHA1.new()
        hash_obj.update(data_)
        crypto_signature.new(pub_key).verify(hash_obj, signature.asOctets())
    except Exception as e:
        logging.error('Check signature: Failure', exc_info=True)
        raise e
    logging.info('Check signature: Success')
    return True


def parse_tsr(tsr_file: str, tsq_file: str, tsa_cert: str, ca_cert: str):
    try:
        response, _ = decoder.decode(open(tsr_file, 'rb').read(), asn1Spec=TimeStampResp())
        request, _ = decoder.decode(open(tsq_file, 'rb').read(), asn1Spec=TimeStampReq())

        status = response['status']
        assert check_status(status)

        e_content = response['timeStampToken']['content']['encapContentInfo']['eContent']
        de_e_cont, _ = decoder.decode(e_content, asn1Spec=TSTInfo())
        assert check_TSTInfo(de_e_cont, request)

        content = response['timeStampToken']['content']
        assert check_signed_attrs(content, tsa_cert)

        assert check_tsa_certificate(tsa_cert, ca_cert)

        signature = response['timeStampToken']['content']['signerInfos'][0]['signature']
        data = response['timeStampToken']['content']['signerInfos'][0]['signedAttrs']
        digest_algo = response['timeStampToken']['content']['signerInfos'][0]['digestAlgorithm']['algorithm']

        assert check_signature(tsa_cert, signature, data, digest_algorithm.get(digest_algo))
    except Exception as e:
        logging.error('TimeStampResp: INVALID')
        return False
    logging.info('TimeStampResp: VALID')
    return True


def main(tsr_file: str, tsq_file: str, tsa_cert: str = TSACERT, ca_cert: str = CACERT):
    logging.basicConfig(filename=f'verify_tsr_{tsr_file}.log', filemode='w', level=logging.INFO, format='%(levelname)s : %(message)s')
    print(f'Refer to log file: verify_tsr_{tsr_file}.log for more info...')
    logging.info('VERIFYING TimeStampResp...')
    logging.info(f'\tTimeStampResp file: {tsr_file}')
    logging.info(f'\tTimeStampReq file: {tsq_file}')
    logging.info(f'\tTSA cert file: {tsa_cert}')
    logging.info(f'\tCA cert file: {ca_cert}')
    if parse_tsr(tsr_file, tsq_file, tsa_cert, ca_cert):
        print('Status: OK')
    else:
        print('Status: KO')


if __name__ == '__main__':
    main(TSR_FILE, TSQ_FILE, TSACERT, CACERT)
