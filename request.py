"""
Module to process and send timestamp request
"""
import hashlib
from os import urandom
from struct import unpack
from pyasn1.codec.der import encoder
from pyasn1_modules.rfc2459 import AlgorithmIdentifier
from pyasn1.type import univ
import requests
import logging

from rfc3161 import MessageImprint, TimeStampReq


SERVER = 'https://www.freetsa.org/tsr'
FILE = 'READ_ME_.txt'
FILENAME = 'default'

digest_algorithms = {
    'sha1': univ.ObjectIdentifier('1.3.14.3.2.26'),
    'md5': univ.ObjectIdentifier('1.2.840.113549.2.5'),
    'sha256': univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1'),
    'sha384': univ.ObjectIdentifier('2.16.840.1.101.3.4.2.2'),
    'sha512': univ.ObjectIdentifier('2.16.840.1.101.3.4.2.3')
}


def write_filename(file):
    global FILENAME
    if file.find('.'):
        FILENAME = file.replace('.', '_')


def compute_hash(file_, hash_object, size=131072):
    """
    Compute the hash of a file_ in a memory-efficient way.

    :param file_: File path
    :param hash_object: Hash object to use
    :param size: Size in bytes of every chunk
    :return: Hash digest
    """
    logging.info('Computing hash...')
    try:
        with open(file_, 'rb') as read_file:
            while True:
                data = read_file.read(size)
                if not data:
                    logging.info('Computing hash: Success')
                    return hash_object.digest()
                hash_object.update(data)
    except Exception as e:
        logging.error('Computing hash: Failure', exc_info=True)
        raise e


def create_tsq(file_: str, hash_digest: str = 'sha512', nonce: bool = True):
    """
    Create TimeStampReq byte string

    :param file_: File path
    :param hash_digest: Hash algorithm
    :param nonce: Random integer value
    :return: Byte string
    """
    try:
        logging.info('Creating TimeStampReq object...')
        message_imprint = MessageImprint()
        hash_algorithm = AlgorithmIdentifier()
        if hash_digest in digest_algorithms:
            hash_algorithm['algorithm'] = digest_algorithms.get(hash_digest)
        else:
            logging.error(f'{hash_digest} is not listed in list of digest algorithms')
            raise Exception
        message_imprint['hashAlgorithm'] = hash_algorithm
        message_imprint['hashedMessage'] = compute_hash(file_, hashlib.new(hash_digest))

        tsq = TimeStampReq()
        tsq['version'] = 1
        tsq['messageImprint'] = message_imprint
        if nonce:
            tsq['nonce'] = unpack('<q', urandom(8))[0]
        logging.info('Creating TimeStampReq: Success')
        return encoder.encode(tsq)
    except Exception as e:
        logging.error('Creating TimeStampReq: Failure', exc_info=True)
        raise e


def save_tsq(encoded_tsq):
    """
    Save encoded TimeStampReq to .tsq file

    :param encoded_tsq: Encoded TimeStampReq
    :return:
    """
    logging.info('Creating TimeStampReq file...')
    try:
        filename = '%s.tsq' % FILENAME
        logging.info(f'TimeStampReq filepath: {filename}')
        with open(filename, 'wb') as tsq_file:
            tsq_file.write(encoded_tsq)
    except Exception as e:
        logging.error('Creating TimeStampReq file: Failure', exc_info=True)
        raise e
    logging.info('Creating TimeStampReq file: Success')
    return filename


def send_tsq(server: str = SERVER):
    """
    Send tsq to trusted server and save the response
    :param server: String of server address
    :return: Dir path of tsr file
    """
    logging.info('Sending TimeStampReq to TSA...')
    try:
        tsq_file = open(f'{FILENAME}.tsq', 'rb').read()
        tsr_file = f'{FILENAME}.tsr'
        header = {'Content-Type': 'application/timestamp-query'}
        r = requests.post(server, data=tsq_file, headers=header)
        with open(tsr_file, 'wb') as resp:
            resp.write(r.content)
        r.close()
        logging.info(f'\tTSA Server: {server}')
        logging.info(f'\tTimeStampReq filepath: {FILENAME}.tsq')
        logging.info(f'\tTimeStampResp filepath: {tsr_file}')
        logging.info('Sending TimeStampReq: Success')
        return tsr_file
    except Exception as e:
        logging.error('SendingTimeStampReq: Failure', exc_info=True)
        raise e


def main(file: str, hash_digest: str = 'sha512', server: str = SERVER):
    """
    :param file: Filepath to be timestamped
    :param hash_digest: Hash algorithm
    :param server: TSA server
    :return: TSQ and TSR filepath
    """
    try:
        write_filename(file)
        logging.basicConfig(filename=f'request_tsq_{FILENAME}.log', filemode='w', level=logging.INFO, format='%(levelname)s : %(message)s')
        print(f'Refer to log file: request_tsq_{FILENAME}.log for more info...')
        logging.info('PROCESSING TimeStampReq...')
        encoded_tsq = create_tsq(file, hash_digest)
        tsq_filepath = save_tsq(encoded_tsq)
        tsr_filepath = send_tsq(server)
        logging.info('PROCESSING TimeStampReq: SUCCESS')
        return tsq_filepath, tsr_filepath
    except Exception as e:
        logging.error('PROCESSING TimeStampReq: FAILURE', exc_info=True)
        return None, None


if __name__ == '__main__':
    main(FILE)
