"""
Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)

ASN.1 source from:

http://www.rfcreader.com/#rfc3161
"""

from pyasn1.type import univ
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import useful

from pyasn1_modules.rfc2459 import Extensions, AlgorithmIdentifier, GeneralName, GeneralNames,\
    CertificateSerialNumber, PolicyInformation
from pyasn1_modules.rfc5652 import ContentType, SignedData


MAX = float('inf')

id_ct_TSTInfo = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.4')
id_signedData = univ.ObjectIdentifier('1.2.840.113549.1.7.2')

# ---   TimeStampReq


class MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('hashedMessage', univ.OctetString())
    )


class TSAPolicyId(univ.ObjectIdentifier):
    pass


class TimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues=namedval.NamedValues('v1', 1))),
        namedtype.NamedType('messageImprint', MessageImprint()),
        namedtype.OptionalNamedType('reqPolicy', TSAPolicyId()),
        namedtype.OptionalNamedType('nonce', univ.Integer()),
        namedtype.DefaultedNamedType('certReq', univ.Boolean(False)),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )

# ---   TimeStampResp


class PKIStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('granted', 0),
        ('grantedWithMods', 1),
        ('rejection', 2),
        ('waiting', 3),
        ('revocationsWarning', 4),
        ('revocationsNotification', 5)
    )


class PKIFreeText(univ.SequenceOf):
    componentType = char.UTF8String()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class PKIFailureInfo(univ.BitString):
    namedValues = namedval.NamedValues(
        ('badAlg', 0),
        ('badRequest', 2),
        ('badDataFormat', 5),
        ('timeNotAvailable', 14),
        ('unacceptedPolicy', 15),
        ('unacceptedExtension', 16),
        ('addInfoNotAvailable', 17),
        ('systemFailure', 25)
    )


class PKIStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('status', PKIStatus()),
        namedtype.OptionalNamedType('statusString', PKIFreeText()),
        namedtype.OptionalNamedType('failInfo', PKIFailureInfo())
    )


class Accuracy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('seconds', univ.Integer()),
        namedtype.OptionalNamedType('millis', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0),
            subtypeSpec=constraint.ValueRangeConstraint(1, 999)
        )),
        namedtype.OptionalNamedType('micros', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1),
            subtypeSpec=constraint.ValueRangeConstraint(1, 999)
        ))

    )


class TSTInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues=namedval.NamedValues('v1', 1))),
        namedtype.NamedType('policy', TSAPolicyId()),
        namedtype.NamedType('messageImprint', MessageImprint()),
        namedtype.NamedType('serialNumber', univ.Integer()),
        namedtype.NamedType('genTime', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('accuracy', Accuracy()),
        namedtype.DefaultedNamedType('ordering', univ.Boolean(False)),
        namedtype.OptionalNamedType('nonce', univ.Integer()),
        namedtype.OptionalNamedType('tsa', GeneralName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ))
    )


class ContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', ContentType()),
        namedtype.NamedType('content',
                            SignedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


class TimeStampToken(ContentInfo):
    pass


class TimeStampResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('status', PKIStatusInfo()),
        namedtype.OptionalNamedType('timeStampToken', TimeStampToken())
    )

# ---   SigningCertificate


class Hash(univ.OctetString):
    pass


class IssuerSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', GeneralNames()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber())
    )


class ESSCertID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certHash', Hash()),
        namedtype.OptionalNamedType('issuerSerial', IssuerSerial())
    )


class SigningCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certs', univ.SequenceOf(componentType=ESSCertID())),
        namedtype.OptionalNamedType('policies', univ.SequenceOf(componentType=PolicyInformation()))
    )


class AlgorithmIdentifierV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('algorithm', univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class ESSCertIDV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('hashAlgorithm', AlgorithmIdentifierV2()),
        namedtype.NamedType('certHash', Hash()),
        namedtype.OptionalNamedType('issuerSerial', IssuerSerial())
    )


class SigningCertificateV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certs', univ.SequenceOf(componentType=ESSCertIDV2())),
        namedtype.OptionalNamedType('policies', univ.SequenceOf(componentType=PolicyInformation()))
    )
