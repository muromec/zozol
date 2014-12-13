from .. import base as asn1
from .. markers import Implicit, Explicit, Optional, Default
from . rfc3280_x509 import Certificate, DigestAlgorithmIdentifier, Name


class ContentInfo(asn1.Seq):
    def resolve_content(obj):
        return TYPES[str(obj.contentType)]

    fields = [
        ('contentType', asn1.ObjId),
        ('content', Explicit(tag=0, typ=resolve_content)),
    ]


class DigestAlgorithmIdentifiers(asn1.SetOf):
    typ = DigestAlgorithmIdentifier


class ExtendedCertificatesAndCertificates(asn1.SeqOf):
    typ = Certificate


class IssuerAndSerialNumber(asn1.Seq):
    fields = [
        ('issuer', Name),
        ('serialNumber', asn1.Int),
    ]



class SignerIdentifier(IssuerAndSerialNumber):
    pass


class AttributeValues(asn1.SetOf):
    typ = asn1.Any


class Attribute(asn1.Seq):
    fields = [
        ('type', asn1.ObjId),
        ('values', AttributeValues),
    ]

class Attributes(asn1.SetOf):
    typ = Attribute

class SignerInfo(asn1.Seq):
    fields = [
        ('version', asn1.Int),
        ('sid', SignerIdentifier),
        ('digestAlgorithm', DigestAlgorithmIdentifier),
        ('authenticatedAttributes', Optional(Implicit(tag=0, typ=Attributes))),
    ]


class SignerInfos(asn1.SetOf):
    typ = SignerInfo


class SignedData(asn1.Seq):
    fields = [
        ('version', asn1.Int),
        ('digestAlgorithms', DigestAlgorithmIdentifiers),
        ('contentInfo', ContentInfo),
        ('certificates', Optional(Implicit(tag=0, typ=ExtendedCertificatesAndCertificates))),
        ('crls', Optional(Implicit(tag=1, typ=asn1.Any))),
        ('signerInfos', SignerInfos),

    ]

class Data(asn1.OctStr):
    pass

TYPES = {
    "1.2.840.113549.1.7.2": SignedData,
    "1.2.840.113549.1.7.1": Data,
}

