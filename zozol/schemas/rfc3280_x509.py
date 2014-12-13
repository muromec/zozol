from .. import base as asn1
from .. markers import Implicit, Explicit, Optional, Default


class AttributeTypeAndValue(asn1.Seq):
    fields = [
        ('type', asn1.ObjId),
        ('value', asn1.Any),
    ]

class RelativeDistinguishedName(asn1.SetOf):
    typ = AttributeTypeAndValue

class RDNSequence(asn1.SeqOf):
    typ = RelativeDistinguishedName

class Name(RDNSequence):
    pass


class DigestAlgorithmIdentifier(asn1.Seq):
    fields = [
        ('algorithm', asn1.ObjId),
    ]


class UniqueIdentifier(asn1.BitStr):
    pass


class SubjectPublicKeyInfo(asn1.Seq):
    fields = [
        ('algorithm', DigestAlgorithmIdentifier),
        ('subjectPublicKey', asn1.BitStr),
        
    ]


class Validity(asn1.Seq):
    fields = [
        ('notBefore', asn1.Time),
        ('notAfter', asn1.Time),
    ]


class Extension(asn1.Seq):
    fields = [
        ('extnID', asn1.ObjId),
        ('critical', Default(value=False, typ=asn1.Bool)),
        ('extnValue', asn1.OctStr),
    ]


class Extensions(asn1.SeqOf):
    typ = Extension

class TBSCertificate(asn1.Seq):
    fields = [
        ('version', Explicit(tag=0, typ=asn1.Int)),
        ('serialNumber', asn1.Int),
        ('signature', DigestAlgorithmIdentifier),
        ('issuer', Name),
        ('validity', Validity),
        ('subject', Name),
        ('subjectPublicKeyInfo', SubjectPublicKeyInfo),
        ('issuerUniqueID', Optional(Implicit(tag=1, typ=UniqueIdentifier))),
        ('subjectUniqueID', Optional(Implicit(tag=2, typ=UniqueIdentifier))),
        ('extensions', Optional(Explicit(tag=3, typ=Extensions))),
    ]

class Certificate(asn1.Seq):
    fields = [
        ('tbsCertificate', TBSCertificate),
        ('signatureAlgorithm', DigestAlgorithmIdentifier),
        ('signature', asn1.BitStr),
    ]
