import os.path
from zozol import decode_ber
from zozol.schemas.pkcs7_dstszi import ContentInfo

def here(fname):
    dirname, _ = os.path.split(__file__)
    return os.path.join(dirname, fname)

def test_pkcs7():
    CONTENT = """IGNORE THIS FILE.
This file does nothing, contains no useful data, and might go away in
future releases.  Do not depend on this file or its contents.
"""

    data = open(here('signed1.r')).read()
    msg = ContentInfo.stream(bytearray(data), len(data), decode_ber)
    assert str(msg.content.contentInfo.content) == CONTENT
    assert msg.content.signerInfos[0].sid.serialNumber.value == 359272175317388400160838857906663248925214184704
