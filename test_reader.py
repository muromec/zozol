from zozol import decode_ber
from zozol.schemas.pkcs7_dstszi import ContentInfo


def main():
    data = open('signed1.r').read()
    msg = ContentInfo.stream(bytearray(data), len(data), decode_ber)
    print '\n\nparsed\n\n\n'
    print msg.content.contentInfo.content
    print msg.content.signerInfos[0].sid


if __name__ == '__main__':
    main()
