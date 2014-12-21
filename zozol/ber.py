from . import base
from . import markers

cls_names = ['univ', 'app', 'ct', 'priv']
tags = {
    0x01: base.Bool,
    0x06: base.ObjId,
    0x03: base.BitStr,
    0x04: base.OctStr,
    0x0C: base.Utf8Str,
    0x13: base.PrintStr,
    0x02: base.Int,
    0x11: base.SetOf,
    0x17: base.Time,
}

def decode_len(data, off):
    tlen = data[off]
    off += 1
    hlen = 1
    if tlen & 0x80:
        lenlen = tlen & 0x7F
        hlen += lenlen
        tlen = 0
        while lenlen:
            tlen = tlen << 8
            tlen |= data[off]
            off += 1
            lenlen -= 1

    return tlen, hlen


def decode(data, avail, off=0):
    while avail > 0:
        hlen = 1
        tag = data[off] & 0x1F
        cls = data[off] >> 6
        off += 1

        tlen, llen = decode_len(data, off)
        off += llen
        hlen += llen

        ret = None
        if cls == 0:  # u
            if tag == 0x10 or tag == 0x11:
                ret = decode(data, tlen, off)
            else:
                ret = tags[tag](data[off:off+tlen])

        elif cls == 2:
            ret = markers.Tagged(tag, data, off, tlen)

        if ret is None:
            ret = data[off:off+tlen]

        avail -= tlen + hlen
        off += tlen

        yield tag, cls_names[cls], ret


def encode_tag(tag, cls, content, container):
    container.append(tag | cls << 6)
    tlen = len(content)
    if tlen < 128:
        container.append(tlen)
    else:
        len_bytes = []
        while tlen:
            len_bytes.append(tlen & 0xFF)
            tlen >>= 8

        container.append(0x80 | len(len_bytes))
        while len_bytes:
            container.append(len_bytes.pop())

    for byte in content:
        container.append(byte)

    return container


def encode(inp):
    ret = bytearray()
    for (tag, cls, content) in inp:
        if tag == 0x30 or tag == 31:
            content = encode(content)

        encode_tag(tag, cls, content, ret)

    return ret
