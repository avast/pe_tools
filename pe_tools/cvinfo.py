from .struct3 import Struct3, u16, u32

S_PUB32 = 0x110e

class CvRecHdr(Struct3):
    reclen: u16
    rectyp: u16

class PUBSYM32(Struct3):
    pubsymflags: u32
    off: u32
    seg: u16
    # name: length_prefixed_str
