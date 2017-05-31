from .structs2 import Struct
from .blob import join_blobs
from .utils import align4
import six

_VS_FIXEDFILEINFO = Struct(
    "I:dwSignature",
    "I:dwStrucVersion",
    "I:dwFileVersionMS",
    "I:dwFileVersionLS",
    "I:dwProductVersionMS",
    "I:dwProductVersionLS",
    "I:dwFileFlagsMask",
    "I:dwFileFlags",
    "I:dwFileOS",
    "I:dwFileType",
    "I:dwFileSubtype",
    "I:dwFileDateMS",
    "I:dwFileDateLS",
    )

FIXEDFILEINFO_SIG = 0xFEEF04BD

_NODE_HEADER = Struct(
    'H:wLength',
    'H:wValueLength',
    'H:wType',
    )

class _VerNode:
    def __init__(self, key, value, children):
        self.name = key
        self.value = value
        self.children = children

class _VersionInfo:
    def __init__(self, root):
        self._root = root

    def get(self, name):
        components = [c for c in name.split('/') if c]

        cur = self._root
        for c in components:
            for child in cur.children:
                if child.name == c:
                    cur = child
                    break
            else:
                return None

        return cur

    def get_fixed_info(self):
        fi = _VS_FIXEDFILEINFO.parse_all(self._root.value)
        if fi.dwSignature != FIXEDFILEINFO_SIG:
            raise ValueError('FIXEDFILEINFO_SIG mismatch')
        return fi

    def set_fixed_info(self, fi):
        self._root.value = fi.pack()

    def pack(self):
        return _pack_node(self._root)

def _pack_node(node):
    children = join_blobs(_pack_node(child) for child in node.children)
    name = node.name.encode('utf-16le') + b'\0\0'

    children_offset = align4(_NODE_HEADER.size + len(name))
    name_pad = b'\0' * (children_offset - _NODE_HEADER.size - len(name))

    hdr = _NODE_HEADER()
    if isinstance(node.value, six.string_types):
        value = node.value.encode('utf-16le')
        hdr.wValueLength = len(value) // 2
        hdr.wType = 1
    else:
        value = node.value
        hdr.wValueLength = len(value)
        hdr.wType = 0

    value_len_aligned = align4(len(value))
    value_pad = b'\0' * (value_len_aligned - len(value))
    hdr.wLength = _NODE_HEADER.size + len(name) + len(name_pad) + len(value) + len(value_pad) + len(children)

    return hdr.pack() + name + name_pad + value + value_pad + children

def parse_version_info(blob):
    root, next = _parse_one(blob)
    if next:
        raise RuntimeError('extra data in the version info blob')
    return _VersionInfo(root)

def _parse_one(blob):
    hdr = _NODE_HEADER.parse_blob(blob)
    next = blob[align4(hdr.wLength):]
    blob = blob[:hdr.wLength]

    key, key_size = _read_string(blob[hdr.size:])
    blob = blob[align4(hdr.size + key_size):]

    value_len = hdr.wValueLength if hdr.wType == 0 else hdr.wValueLength * 2
    value = blob[:value_len]
    blob = blob[align4(value_len):]

    if hdr.wType != 0:
        value = bytes(value).decode('utf-16le')

    children = []
    while blob:
        node, blob = _parse_one(blob)
        children.append(node)

    return _VerNode(key, value, children), next

def _read_string(blob):
    r = []
    while True:
        s = bytes(blob[:64])
        if not s:
            raise RuntimeError('no string')
        i = 0
        while i < len(s):
            if s[i:i+2] == b'\0\0':
                r.append(s[:i])
                r = b''.join(r)
                return r.decode('utf-16le'), len(r) + 2
            i += 2
        r.append(s)
        blob = blob[len(s):]
