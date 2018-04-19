from .structs2 import Struct
from .utils import align4
from grope import rope
import six, struct

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

def _set_file_version(self, major, minor=0, patch=0, build=0):
    self.dwFileVersionMS = (major << 16) | minor
    self.dwFileVersionLS = (patch << 16) | build

def _set_product_version(self, major, minor=0, patch=0, build=0):
    self.dwProductVersionMS = (major << 16) | minor
    self.dwProductVersionLS = (patch << 16) | build

_VS_FIXEDFILEINFO.set_file_version = _set_file_version
_VS_FIXEDFILEINFO.set_product_version = _set_product_version

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

    def get(self, name, default=None):
        components = [c for c in name.split('/') if c]

        cur = self._root
        for c in components:
            for child in cur.children:
                if child.name == c:
                    cur = child
                    break
            else:
                return default

        return cur

    def get_fixed_info(self):
        fi = _VS_FIXEDFILEINFO.parse_all(self._root.value)
        if fi.dwSignature != FIXEDFILEINFO_SIG:
            raise ValueError('FIXEDFILEINFO_SIG mismatch')
        fi.set_file_version
        return fi

    def set_fixed_info(self, fi):
        self._root.value = fi.pack()

    def string_file_info(self):
        r = {}
        for fi in self.get('StringFileInfo', []).children:
            if len(fi.name) != 8:
                raise RuntimeError('corrupted string file info')
            langid = int(fi.name[:4], 16)
            cp = int(fi.name[4:], 16)

            tran = {}
            for s in fi.children:
                tran[s.name] = s.value
            r[(langid, cp)] = tran
        return r

    def set_string_file_info(self, translations):
        children = []
        trans = []
        for (langid, cp), strs in translations.items():
            tran_children = [_VerNode(k, v, []) for k, v in sorted(strs.items())]
            children.append(_VerNode('{:04x}{:04x}'.format(langid, cp), None, tran_children))
            trans.append(struct.pack('<HH', langid, cp))

        for root_child in self._root.children:
            if root_child.name == 'StringFileInfo':
                root_child.children = children
                break
        else:
            self._root.children.append(_VerNode('StringFileInfo', None, children))

        self.set_var('Translation', b''.join(trans))

    def set_var(self, name, value):
        for ch in self._root.children:
            if ch.name == 'VarFileInfo':
                vfi_node = ch
                break
        else:
            vfi_node = _VerNode('VarFileInfo', None, [])
            self._root.children.append(vfi_node)

        for ch in vfi_node.children:
            if ch.name == name:
                ch.value = value
                break
        else:
            vfi_node.children.append(_VerNode(name, value, []))

    def pack(self):
        return _pack_node(self._root)

def _pack_node(node):
    children = []
    for child in node.children:
        if children:
            children.append(b'\0' * (align4(len(children[-1])) - len(children[-1])))
        children.append(_pack_node(child))
    children = rope(*children)

    name = node.name.encode('utf-16le') + b'\0\0'

    children_offset = align4(_NODE_HEADER.size + len(name))
    name_pad = b'\0' * (children_offset - _NODE_HEADER.size - len(name))

    hdr = _NODE_HEADER()
    if node.value is None:
        value = b''
        hdr.wValueLength = 0
        hdr.wType = 1
    elif isinstance(node.value, six.string_types):
        value = node.value.encode('utf-16le') + b'\0\0'
        hdr.wValueLength = len(value) // 2
        hdr.wType = 1
    else:
        value = node.value
        hdr.wValueLength = len(value)
        hdr.wType = 0

    if not children:
        hdr.wLength = _NODE_HEADER.size + len(name) + len(name_pad) + len(value)
        value_pad = b''
    else:
        value_len_aligned = align4(len(value))
        value_pad = b'\0' * (value_len_aligned - len(value))

    hdr.wLength = _NODE_HEADER.size + len(name) + len(name_pad) + len(value) + len(value_pad) + len(children)
    return rope(hdr.pack(), name, name_pad, value, value_pad, children)

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
        if not value:
            value = None
        else:
            if len(value) % 2 != 0:
                raise RuntimeError('a text version info value is not of an even length')
            if bytes(value[-2:]) != b'\0\0':
                raise RuntimeError('version info string is not terminated by zero')
            value = bytes(value[:-2]).decode('utf-16le')

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
