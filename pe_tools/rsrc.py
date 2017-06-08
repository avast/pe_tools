from .structs2 import Struct
from .blob import join_blobs
from .utils import *
import six, time, struct

_RESOURCE_DIRECTORY_TABLE = Struct(
    "I:Characteristics",
    "I:Timestamp",
    "H:Major",
    "H:Minor",
    "H:NumberOfNameEntries",
    "H:NumberOfIdEntries",
    )

_RESOURCE_DIRECTORY_ENTRY = Struct(
    "I:NameOrId",
    "I:Offset",
    )

_RESOURCE_DATA_ENTRY = Struct(
    "I:DataRva",
    "I:Size",
    "I:Codepage",
    "I:Reserved"
    )

_STRING_HEADER = Struct(
    "H:Length",
    )

_RES_HEADER_SIZES = Struct(
    "I:DataSize",
    "I:HeaderSize",
    )

_RES_HEADER = Struct(
    "I:DataVersion",
    "H:MemoryFlags",
    "H:LanguageId",
    "I:Version",
    "I:Characteristics",
    )

def _parse_prelink_name(blob, align=False):
    name, = struct.unpack('<H', bytes(blob[:2]))
    if name == 0xffff:
        name, = struct.unpack('<H', bytes(blob[2:4]))
        return name, blob[4:]
    else:
        r = []
        while True:
            ch = bytes(blob[:64])
            i = 0
            while i < 64:
                if ch[i:i+2] == b'\0\0':
                    r.append(ch[:i])
                    return b''.join(r).decode('utf-16le'), blob[align4(i+2) if align else i+2:]
                i += 2
            r.append(ch)
            blob = blob[64:]


def _parse_one_prelink_res(blob):
    hdr_sizes = _RES_HEADER_SIZES.parse_blob(blob)
    if hdr_sizes.HeaderSize < hdr_sizes.size:
        raise RuntimeError('corrupted header')

    hdr_blob = blob[hdr_sizes.size:hdr_sizes.HeaderSize]
    data_blob = blob[hdr_sizes.HeaderSize:hdr_sizes.HeaderSize + hdr_sizes.DataSize]
    next_blob = blob[align4(hdr_sizes.HeaderSize + hdr_sizes.DataSize):]

    type, hdr_blob = _parse_prelink_name(hdr_blob, align=False)
    name, hdr_blob = _parse_prelink_name(hdr_blob, align=True)

    hdr = _RES_HEADER.parse_blob(hdr_blob)
    hdr.type = type
    hdr.name = name
    return hdr, data_blob, next_blob

def parse_prelink_resources(blob):
    r = {}
    while blob:
        hdr, data, blob = _parse_one_prelink_res(blob)
        r.setdefault(hdr.type, {}).setdefault(hdr.name, {})[hdr.LanguageId] = data

    if 0 in r:
        del r[0]
    return r

def parse_pe_resources(blob, base):
    def parse_string(offs):
        hdr = _STRING_HEADER.parse_blob(blob[offs:])
        return bytes(blob[offs+_STRING_HEADER.size:offs+_STRING_HEADER.size+hdr.Length*2]).decode('utf-16le')

    def parse_data(offs):
        entry = _RESOURCE_DATA_ENTRY.parse_blob(blob[offs:])

        if entry.DataRva < base:
            raise RuntimeError('resource is outside the resource blob')

        if entry.DataRva + entry.Size - base > len(blob):
            raise RuntimeError('resource is outside the resource blob')

        return blob[entry.DataRva - base:entry.DataRva + entry.Size - base]

    def parse_tree(offs):
        r = {}

        fin = blob.seek(offs)

        node = _RESOURCE_DIRECTORY_TABLE.parse(fin)
        name_entries = [_RESOURCE_DIRECTORY_ENTRY.parse(fin) for i in range(node.NumberOfNameEntries)]
        id_entries = [_RESOURCE_DIRECTORY_ENTRY.parse(fin) for i in range(node.NumberOfIdEntries)]

        for entry in name_entries:
            name = parse_string(entry.NameOrId & ~(1<<31))
            if entry.Offset & (1<<31):
                r[name] = parse_tree(entry.Offset & ~(1<<31))
            else:
                r[name] = parse_data(entry.Offset)

        for entry in id_entries:
            if entry.Offset & (1<<31):
                r[entry.NameOrId] = parse_tree(entry.Offset & ~(1<<31))
            else:
                r[entry.NameOrId] = parse_data(entry.Offset)

        return r

    return parse_tree(0)

class _PrepackedResources:
    def __init__(self, entries, strings, blobs):
        self._entries = entries
        self._strings = strings
        self._blobs = blobs

        self.size = sum(ent.size for ent in self._entries) + len(strings) + len(blobs)

    def pack(self, base):
        def _transform(ent):
            if ent.type != _RESOURCE_DATA_ENTRY:
                return ent
            return ent.clone(DataRva=ent.DataRva + base)

        ents = [_transform(ent).pack() for ent in self._entries]
        return b''.join(ents) + self._strings + bytes(self._blobs)

def _prepack(rsrc):
    if isinstance(rsrc, dict):
        name_keys = [key for key in rsrc.keys() if isinstance(key, six.string_types)]
        id_keys = [key for key in rsrc.keys() if not isinstance(key, six.string_types)]

        name_keys.sort()
        id_keys.sort()

        r = []
        children = []

        r.append(_RESOURCE_DIRECTORY_TABLE(
            Characteristics=0,
            Timestamp=0,
            Major=0,
            Minor=0,
            NumberOfNameEntries=len(name_keys),
            NumberOfIdEntries=len(id_keys),
            ))

        for keys in (name_keys, id_keys):
            for name in keys:
                items = _prepack(rsrc[name])
                children.extend(items)
                r.append(_RESOURCE_DIRECTORY_ENTRY(
                    NameOrId=name,
                    Offset=items[0]
                    ))

        r.extend(children)
        return r
    else:
        return [_RESOURCE_DATA_ENTRY(
            DataRva=rsrc,
            Size=len(rsrc),
            Codepage=0,
            Reserved=0
            )]

def pe_resources_prepack(rsrc):
    entries = _prepack(rsrc)

    strings = []
    string_map = {}
    def add_string(s):
        r = string_map.get(s)
        if r is None:
            encoded = s.encode('utf-16le')

            r = sum(len(ss) for ss in strings)
            string_map[s] = r

            strings.append(_STRING_HEADER(Length=len(encoded)//2).pack())
            strings.append(encoded)
        return r

    _entry_offsets = {}
    offs = 0
    for ent in entries:
        _entry_offsets[ent] = offs
        offs += ent.size

    table_size = offs
    for ent in entries:
        if ent.type == _RESOURCE_DIRECTORY_ENTRY:
            if isinstance(ent.NameOrId, six.string_types):
                ent.NameOrId = (1<<31) | (table_size + add_string(ent.NameOrId))

    strings = b''.join(strings)
    aligned_strings_len = align16(len(strings))
    strings += b'\0' * (aligned_strings_len - len(strings))

    data_offs = table_size + len(strings)
    blobs = []

    for ent in entries:
        if ent.type == _RESOURCE_DIRECTORY_ENTRY:
            if ent.Offset.type == _RESOURCE_DIRECTORY_TABLE:
                ent.Offset = (1<<31) | _entry_offsets[ent.Offset]
            else:
                ent.Offset = _entry_offsets[ent.Offset]
        elif ent.type == _RESOURCE_DATA_ENTRY:
            blob = ent.DataRva
            ent.DataRva = data_offs

            blobs.append(blob)
            aligned_size = align8(len(blob))
            pad = aligned_size - len(blob)
            if pad:
                blobs.append(b'\0' * pad)

            data_offs += aligned_size

    return _PrepackedResources(entries, strings, join_blobs(blobs))
