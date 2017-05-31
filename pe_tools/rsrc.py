from .structs2 import Struct
from .blob import join_blobs
from .utils import align4
import six, time

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

def parse_pe_resources(blob, base):
    def parse_string(offs):
        hdr = _STRING_HEADER.parse_blob(blob[offs:])
        return fileobj.read(hdr.Length).decode('utf-16le')

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
            name = parse_string(entry.NameOrId)
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

            strings.append(_STRING_HEADER(Length=len(encoded)).pack())
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
                ent.NameOrId = table_size + add_string(ent.NameOrId)

    strings = b''.join(strings)
    strings += b'\0' * ((4 - (len(strings) % 4)) % 4)

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
            aligned_size = align4(len(blob))
            pad = aligned_size - len(blob)
            if pad:
                blobs.append(b'\0' * pad)

            data_offs += aligned_size

    return _PrepackedResources(entries, strings, join_blobs(blobs))
