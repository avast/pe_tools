import struct

class StructParseError(RuntimeError):
    pass

def Struct(*fields):
    fmts = ['<']
    names = []
    for fld in fields:
        fmt, name = fld.split(':', 1)
        fmts.append(fmt)
        names.append(name.split(':'))

    _names = names
    _fmt = ''.join(fmts)
    size = struct.calcsize(_fmt)

    def __init__(self, **kw):
        for names in _names:
            for name in names:
                setattr(self, name, kw.get(name, 0))

    def __repr__(self):
        return 'struct({})'.format(', '.join('{}={!r}'.format(k[0], getattr(self, k[0])) for k in _names))

    def pack(self):
        data = tuple(getattr(self, fld[0]) for fld in _names)
        return struct.pack(_fmt, *data)

    def clone(self, **kw):
        r = rtype()
        for names in _names:
            for name in names:
                if name in kw:
                    value = kw[name]
                    break
            else:
                value = getattr(self, names[0])
                    
            for name in names:
                setattr(r, name, value)
        return r

    def write_to(self, fout):
        fout.write(self.pack())

    def _parse(data):
        fields = struct.unpack(_fmt, data)
        r = rtype()
        for fld, names in zip(fields, _names):
            for name in names:
                setattr(r, name, fld)
        return r

    @staticmethod
    def parse(fin):
        data = fin.read(size)
        if len(data) != size:
            raise StructParseError('Prematurely reached EOF')
        return _parse(data)

    @staticmethod
    def parse_blob(blob):
        return _parse(bytes(blob[:size]))

    @staticmethod
    def parse_all(blob):
        if len(blob) != size:
            raise StructParseError('Size mismatch')
        return _parse(bytes(blob))

    rtype = type('struct', (object, ), {
        '__init__': __init__,
        '__repr__': __repr__,
        'pack': pack,
        'clone': clone,
        'write_to': write_to,
        'size': size,
        'parse': parse,
        'parse_blob': parse_blob,
        'parse_all': parse_all,
        })
    return rtype
