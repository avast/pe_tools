import struct
from .blob import Blob

class StructParseError(RuntimeError):
    pass

class _StructInstance:
    def __init__(self, type, schema, fmt, size):
        self.type = type
        self._schema = schema
        self._fmt = fmt
        self.size = size

    def __repr__(self):
        return '_StructInstance({})'.format(', '.join('{}={!r}'.format(k[0], getattr(self, k[0])) for k in self._schema))

    def pack(self):
        data = tuple(getattr(self, fld[0]) for fld in self._schema)
        return struct.pack(self._fmt, *data)

    def clone(self, **kw):
        r = _StructInstance(self.type, self._schema, self._fmt, self.size)
        for names in self._schema:

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

class Struct:
    def __init__(self, *fields):
        fmts = ['<']
        names = []
        for fld in fields:
            fmt, name = fld.split(':', 1)
            fmts.append(fmt)
            names.append(name.split(':'))

        self._names = names
        self._fmt = ''.join(fmts)
        self.size = struct.calcsize(self._fmt)

    def __call__(self, **kw):
        r = _StructInstance(self, self._names, self._fmt, self.size)
        for names in self._names:
            for name in names:
                setattr(r, name, kw.get(name, 0))
        return r

    def _parse(self, data):
        fields = struct.unpack(self._fmt, data)
        r = _StructInstance(self, self._names, self._fmt, self.size)
        for fld, names in zip(fields, self._names):
            for name in names:
                setattr(r, name, fld)
        return r

    def parse(self, fin):
        data = fin.read(self.size)
        if len(data) != self.size:
            raise StructParseError('Prematurely reached EOF')
        return self._parse(data)

    def parse_blob(self, blob):
        return self._parse(bytes(blob[:self.size]))

    def parse_all(self, blob):
        if len(blob) != self.size:
            raise StructParseError('Size mismatch')
        return self._parse(bytes(blob))

