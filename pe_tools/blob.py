import struct

def join_blobs(iterable):
    blobs = [b for b in iterable if len(b)]
    if not blobs:
        return b''

    if len(blobs) == 1:
        return blobs[0]

    return _SeqBlob(blobs)

def write_blob(fout, blob):
    chunk = 1024*1024

    while blob:
        ch = blob[:chunk]
        fout.write(bytes(ch))
        blob = blob[chunk:]

class Blob:
    def seek(self, offs):
        return _BlobStream(self, offs)

    def load(self, offs, fmt):
        size = struct.calcsize(fmt)
        s = self.to_bytes(offs, size)
        return struct.unpack(fmt, s)

    def __bytes__(self):
        return self.to_bytes(0, len(self))

    def __nonzero__(self):
        return len(self) != 0

    def __bool__(self):
        return len(self) != 0

    def __getitem__(self, key):
        if not isinstance(key, slice):
            return self.to_bytes(key, 1)

        start, stop, step = key.indices(len(self))
        if step != 1:
            raise IndexError('only step 1 is allowed')

        return _SubBlob(self, start, stop)

    def __add__(self, rhs):
        return join_blobs([self, rhs])

    def __radd__(self, lhs):
        return join_blobs([lhs, self])

class IoBlob(Blob):
    def __init__(self, fileobj, size=-1):
        self._fileobj = fileobj
        self._fileobj_size = size if size != -1 else fileobj.seek(0, 2)

    def __len__(self):
        return self._fileobj_size

    def __repr__(self):
        return 'IoBlob({!r})[:{}]'.format(self._fileobj, self._fileobj_size)

    def __bytes__(self):
        self._file

    def to_bytes(self, offs, size):
        assert 0 <= offs <= self._fileobj_size
        assert 0 <= size
        assert offs + size <= self._fileobj_size

        self._fileobj.seek(offs)
        s = self._fileobj.read(size)
        if len(s) == size:
            return s

        r = [s]
        last = offs + size
        offs += len(s)
        while offs < last:
            s = self._fileobj.read(last - offs)
            if not s:
                raise RuntimeError('failed to read blob from stream')
            r.append(s)
            offs += len(s)

        return b''.join(r)

class PadBlob(Blob):
    def __init__(self, size, pad=b'\0'):
        self._size = size
        self._pad = pad

    def __len__(self):
        return self._size

    def to_bytes(self, offs, size):
        assert 0 <= offs <= self._size
        assert 0 <= size
        assert offs + size <= self._size

        return self._pad * size

class _SeqBlob(Blob):
    def __init__(self, blobs):
        self._blobs = blobs
        self._size = sum(len(b) for b in blobs)

    def __len__(self):
        return self._size

    def to_bytes(self, offs, size):
        assert 0 <= offs <= self._size
        assert 0 <= size
        assert offs + size <= self._size

        r = []

        for b in self._blobs:
            if size == 0:
                break

            if offs < len(b):
                ch = min(len(b), size)
                s = bytes(b[offs:offs + ch])
                r.append(s)
                offs = 0
                size -= len(s)
            else:
                offs -= len(b)

        return b''.join(r)

    def __add__(self, rhs):
        return join_blobs(self._blobs + [rhs])

    def __radd__(self, lhs):
        return join_blobs([lhs] + self._blobs)

class _SubBlob(Blob):
    def __init__(self, blob, start, stop):
        self._blob = blob
        self._start = start
        self._size = stop - start

    def __len__(self):
        return self._size

    def __repr__(self):
        return '{!r}[{}:{}]'.format(self._blob, self._start, self._start + self._size)

    def to_bytes(self, offs, size):
        assert 0 <= offs <= self._size
        assert 0 <= size
        assert offs + size <= self._size

        if isinstance(self._blob, Blob):
            return self._blob.to_bytes(self._start + offs, size)
        else:
            return bytes(self._blob[self._start + offs: self._start + offs + size])

    def __getitem__(self, key):
        if not isinstance(key, slice):
            return self.read(self._start + key, 1)

        start, stop, step = key.indices(self._size)
        if step != 1:
            raise IndexError('only step 1 is allowed')

        return _SubBlob(self._blob, self._start + start, self._start + stop)

class _BlobStream:
    def __init__(self, blob, offs):
        self._blob = blob
        self._offs = offs
        self._fp = 0

    def read(self, size=-1):
        rem = len(self._blob) - (self._offs + self._fp)
        if size == -1 or size > rem:
            size = rem

        if size <= 0:
            return b''

        start = self._offs + self._fp

        r = bytes(self._blob[start:start + size])
        self._fp += len(r)
        return r
