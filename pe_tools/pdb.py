from typing import NamedTuple
from .pe_parser import _IMAGE_SECTION_HEADER
from . import cvinfo as cv
from grope import rope, BlobIO
from .struct3 import Struct3, char, u32, i32, u16
import struct

pdb_signature = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'

class PdbFileHeader(Struct3):
    magic: char[len(pdb_signature)]
    block_size: u32
    free_block: u32
    block_count: u32
    directory_size: u32
    _reserved: u32

class DbiStreamHeader(Struct3):
    VersionSignature: u32
    VersionHeader: u32
    Age: u32
    GlobalStreamIndex: u16
    BuildNumber: u16
    PublicStreamIndex: u16
    PdbDllVersion: u16
    SymRecordStream: u16
    PdbDllRbld: u16
    ModInfoSize: i32
    SectionContributionSize: i32
    SectionMapSize: i32
    SourceInfoSize: i32
    TypeServerMapSize: i32
    MFCTypeServerIndex: u32
    OptionalDbgHeaderSize: i32
    ECSubstreamSize: i32
    Flags: u16
    Machine: u16
    Padding: u32

class SectionContribEntry2(Struct3):
    Section: u16
    Padding1: char[2]
    Offset: i32
    Size: i32
    Characteristics: u32
    ModuleIndex: u16
    Padding2: char[2]
    DataCrc: u32
    RelocCrc: u32
    ISectCoff: u32

class SectionMapHeader(Struct3):
    Count: u16
    LogCount: u16

class SectionMapEntry(Struct3):
  Flags: u16
  Ovl: u16
  Group: u16
  Frame: u16
  SectionName: u16
  ClassName: u16
  Offset: u32
  SectionLength: u32

class PublicSymbol(NamedTuple):
    name: str
    segment: int
    offset: int
    rva: int

class PdbFile:
    def __init__(self, blob, block_size, streams):
        self._blob = blob
        self._block_size = block_size
        self._streams = streams
        self._stream_bytes = [None]*len(streams)

        self._dbihdr = None
        self._sections = None
        self._addr_map = None

    def _parse_dbi(self):
        if self._dbihdr is not None:
            return

        dbi = self.get_stream(3)
        hdr = DbiStreamHeader.unpack_from(dbi)

        offs = hdr.size + hdr.ModInfoSize + hdr.SectionContributionSize + hdr.SectionMapSize + hdr.SourceInfoSize + hdr.TypeServerMapSize + hdr.ECSubstreamSize

        cnt = hdr.OptionalDbgHeaderSize // 2
        debug_streams = struct.unpack_from(f'<{cnt}h', dbi, offs)

        secstream = self.get_stream(debug_streams[5])
        offs = 0

        sections = []
        while offs < len(secstream):
            sections.append(_IMAGE_SECTION_HEADER.unpack_from(secstream, offs))
            offs += _IMAGE_SECTION_HEADER.size
        self._sections = sections

        addr_map = []

        offs = hdr.size + hdr.ModInfoSize + hdr.SectionContributionSize
        maphdr = SectionMapHeader.unpack_from(dbi, offs)
        offs += maphdr.size
        for _ in range(maphdr.Count):
            entry = SectionMapEntry.unpack_from(dbi, offs)
            offs += entry.size

            if entry.Frame:
                addr_map.append(sections[entry.Frame - 1].VirtualAddress)
            else:
                addr_map.append(0)

        self._addr_map = addr_map
        self._dbihdr = hdr

    def machine_type(self):
        self._parse_dbi()
        return self._dbihdr.Machine

    def get_public_symbols(self):
        self._parse_dbi()
        hdr = self._dbihdr

        syms = self.get_stream(hdr.SymRecordStream)

        offs = 0
        while offs < len(syms):
            reclen, rectp = struct.unpack_from('<HH', syms, offs)
            eoffs = offs + reclen + 2

            if rectp == cv.S_PUB32:
                symhdr = cv.PUBSYM32.unpack_from(syms, offs + 4)
                syms: bytes
                npos = offs + 4 + cv.PUBSYM32.size
                zpos = syms.find(0, npos, eoffs)
                if zpos < 0:
                    raise RuntimeError('missing null termination')
                name = syms[npos:zpos].decode('utf-8')
                if symhdr.seg != 0:
                    rva = self._addr_map[symhdr.seg - 1] + symhdr.off
                else:
                    rva = 0

                yield PublicSymbol(name, symhdr.seg, symhdr.off, rva)

            offs = eoffs

    def get_rva(self, seg, offs):
        pass

    def get_stream(self, idx):
        r = self._stream_bytes[idx]
        if r is None:
            blocks, size = self._streams[idx]
            r = bytearray(size)
            offs = 0
            for block in blocks[:-1]:
                r[offs:offs+self._block_size] = bytes(self._blob[block*self._block_size:][:self._block_size])
                offs += self._block_size
            size = len(r) - offs
            r[offs:] = self._blob[blocks[-1]*self._block_size:][:size]
            r = bytes(r)
            self._stream_bytes[idx] = r
        return r

def parse_pdb(blob):
    hdr = PdbFileHeader.unpack_from(blob)
    if hdr.magic != pdb_signature:
        raise RuntimeError('not a PDB file (wrong signature)')

    def make_pdb_stream(blocks, size):
        r =  rope(*(blob[hdr.block_size*block:][:hdr.block_size] for block in blocks))
        return r[:size]

    metadirectory_size = (hdr.directory_size + (hdr.block_size - 1)) // hdr.block_size * 4
    metadirectory_block_count = (metadirectory_size + (hdr.block_size - 1)) // hdr.block_size
    metadirectory_blocks = struct.unpack_from(f'<{metadirectory_block_count}I',
        bytes(blob[PdbFileHeader.size:][:metadirectory_block_count*4]))

    metadirectory = make_pdb_stream(metadirectory_blocks, metadirectory_size)
    directory_block_count = len(metadirectory) // 4
    directory_blocks = struct.unpack_from(f'<{directory_block_count}I', bytes(metadirectory))

    directory = make_pdb_stream(directory_blocks, hdr.directory_size)

    stream_count, = struct.unpack('<I', bytes(directory[:4]))

    idx = 4 + stream_count*4
    stream_sizes = struct.unpack(f'<{stream_count}I', bytes(directory[4:idx]))

    streams = []
    for stream_size in stream_sizes:
        if stream_size == 0xffff_ffff:
            streams.append(None)
            continue

        stream_block_count = (stream_size + (hdr.block_size - 1)) // hdr.block_size
        next_idx = idx + stream_block_count * 4
        stream_blocks = struct.unpack(f'<{stream_block_count}I', bytes(directory[idx:next_idx]))
        idx = next_idx
        streams.append((stream_blocks, stream_size))

    return PdbFile(blob, hdr.block_size, streams)
