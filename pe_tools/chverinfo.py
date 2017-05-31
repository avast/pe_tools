import argparse, sys
from .pe_parser import parse_pe, IMAGE_DIRECTORY_ENTRY_RESOURCE
from .rsrc import parse_pe_resources, pe_resources_prepack
from .blob import IoBlob
from .version_info import parse_version_info

RT_VERSION = 16

class Version:
    def __init__(self, s):
        self._parts = [int(part) for part in s.split('.')]
        if not self._parts or len(self._parts) > 4 or any(part < 0 or part >= 2**16 for part in self._parts):
            raise ValueError('invalid version')

        while len(self._parts) < 4:
            self._parts.append(0)

    def get_ms_ls(self):
        ms = self._parts[0] << 16 + self._parts[1]
        ls = self._parts[2] << 16 + self._parts[3]
        return ms, ls

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file-ver', type=Version)
    ap.add_argument('--product-ver', type=Version)
    ap.add_argument('--remove-signature', action='store_true')
    ap.add_argument('--ignore-trailer', action='store_true')
    ap.add_argument('--remove-trailer', action='store_true')
    ap.add_argument('--output', '-o')
    ap.add_argument('file')

    args = ap.parse_args()

    if not args.output:
        args.output = args.file + '.out'

    fin = IoBlob(open(args.file, 'rb'))

    pe = parse_pe(fin)
    if pe.has_signature():
        if not args.remove_signature and not args.remove_trailer:
            print('error: the file contains a signature', file=sys.stderr)
            return 1

        pe.remove_signature()

    if pe.has_trailer():
        if not args.ignore_trailer and not args.remove_trailer:
            print('error: the file contains trailing data', file=sys.stderr)
            return 1

        if args.remove_trailer:
            pe.remove_trailer()

    if not pe.has_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE):
        return 0

    rsrc_slice = pe.find_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)
    rsrc_blob = pe.get_vm(rsrc_slice.start, rsrc_slice.stop)

    rsrc = parse_pe_resources(rsrc_blob, rsrc_slice.start)
    if RT_VERSION not in rsrc:
        return 0

    for name in rsrc[RT_VERSION]:
        for lang in rsrc[RT_VERSION][name]:
            vi = parse_version_info(rsrc[RT_VERSION][name][lang])

            fi = vi.get_fixed_info()

            if args.file_ver:
                fi.dwFileVersionMS, fi.dwFileVersionLS = args.file_ver.get_ms_ls()

            if args.product_ver:
                fi.dwProductVersionMS, fi.dwProductVersionLS = args.product_ver.get_ms_ls()

            vi.set_fixed_info(fi)

            rsrc[RT_VERSION][name][lang] = vi.pack()

    prepacked = pe_resources_prepack(rsrc)
    sl = pe.resize_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size)
    pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(sl.start))

    with open(args.output, 'wb') as fout:
        pe.store(fout)

    return 0
