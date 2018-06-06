import argparse, sys, re, tempfile, os
import xml.dom.minidom
import grope
from .pe_parser import parse_pe, IMAGE_DIRECTORY_ENTRY_RESOURCE
from .rsrc import parse_pe_resources, pe_resources_prepack, parse_prelink_resources
from .version_info import parse_version_info

RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3
RT_MENU = 4
RT_DIALOG = 5
RT_STRING = 6
RT_FONTDIR = 7
RT_FONT = 8
RT_ACCELERATOR = 9
RT_RCDATA = 10
RT_MESSAGETABLE = 11
RT_GROUP_CURSOR = 12
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_DLGINCLUDE = 17
RT_PLUGPLAY = 19
RT_VXD = 20
RT_ANICURSOR = 21
RT_ANIICON = 22
RT_HTML = 23
RT_MANIFEST = 24

class Version:
    def __init__(self, s):
        parts = s.split(',')
        if len(parts) == 1:
            parts = parts[0].split('.')
        self._parts = [int(part.strip()) for part in parts]
        if not self._parts or len(self._parts) > 4 or any(part < 0 or part >= 2**16 for part in self._parts):
            raise ValueError('invalid version')

        while len(self._parts) < 4:
            self._parts.append(0)

    def get_ms_ls(self):
        ms = (self._parts[0] << 16) + self._parts[1]
        ls = (self._parts[2] << 16) + self._parts[3]
        return ms, ls

    def format(self):
        return ', '.join(str(part) for part in self._parts)

class _IdentityReplace:
    def __init__(self, val):
        self._val = val

    def __call__(self, s):
        return self._val

class _ReReplace:
    def __init__(self, compiled_re, sub):
        self._compiled_re = compiled_re
        self._sub = sub

    def __call__(self, s):
        return self._compiled_re.sub(self._sub, s)

def main():
    ap = argparse.ArgumentParser(fromfile_prefix_chars='@')
    ap.add_argument('--remove-signature', action='store_true')
    ap.add_argument('--ignore-trailer', action='store_true')
    ap.add_argument('--remove-trailer', action='store_true')
    ap.add_argument('--ignore-checksum', action='store_true')
    ap.add_argument('--rebrand', type=argparse.FileType('rb'))
    ap.add_argument('--manifest-deps', action='append')
    ap.add_argument('--output', '-o')
    ap.add_argument('file')
    ap.add_argument('strings', nargs='*')

    args = ap.parse_args()

    if args.rebrand is not None:
        rebrand_rsrc = parse_prelink_resources(grope.BlobIO(args.rebrand))

    params = {}
    for param in args.strings:
        toks = param.split('=', 1)
        if len(toks) != 2:
            print('error: strings must be in the form "name=value"', file=sys.stderr)
            return 2
        name, value = toks

        if value.startswith('/'):
            pattern, sub = value[1:-1].split('/', 1)
            r = re.compile(pattern)
            params[name] = _ReReplace(r, sub)
        else:
            params[name] = _IdentityReplace(value)

    fin = open(args.file, 'rb')

    pe = parse_pe(grope.wrap_io(fin), ignore_checksum=args.ignore_checksum)
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
    if rsrc_slice is None:
        print('warning: there are no resources in the file: {}'.format(args.file), file=sys.stderr)
        return 0

    if not pe.is_dir_safely_resizable(IMAGE_DIRECTORY_ENTRY_RESOURCE):
        print('error: the resource section is not resizable: {}'.format(args.file), file=sys.stderr)
        return 3

    rsrc_blob = pe.get_vm(rsrc_slice.start, rsrc_slice.stop)

    rsrc = parse_pe_resources(rsrc_blob, rsrc_slice.start)

    if args.manifest_deps:
        new_man = ['<dependency>']
        for man in args.manifest_deps:
            new_man.append('<dependentAssembly><assemblyIdentity {}></assemblyIdentity></dependentAssembly>'.format(man))
        new_man.append('</dependency>')
        new_dep_node = xml.dom.minidom.parseString(''.join(new_man)).documentElement

        if RT_MANIFEST in rsrc:
            for name in rsrc[RT_MANIFEST]:
                for lang in rsrc[RT_MANIFEST][name]:
                    m = rsrc[RT_MANIFEST][name][lang]

                    man = xml.dom.minidom.parseString(bytes(m))

                    assembly_node = man.documentElement
                    for dep_elem in assembly_node.getElementsByTagName('dependency'):
                        assembly_node.removeChild(dep_elem)

                    assembly_node.insertBefore(new_dep_node, assembly_node.firstChild)

                    new_man = b'\xef\xbb\xbf' + man.toxml('UTF-8')
                    rsrc[RT_MANIFEST][name][lang] = new_man

    if RT_VERSION not in rsrc:
        print('warning: there is no version info in the file {}'.format(args.file), file=sys.stderr)

    if args.rebrand is not None:
        new_rsrc = rebrand_rsrc
        if RT_MANIFEST in rsrc:
            new_rsrc[RT_MANIFEST] = rsrc[RT_MANIFEST]
        rsrc = new_rsrc

    for name in rsrc.get(RT_VERSION, []):
        for lang in rsrc[RT_VERSION][name]:
            vi = parse_version_info(rsrc[RT_VERSION][name][lang])

            fi = vi.get_fixed_info()

            if 'FileVersion' in params:
                ver = Version(params['FileVersion'](None))
                fi.dwFileVersionMS, fi.dwFileVersionLS = ver.get_ms_ls()

            if 'ProductVersion' in params:
                ver = Version(params['ProductVersion'](None))
                fi.dwProductVersionMS, fi.dwProductVersionLS = ver.get_ms_ls()

            vi.set_fixed_info(fi)

            sfi = vi.string_file_info()
            for (langid, cp), strings in sfi.items():
                for k, fn in params.items():
                    val = fn(strings.get(k, ''))
                    if val:
                        strings[k] = val
                    elif k in strings:
                        del strings[k]
            vi.set_string_file_info(sfi)

            rsrc[RT_VERSION][name][lang] = vi.pack()

    prepacked = pe_resources_prepack(rsrc)
    addr = pe.resize_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size)
    pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(addr))

    if not args.output:
        fout, fout_name = tempfile.mkstemp(dir=os.path.split(args.file)[0])
        fout = os.fdopen(fout, mode='w+b')
        try:
            grope.dump(pe.to_blob(), fout)

            fin.close()
            fout.close()
        except:
            fout.close()
            os.remove(fout_name)
            raise
        else:
            os.remove(args.file)
            os.rename(fout_name, args.file)

    else:
        with open(args.output, 'wb') as fout:
            grope.dump(pe.to_blob(), fout)

    return 0

if __name__ == '__main__':
    main()
