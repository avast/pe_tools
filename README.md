# pe-tools

A toolkit for parsing/writing PE files and some of its internal structures.

Requires Python3. Install using the following command.

    python3 setup.py install

This installs the `pe_tools` module you can use in your Python scripts and command line tools.

## Change version info

Modifies version info embedded in a PE file.

    chverinfo [--rebrand <res-file>] [-o <out-file>] <file> [key=value]...

Key can be any of the following values.

 * FileVersion
 * ProductVersion
 * FileDescription
 * InternalName
 * LegalCopyright
 * OriginalFilename
 * ProductName

For example, to change FileVersion to 1.2.3.4, run the following command.

    chverinfo myfile.exe FileVersion=1.2.3.4

You can save command line arguments to a text file, one argument per line, and then pass the name of this file.

    chverinfo myfile.exe @params.txt

The `--rebrand` option allows you to apply a completely different resource section using a compile resource file.
Rebrand is performed before version info changes.
