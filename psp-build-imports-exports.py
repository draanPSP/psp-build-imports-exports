#
# PSP Software Development Kit - https://github.com/pspdev
# -----------------------------------------------------------------------
# Licensed under the BSD license, see LICENSE in PSPSDK root for details.
#
#  psp-build-imports-exports.py - Simple program to build an import or export file.
#
# Copyright (c) 2021 Draan <draanpsp@gmail.com>
#

import argparse
import sys
import re
import hashlib
import pathlib
import logging
import itertools

parser = argparse.ArgumentParser(description='PSP exports/imports builder')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-b', '--build-exports', action='store_true', default=None, help='Build an export file to stdout')
group.add_argument('-s', '--build-stubs', action='store_true', help='Build a batch of stub files for the exports')
group.add_argument('-k', '--build-stubs-new', action='store_true', help='Build a batch of stub files for the exports (in new format)')
group.add_argument('-i', '--build-imports', action='store_true', default=None, help='Build an import stub file to stdout')
group.add_argument('-l', '--build-stubs-new-imports', action='store_true', help='Build a batch of stub files for the imports (in new format)')
parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
parser.add_argument('file', type=pathlib.Path)

args = parser.parse_args()

if args.verbose:
    loggingLevel = logging.DEBUG
else:
    loggingLevel = logging.WARNING

logging.basicConfig(stream=sys.stderr, level=loggingLevel)

class Parser:
    SYSTEM_LIB_NAME = 'syslib'

    MAX_LIB_NAME = 27
    MAX_LIB_FUNCS = 65535
    MAX_LIB_VARS = 255
    MAX_LIB_ENTRY_NAME = 127

    ATTRIBUTES = {
        'ATTR_AUTO_EXPORT': 0x1,
        'ATTR_WEAK_EXPORT': 0x2,
        'ATTR_NOLINK_EXPORT': 0x4,
        'ATTR_WEAK_IMPORT': 0x8,
        'ATTR_SYSCALL_EXPORT': 0x4000,
        'ATTR_SYSLIB': 0x8000
    }

    class Library:
        class Entry:
            def __init__(self, name, nid):
                self.name = name
                self.nid = nid

        def __init__(self, name, version, flags):
            if len(name) > Parser.MAX_LIB_NAME:
                raise RuntimeError(f'Library name too long: {name}.')

            self.name = name
            self.version = version
            self.flags = flags

            self.functions = []
            self.variables = []

        def addFunction(self, name, nid):
            if len(name) > Parser.MAX_LIB_ENTRY_NAME:
                raise RuntimeError(f'Function name too long: {name}.')

            if len(self.functions) == Parser.MAX_LIB_FUNCS:
                raise RuntimeError(f'Too many functions for library {self.name}.')

            self.functions.append(self.Entry(name, nid))

        def addVariable(self, name, nid):
            if len(name) > Parser.MAX_LIB_ENTRY_NAME:
                raise RuntimeError(f'Variable name too long: {name}.')

            if len(self.variables) == Parser.MAX_LIB_FUNCS:
                raise RuntimeError(f'Too many variables for library {self.name}.')

            self.variables.append(self.Entry(name, nid))

    def __init__(self):
        self.begin_flag = False
        self.end_flag = False
        self.actions = {}
        self.libraryFlags = {}

        self.currentLib = None
        self.libraries = []

    def parseLine(self, line):
        for action, function in self.actions.items():
            m = action.match(line)
            if m is not None:
                function(m)
                break
        else:
            if len(line) > 1:
                raise RuntimeError('Invalid instruction.')

    def begin(self, match):
        self.begin_flag = True

    def end(self, match):
        self.end_flag = True

    def nameToNid(self, name):
        return int(hashlib.sha1(name.encode('ascii')).hexdigest()[:8].upper()[::-1], base=16)

    def entryStart(self, match):
        args = match.group(1).replace(' ', '').split(',')

        if len(args) != 3:
            raise RuntimeError('Invalid number of arguments.')

        libname = args[0]
        version = int(args[1], base=16)

        # Either a hex value or attribute expression
        try:
            flags = int(args[2], base=16)
        except ValueError:
            attrs = args[2].replace(' ', '').split('|')

            flags = 0
            for a in attrs:
                if a in Parser.ATTRIBUTES:
                    flags |= Parser.ATTRIBUTES[a]
                else:
                    raise RuntimeError('Invalid attribute name.')

        if libname == Parser.SYSTEM_LIB_NAME and not (flags & Parser.ATTRIBUTES['ATTR_SYSLIB']):
            flags |= Parser.ATTRIBUTES['ATTR_SYSLIB']
            logging.warning(f'{Parser.SYSTEM_LIB_NAME} requires '
                            f'ATTR_SYSLIB (0x{Parser.ATTRIBUTES["ATTR_SYSLIB"]:04X}) attribute, but it was not set. '
                            f'The attribute was automatically added.')

        if self.currentLib is not None:
            raise RuntimeError('Library declaration already started. '
                               'Did you forget to end the previous library declaration?')

        self.currentLib = self.Library(libname, version, flags)
        self.libraries.append(self.currentLib)

    def entryEnd(self, match):
        if self.currentLib is None:
            raise RuntimeError('Encountered library declaration ending without a matching start.')

        self.currentLib = None

    def entryFuncHash(self, match):
        args = match.group(1).strip(' ').split(',')

        if self.currentLib is None:
            raise RuntimeError('Not inside a valid library declaration.')

        if len(args) == 1:
            nid = self.nameToNid(args[0])
            self.currentLib.addFunction(args[0], nid)
        else:
            raise RuntimeError('Invalid number of arguments.')

    def entryFuncNid(self, match):
        args = match.group(1).strip(' ').split(',')

        if self.currentLib is None:
            raise RuntimeError('Not inside a valid library declaration.')

        if len(args) == 2:
            nid = int(args[1], base=16)
            self.currentLib.addFunction(args[0], nid)
        else:
            raise RuntimeError('Invalid number of arguments.')

    def entryVarHash(self, match):
        args = match.group(1).strip(' ').split(',')

        if self.currentLib is None:
            raise RuntimeError('Not inside a valid library declaration.')

        if len(args) == 1:
            nid = self.nameToNid(args[0])
            self.currentLib.addVariable(args[0], nid)
        else:
            raise RuntimeError('Invalid number of arguments.')

    def entryVarNid(self, match):
        args = match.group(1).strip(' ').split(',')

        if self.currentLib is None:
            raise RuntimeError('Not inside a valid library declaration.')

        if len(args) == 2:
            nid = int(args[1], base=16)
            self.currentLib.addVariable(args[0], nid)
        else:
            raise RuntimeError('Invalid number of arguments.')

    def entryAlias(self, match):
        args = match.group(1).strip(' ').split(',')

        raise NotImplementedError()

    def libStubs(self, lib, new=False):
        string = ''

        flags_ver = (lib.flags << 16) | lib.version

        numEntries = len(lib.functions)
        stubs_len = (numEntries << 16) | 5

        if new is False:
            string += f'STUB START "{lib.name}", 0x{flags_ver:08X},0x{stubs_len:08X}\n'

            for func in lib.functions:
                string += f'    STUB_FUNC 0x{func.nid:08X}, {func.name}\n'

            string += 'STUB_END\n'
            string += '\n'
        else:
            string += '// Build files\n'
            string += '// ' + ' '.join(f'{lib.name}_{i:04}.o' for i in range(len(lib.functions)+1)) + '\n'
            string += '\n'

            string += f'#ifdef F_{lib.name}_{0:04}\n'
            string += f'    IMPORT_START "{lib.name}",0x{flags_ver:08X}\n'
            string += f'#endif\n'

            for i, func in enumerate(lib.functions):
                string += f'#ifdef F_{lib.name}_{i+1:04}\n'
                string += f'    IMPORT_FUNC "{lib.name}",0x{func.nid:08X},{func.name}\n'
                string += f'#endif\n'

        return string

    def print(self):
        return ''

    def stubs(self, new=False):
        pass

class ExportsParser(Parser):
    def __init__(self):
        super().__init__()

        self.actions = {
            re.compile('PSP_BEGIN_EXPORTS'): self.begin,
            re.compile('PSP_END_EXPORTS'): self.end,
            re.compile('PSP_EXPORT_START\((.+)\)'): self.entryStart,
            re.compile('PSP_EXPORT_END'): self.entryEnd,
            re.compile('PSP_EXPORT_FUNC\((.+)\)'): self.entryFuncHash,
            re.compile('PSP_EXPORT_FUNC_HASH\((.+)\)'): self.entryFuncHash,
            re.compile('PSP_EXPORT_FUNC_NID\((.+)\)'): self.entryFuncNid,
            re.compile('PSP_EXPORT_VAR\((.+)\)'): self.entryVarHash,
            re.compile('PSP_EXPORT_VAR_HASH\((.+)\)'): self.entryVarHash,
            re.compile('PSP_EXPORT_VAR_NID\((.+)\)'): self.entryVarNid,
            re.compile('PSP_EXPORT_ALIAS\((.+)\)'): self.entryAlias
        }

    def print(self):
        string = super().print()

        string += '#include <pspmoduleexport.h>\n'
        string += '#define NULL ((void *) 0)\n'
        string += '\n'

        for lib in self.libraries:
            for entry in itertools.chain(lib.functions, lib.variables):
                string += f'extern int {entry.name};\n'

            string += '\n'

            numEntries = len(lib.functions) + len(lib.variables)

            string += f'static const unsigned int __{lib.name}_exports[{2*numEntries}] __attribute__((section(".rodata.sceResident"))) = {{\n'

            for entry in itertools.chain(lib.functions, lib.variables):
                string += f'    0x{entry.nid:08X},\n'

            for entry in itertools.chain(lib.functions, lib.variables):
                string += f'    (unsigned int) &{entry.name},\n'

            string += '};\n'

            string += '\n'

        numLibraries = len(self.libraries)

        string += f'const struct _PspLibraryEntry __library_exports[{numLibraries}] __attribute__((section(".lib.ent"), used)) = {{\n'

        for lib in self.libraries:
            if lib.name == Parser.SYSTEM_LIB_NAME:
                libname = 'NULL'
            else:
                libname = f'"{lib.name}"'

            string += f'    {{ {libname}, 0x{lib.version:04X}, 0x{lib.flags:04X}, 4, {len(lib.variables)}, {len(lib.functions)}, (unsigned int *) &__{lib.name}_exports }},\n'

        string += '};\n'
        string += '\n'

        return string

    def stubs(self, new=False):
        if new is False:
            for lib in self.libraries:
                if lib.name == Parser.SYSTEM_LIB_NAME:
                    continue

                with open(f'{lib.name}.S', 'w') as f:
                    string = '.set noreorder\n'
                    string += '\n'
                    string += '#include "pspstub.s"\n'
                    string += '\n'

                    string += super().libStubs(lib, new)

                    f.write(string)
        else:
            for lib in self.libraries:
                if lib.name == Parser.SYSTEM_LIB_NAME:
                    continue

                with open(f'{lib.name}.S', 'w') as f:
                    string = '.set noreorder\n'
                    string += '\n'
                    string += '#include "pspimport.s"\n'
                    string += '\n'

                    string += super().libStubs(lib, new)

                    f.write(string)

class ImportsParser(Parser):
    def __init__(self):
        super().__init__()

        self.actions = {
            re.compile('PSP_BEGIN_IMPORTS'): self.begin,
            re.compile('PSP_END_IMPORTS'): self.end,
            re.compile('PSP_IMPORT_START\((.+)\)'): self.entryStart,
            re.compile('PSP_IMPORT_END'): self.entryEnd,
            re.compile('PSP_IMPORT_FUNC\((.+)\)'): self.entryFuncHash,
            re.compile('PSP_IMPORT_FUNC_HASH\((.+)\)'): self.entryFuncHash,
            re.compile('PSP_IMPORT_FUNC_NID\((.+)\)'): self.entryFuncNid,
            re.compile('PSP_IMPORT_VAR\((.+)\)'): self.entryVarHash,
            re.compile('PSP_IMPORT_VAR_HASH\((.+)\)'): self.entryVarHash,
            re.compile('PSP_IMPORT_VAR_NID\((.+)\)'): self.entryVarNid,
            re.compile('PSP_IMPORT_ALIAS\((.+)\)'): self.entryAlias
        }

    def print(self):
        string = super().print()

        string += '.set noreorder\n'
        string += '\n'
        string += '#include "pspstub.s"\n'
        string += '\n'

        for lib in self.libraries:
            string += super().libStubs(lib, new=False)

        return string

    def stubs(self, new=False):
        if new is False:
            for lib in self.libraries:
                if lib.name == Parser.SYSTEM_LIB_NAME:
                    continue

                with open(f'{lib.name}.S', 'w') as f:
                    f.write(self.print())
        else:
            for lib in self.libraries:
                if lib.name == Parser.SYSTEM_LIB_NAME:
                    continue

                with open(f'{lib.name}.S', 'w') as f:
                    string = '.set noreorder\n'
                    string += '\n'
                    string += '#include "pspimport.s"\n'
                    string += '\n'

                    string += super().libStubs(lib, new)

                    f.write(string)

parser = None

if args.build_imports or args.build_stubs_new_imports:
    parser = ImportsParser()
elif args.build_exports or args.build_stubs or args.build_stubs_new:
    parser = ExportsParser()

with open(args.file, 'r') as f:
    for i, line in enumerate(f):
        if line[0] == '#':
            continue
        try:
            parser.parseLine(line)
        except Exception as e:
            logging.error(f'Error parsing line {i}:\n{line}\n{e}')
            sys.exit(1)

if args.build_imports or args.build_exports:
    print(parser.print())
elif args.build_stubs:
    parser.stubs()
elif args.build_stubs_new or args.build_stubs_new_imports:
    parser.stubs(new=True)
