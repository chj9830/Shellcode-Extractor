#!/usr/bin/python3
import sys
import os
import subprocess
import getopt


def usage():
    print('Usage: {} [OPTION] <binary>'.format(sys.argv[0]))
    print('Extract shellcode from binary.')
    print('  -h, --help\t\tdisplay this help and exit')
    print('  -b, --base=LABEL,\tExtracts based on label (default: main)')
    print('  -l, --lines=NUM\tExtracts NUM lines')
    sys.exit(1)


def parsing(binary, base, lines):
    objdump = "/usr/bin/objdump"
    grep = "/bin/grep"

    print('[*] Parsing binary...')
    try:
        dump = subprocess.Popen([objdump, '-d', binary], stdout=subprocess.PIPE)
        dump = subprocess.check_output([grep, '-A{}'.format(lines), '<{}>:'.format(base)], stdin=dump.stdout, encoding='utf-8')
    except Exception as e:
        print('[-] Parsing failure...')
        print(e)
        sys.exit(1)

    dump = dump.split('\n')
    if not base in dump[0]:
        print('[-] Parsing failure...')
        sys.exit(1)
    else:
        print('[+] Done')
        del dump[0]

    return dump


def extract(dump):
    shellcode = str()
    for line in dump:
        line = line.split('\t')
        if len(line) < 2:
            break
        opcode = line[1]
        if len(line) >= 3:
            mnemonic = line[2]
        else:
            mnmonic = None
        shellcode += opcode.replace(' ', '')

    return shellcode


def print_result(shellcode):
    print('Shellcode: ', end='')
    for i in range(0, len(shellcode), 2):
        print('\\x' + shellcode[i:i+2], end='')
    print()
    print('Length: {}'.format(int(len(shellcode) / 2)))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()

    bases = ["main"]
    lines = 1024

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hb:l:", ["base=", "lines="])
    except getopt.GetoptError as err:
        usage()

    for opt, arg in opts:
        if opt in ('-b', '--base'):
            bases = arg.split(',')
        elif opt in ('-l', '--lines'):
            lines = int(arg)
        elif opt in ('-h', '--help'):
            usage()

    binary = os.path.abspath(sys.argv[-1])

    shellcode = str()

    for base in bases:
        dump = parsing(binary, base, lines)
        shellcode += extract(dump)

    print_result(shellcode)
