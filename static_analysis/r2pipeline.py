import r2pipe
import os

def analyse_binary(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')  # analyze all

    functions = r2.cmdj('aflj')
    if not functions:
        print('[!] No functions found')
        r2.quit()
        return []

    all_strings = r2.cmdj('izj') or []
    all_imports = r2.cmdj('iij') or []

    results = []

    for fn in functions:
        try:
            addr = fn['offset']
            name = fn.get('name', f'func_{addr:x}')
            disasm = r2.cmdj(f'pdrj @ {addr}') or []

            fn_data = {
                'name': name,
                'address': hex(addr),
                'size': fn['size'],
                'disassembly': disasm,
                'strings': [s for s in all_strings if 'string' in s],
                'imports': [imp for imp in all_imports if 'name' in imp]
            }

            results.append(fn_data)
        except Exception as e:
            print(f"[!] Error parsing function at addr {addr:x}: {e}")
    r2.quit()
    return results

def extract_full_disassembly(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')

    disasm_json = r2.cmdj('pdj 5000') or []  # Disassemble 5000 instructions max
    strings = r2.cmdj('izj') or []
    imports = r2.cmdj('iij') or []

    r2.quit()

    return {
        'binary': os.path.basename(filepath),
        'disassembly': disasm_json,
        'strings': [s for s in strings if 'string' in s],
        'imports': [imp for imp in imports if 'name' in imp]
    }

def print_assembly(disasm):
    print("\n📜 Assembly Instructions:")
    for instr in disasm:
        offset = instr.get("offset")
        opcode = instr.get("opcode")
        if offset is not None and opcode:
            print(f"{offset:08x}: {opcode}")

def print_fn_info(fn_data):
    print(f"\n=== Function: {fn_data['name']} @ {fn_data['address']} ===")
    print_assembly(fn_data.get('disassembly', []))

    print("\n📦 Imports:")
    for imp in fn_data.get('imports', []):
        print(f" - {imp.get('name', '<unknown>')}")

    print("\n🔍 Strings:")
    for s in fn_data.get('strings', []):
        print(f" - {s.get('string', '')}")

# CLI Test Mode
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("[!] Missing arguments")
        print(f"[!] Usage: python {sys.argv[0]} <binary_file_path>")
        exit(1)

    binary_path = sys.argv[1]
    output = analyse_binary(binary_path)

    print(f"[+] Extracted {len(output)} functions.")
    if output:
        print_fn_info(output[0])
