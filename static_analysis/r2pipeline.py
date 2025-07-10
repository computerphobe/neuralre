import r2pipe
import json

def analyse_binary(filepath):
    r2  = r2pipe.open(filepath)
    r2.cmd('aaa')

    functions = r2.cmdj('aflj')
    if not functions:
        print('[!] No functions found')
        return []
    
    all_strings = r2.cmdj('izj') or []
    all_imports = r2.cmdj('iij') or []

    results = []

    for fn in functions:
        try:
            addr = fn['offset']
            name = fn.get('name', f'func_addr{addr:x}')
            disasm = r2.cmdj(f'pdrj @ {addr}') # Disassemble functions as json
            
            fn_data = {
                'name':name,
                'address':hex(addr),
                'size': fn['size'],
                'disassembly': disasm,
                'strings': all_strings,
                'imports': all_imports
            }
            results.append(fn_data)
        except Exception as e:
            print(f"[!] Error parsing function at addr : {addr:x} : Error : {e}")
    r2.quit()
    return results

if __name__ == "__main__":
    import sys
    import pprint
    if len(sys.argv) != 2:
        print("[!] missing arguments")
        print(f"[!] Useage : python {sys.argv[0]} <binary_file_path>")
        exit(1)
    
    binary_path = sys.argv[1]
    output = analyse_binary(binary_path)

    print(f"[+] Extracted {len(output)} functions. \n")
    pprint.pprint(output[0])
