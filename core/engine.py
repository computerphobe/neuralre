from jinja2 import Environment, FileSystemLoader
import os

template_dir = os.path.join(os.path.dirname(__file__), '..', 'prompts')
env = Environment(loader=FileSystemLoader(template_dir))

def prompt_builder(mode, fn_data):
    """
    mode: 'summarize', 'obfuscation', 'vuln_analysis'
    fn_data: dictionary from r2 pipeline
    """
    template = env.get_template(f"{mode}.txt")

    asm_lines = [
        f"{instr['offset']:08x}: {instr['opcode']}"
        for instr in fn_data["disassembly"]
        if 'opcode' in instr and 'offset' in instr
    ]
    print("assembly lines",asm_lines)
    context = {
        'name': fn_data['name'],
        'address': fn_data['address'],
        'imports': [imp['name'] for imp in fn_data.get('imports', []) if 'name' in imp],
        'strings': [s['string'] for s in fn_data.get('strings', []) if 'string' in s],
        'disassembly': "\n".join(asm_lines)
    }

    return template.render(**context)
