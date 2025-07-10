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

    asm_lines = []

    for instr in fn_data['disassembly']:
        asm_lines.append(f"{instr['opcode']}")
    
    context = {
        'name': fn_data['name'],
        'address': fn_data['address'],
        'imports': [imp['name'] for imp in fn_data.get('imports', [])],
        'strings': [s['string'] for s in fn_data.get('strings', [])],
        'disassembly': "\n".join(asm_lines)
    }

    return template.render(**context)

