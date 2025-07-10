import argparse
from static_analysis.r2pipeline import analyse_binary
from core.engine import prompt_builder
from llm.ollama_runner import llm_query

def list_fn(functions):
    print("[+] Available functions")
    for i, fn in enumerate(functions):
        print(f"[{i}] {fn['name']} @ {fn['address']} ( size: {fn['size']} bytes)")


def main():
    parser = argparse.ArgumentParser(description="RE-LLM - reverse engineering LLM")
    parser.add_argument('--binary', '-b', required=True, help='path to the binary file')
    parser.add_argument('--function', '-f', help='Function index or address to analyze (optional)')
    parser.add_argument('--mode', '-m' , default="summarize", choices=['summarize', 'obfuscation', 'vuln_analysis'], help='analysis mode')
    parser.add_argument('--model', default="phi3", help='Model name in ollama ( default: phi3 )')

    args = parser.parse_args()

    print(f'[~] Analyzing binary: {args.binary}')
    functions = analyse_binary(args.binary)
    if not functions:
        print("[X] No functions found")
        return
    fn = None
    if args.function:
        try:
            idx = int(args.function)
            fn = functions[idx]
        except ValueError:
            addr = int(args.function, 16)
            fn = next((f for f in functions if int(f['address'], 16)==addr), None)
    else:
        list_fn(functions)
        choice = int(input("Select function index to analyse: "))
        fn = functions[choice]
    if not fn:
        print("[ ! ] could not locate the reqested function to analyze")
        return
    
    print(f"\n[~] Analyzing function {fn['name']} @ {fn['address']} with mode: {args.mode}")
    prompt = prompt_builder(args.mode, fn)
    response = llm_query(prompt, model=args.model)

    print("[ ! ] LLM response: \n " + "="*40)
    print(response)
    print("="*40)

if __name__ == "__main__":
    main()