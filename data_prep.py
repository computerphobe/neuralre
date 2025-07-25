import os
import json
import time
from tqdm import tqdm
from ollama import Client

# === CONFIGURATION ===
train_dir = "./dataset/train"  # <-- Update this
output_dir = "summary_output"
use_dummy = False  # Set to True to simulate summaries
model_name = "deepseek-r1:7b"
chunk_size = 100000  # Large chunks for 128k token context
chunk_overlap = 2000

# === ENSURE OUTPUT DIRECTORY EXISTS ===
os.makedirs(output_dir, exist_ok=True)

# === OLLAMA CLIENT ===
ollama_client = Client(host='http://localhost:11434')

# === SUMMARIZER ===
def dummy_summary(chunk):
    time.sleep(0.2)
    return "This is a dummy summary of the chunk."

def ollama_summary(chunk):
    try:
        prompt = f"""
You are a malware reverse engineering assistant. Given the following x86 assembly code from a disassembled malware binary, generate a high-level summary of what the code does.

Assembly:
```
{chunk}
```

Summary:
"""
        response = ollama_client.generate(model=model_name, prompt=prompt)
        return response['response'].strip()
    except Exception as e:
        return f"[ERROR: {e}]"

# === UTIL ===
def read_file_chunks(filepath, chunk_size=100000, overlap=2000):
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    chunks = []
    i = 0
    while i < len(lines):
        chunk = lines[i:i+chunk_size]
        chunks.append("".join(chunk))
        i += chunk_size - overlap
    return chunks

# === MAIN ===
if __name__ == "__main__":
    asm_files = [f for f in os.listdir(train_dir) if f.endswith(".asm")]
    print(f"[*] Found {len(asm_files)} .asm files.")

    if not asm_files:
        print("[X] No .asm files found. Check your train_dir path.")
        exit(1)

    for idx, asm_file in enumerate(tqdm(asm_files[:500], desc="[+] Processing files")):
        full_path = os.path.join(train_dir, asm_file)
        print(f"\n[>] Processing file {idx+1}/{len(asm_files)}: {asm_file}")

        try:
            chunks = read_file_chunks(full_path, chunk_size, chunk_overlap)
            print(f"    [*] Split into {len(chunks)} chunks")

            all_summaries = []
            for cidx, chunk in enumerate(chunks):
                print(f"        [-] Summarizing chunk {cidx+1}/{len(chunks)}")
                summary = dummy_summary(chunk) if use_dummy else ollama_summary(chunk)
                all_summaries.append(summary)

            combined_summary = "\n".join(all_summaries)
            output_path = os.path.join(output_dir, asm_file.replace(".asm", ".json"))
            with open(output_path, "w") as f:
                json.dump({"file": asm_file, "summary": combined_summary}, f, indent=2)

            print(f"    [✓] Summary saved to {output_path}")

        except Exception as e:
            print(f"[X] Error processing {asm_file}: {e}")
            continue

    print("[✓] Summary generation completed.")
