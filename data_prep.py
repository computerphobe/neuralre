import os
import json
from tqdm import tqdm
import ollama

# === CONFIGURATION ===
MODEL_NAME = "deepseek-r1:7b"
INPUT_DIR = "./dataset/train"
OUTPUT_DIR = "summary_outputs"
BATCH_SIZE = 500
CHUNK_SIZE = 80000  # tokens/bytes approx per prompt (adjust if needed for long asm files)

# === LLM-based summarization ===
def summarize_with_deepseek(content):
    prompt = f"""
You are a malware reverse engineering assistant. Given the following x86 assembly code from a disassembled malware binary, generate a high-level summary of what the code does.

Assembly:
```
{content}
```

Summary:
"""
    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt.strip()}]
        )
        return response['message']['content']
    except Exception as e:
        print(f"[!] LLM failed: {e}")
        return "ERROR: LLM failed to summarize."

# === File pairing and processing ===
def get_file_pairs(folder_path):
    files = os.listdir(folder_path)
    asm_files = sorted([f for f in files if f.endswith('.asm')])
    byte_files = sorted([f for f in files if f.endswith('.bytes')])
    return [(asm, asm.replace('.asm', '.bytes')) for asm in asm_files if asm.replace('.asm', '.bytes') in byte_files]

def chunk_content(content, max_len=CHUNK_SIZE):
    lines = content.splitlines()
    chunks, current = [], []
    total_len = 0
    for line in lines:
        line_len = len(line)
        if total_len + line_len > max_len:
            chunks.append("\n".join(current))
            current = []
            total_len = 0
        current.append(line)
        total_len += line_len
    if current:
        chunks.append("\n".join(current))
    return chunks

def process_batch(folder_path, pairs, batch_index, output_dir):
    summaries = {}
    for asm_file, _ in tqdm(pairs, desc=f"Batch {batch_index+1}"):
        asm_path = os.path.join(folder_path, asm_file)
        try:
            with open(asm_path, 'r', errors='ignore') as f:
                content = f.read()

            chunks = chunk_content(content)
            summaries_for_chunks = []
            for chunk in chunks:
                summary = summarize_with_deepseek(chunk)
                summaries_for_chunks.append(summary)

            final_summary = "\n".join(summaries_for_chunks)
            summaries[asm_file] = final_summary

        except Exception as e:
            print(f"[!] Failed to process {asm_file}: {e}")
            continue

    output_path = os.path.join(output_dir, f'summaries_batch_{batch_index+1}.json')
    with open(output_path, 'w') as f:
        json.dump(summaries, f, indent=2)

    print(f"[✓] Saved {len(summaries)} summaries to {output_path}")

# === Main runner ===
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    pairs = get_file_pairs(INPUT_DIR)
    print(f"[*] Total samples: {len(pairs)}")
    total_batches = (len(pairs) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(total_batches):
        start = i * BATCH_SIZE
        end = min((i + 1) * BATCH_SIZE, len(pairs))
        current_batch = pairs[start:end]
        process_batch(INPUT_DIR, current_batch, i, OUTPUT_DIR)

if __name__ == "__main__":
    main()
