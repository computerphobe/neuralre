import subprocess
import json

def llm_query(prompt, model="phi3", sys_msg=None):
    payload = {
        "model":model,
        "message": []
    }

    if sys_msg:
        payload["message"].append({"role":"system", "content": sys_msg})

    payload['message'].append({"role":"user", "content":prompt})

    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=json.dumps(payload),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("[!] Ollama Error: ", result.stderr)
            return ""
        return result.stdout.strip()
    
    except Exception as e:
        print("[!] Error running ollama : ", e)
        return ""
    
