# RE-LLM: Reverse engineering Langueage model
A smart reverse engineering assistant powered by LLMs. This tool analyzes raw binaries or function chunks, extracts disassembly and metadata via `radare2`, and sends structured prompts to a local LLM (via Ollama) to explain function behavior, detect vulnerabilities, extract strings/IPs, and detect obfuscation patterns.

Ideal for :
- Malware Analysis
- Security researchers
- CTF players

## Features 
- Dissassembly-based function analysis using `radare2` 
- Natural language explanations via local LLM 
- Obfuscation detection and vulnerability hinting
- IOC extraction ( IPs, domains, hardcoded strings )

