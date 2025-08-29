import streamlit as st
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ..static_analysis.r2pipeline import analyse_binary
from core.engine import prompt_builder
from llm.gemini import gemini_query

st.set_page_config(page_title="RE-LLM - Reverse Engineering Assistant")

st.title("🔍 RE-LLM - Reverse Engineering LLM")

uploaded_file = st.file_uploader("Upload a binary to analyze (.exe, ELF)", type=["exe", "bin", "elf"])

mode = st.selectbox("Analysis Mode", ["summarize", "vuln_analysis", "obfuscation"])

if uploaded_file:
    binary_path = f"temp/{uploaded_file.name}"
    os.makedirs("temp", exist_ok=True)

    with open(binary_path, "wb") as f:
        f.write(uploaded_file.read())

    st.success("Binary uploaded and saved.")

    functions = analyse_binary(binary_path)

    if not functions:
        st.error("No functions found in binary.")
    else:
        fn_names = [f"{i}: {fn['name']} @ {fn['address']}" for i, fn in enumerate(functions)]
        fn_choice = st.selectbox("Choose a function to analyze", fn_names)
        fn_idx = int(fn_choice.split(":")[0])
        fn = functions[fn_idx]

        st.code(
            "\n".join(
                f"{instr['offset']:08x}: {instr['opcode']}"
                for instr in fn["disassembly"]
                if "offset" in instr and "opcode" in instr
            ),
            language="asm"
        )

        if st.button("🧠 Analyze with Gemini"):
            prompt = prompt_builder(mode, fn)
            with st.spinner("Sending to Gemini..."):
                response = gemini_query(prompt)

            st.subheader("🧠 Gemini Output")
            st.markdown(response)
