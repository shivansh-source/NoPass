import os
import sys

INPUT_DIR = "/app/input"

def read_file(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def main():
    system_path = os.path.join(INPUT_DIR, "system.txt")
    user_path = os.path.join(INPUT_DIR, "user.txt")

    system_prompt = read_file(system_path)
    user_content = read_file(user_path)

    # Simulated "LLM" – later you can replace this with a real model call.
    print("NO PASS LLM SANDBOX (SIMULATED)\n")
    print("=== SYSTEM PROMPT (TRUNCATED) ===")
    print(system_prompt[:400])
    print("\n=== USER CONTENT (TRUNCATED) ===")
    print(user_content[:800])
    print("\n=== ANSWER ===")
    print("This is a simulated answer generated inside an isolated Docker sandbox.")

if __name__ == "__main__":
    main()
