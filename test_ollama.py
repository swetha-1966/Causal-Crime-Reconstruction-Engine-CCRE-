import requests
import json

prompt = "Respond with strict JSON: {\"status\": \"ok\"}"
try:
    print("Testing Ollama...")
    res = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "llama3", "prompt": prompt, "stream": False, "options": {"temperature": 0.2}},
        timeout=30
    )
    print("Status:", res.status_code)
    print("Response:", res.text)
except Exception as e:
    print("Error:", str(e))
