import requests
import json

try:
    r = requests.get("http://localhost:8000/results")
    print("Results:", r.status_code)
    if r.status_code == 200:
        data = r.json()
        print("Latency:", data.get("evaluation", {}).get("system", {}).get("latency"))
        print("RAG precision:", data.get("evaluation", {}).get("rag", {}).get("precision_k"))
except Exception as e:
    print(e)
