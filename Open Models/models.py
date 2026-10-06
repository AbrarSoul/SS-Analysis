import os
import sys
import requests

API_KEY = os.environ.get("GPTLAB_API_KEY")
API_BASE = "https://gptlab.rd.tuni.fi/GPT-Lab/resources/GPU-farmi-004/v1"


def list_models():
    if not API_KEY:
        raise RuntimeError("GPTLAB_API_KEY environment variable is not set.")
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(f"{API_BASE}/models", headers=headers, timeout=30)
    if response.status_code != 200:
        print(f"Error: {response.status_code} - {response.text}")
        sys.exit(1)
    data = response.json()
    models = data.get("data", [])
    count = len(models)
    print(f"Available models: {count}\n")
    for i, m in enumerate(models, 1):
        name = m.get("id", "?")
        print(f"  {i}. {name}")
 
 
if __name__ == "__main__":
    print("Checking models on GPU-farmi\n")
    list_models()