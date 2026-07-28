import os
import google.generativeai as genai

backend_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(backend_dir, "backend", ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

api_key = os.environ.get("GEMINI_API_KEY")
print("Key:", api_key[:15] if api_key else "None")

genai.configure(api_key=api_key)

try:
    print("Available models:")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(" -", m.name)
except Exception as e:
    print("List models error:", type(e), e)
