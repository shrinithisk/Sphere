import os
import asyncio
from langchain_google_genai import ChatGoogleGenerativeAI

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
print("Testing GEMINI_API_KEY:", api_key[:15] if api_key else "NONE")

async def test():
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            google_api_key=api_key,
            max_output_tokens=1024,
            max_retries=0
        )
        res = await llm.ainvoke("Hello, reply with OK.")
        print("SUCCESS:", res.content)
    except Exception as e:
        print("EXACT ERROR:", type(e), e)

asyncio.run(test())
