import os
import json
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

findings = [
    {"tool": "osv", "severity": "High", "package": "flask", "version": "0.12.2", "cve": "CVE-2018-1000656", "description": "Denial of Service in Flask"},
    {"tool": "gitleaks", "severity": "Critical", "file": "app.py", "description": "Potential leak of GitHub Personal Access Token"},
    {"tool": "hadolint", "severity": "Medium", "file": "Dockerfile", "description": "DL3002: Last USER should not be root"},
    {"tool": "actionlint", "severity": "Low", "file": ".github/workflows/ci.yml", "description": "Floating action version tag checkout@v2"}
]

prompt = f"""
You are a DevSecOps Risk Assessor Agent. Analyze the following list of security findings found in a repository:
{json.dumps(findings, indent=2)}

Provide a JSON object containing:
1. "summary": A security summary of the repository. Use short, easy-to-read paragraphs or bullet points to explain the main weaknesses. Focus on readability.
2. "threat_scenario": A step-by-step description (using a numbered list or bullet points) showing how an attacker could chain these vulnerabilities together to compromise the system.
3. "prioritized_vulns": A list of the findings ordered by true risk/exploitability.

Format the summary and threat_scenario with clear markdown (bullet points, bold highlights, inline code) so they are visually scan-friendly and divided into digestible chunks.
Return ONLY valid JSON.
"""

async def test():
    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=api_key,
        max_output_tokens=4096,
        max_retries=0
    )
    print("Sending prompt to Gemini...")
    try:
        response = await asyncio.wait_for(llm.ainvoke(prompt), timeout=30.0)
        content = response.content.strip()
        print("--- RAW LLM RESPONSE ---")
        print(content)
        print("--- END RAW RESPONSE ---")
        
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            content = json_match.group(1).strip()
        else:
            json_match_alt = re.search(r'```\s*(.*?)\s*```', content, re.DOTALL)
            if json_match_alt:
                content = json_match_alt.group(1).strip()
            else:
                if content.startswith("```json"):
                    content = content.replace("```json", "", 1)
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                
        result = json.loads(content)
        print("PARSE SUCCESS! Keys:", list(result.keys()))
    except Exception as e:
        print("EXACT ERROR:", type(e), e)

asyncio.run(test())
