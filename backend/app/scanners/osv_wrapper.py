import os
import json
import httpx
import re

OSV_API_URL = "https://api.osv.dev/v1/query"

def parse_version_tuple(v_str):
    if not v_str:
        return (0, 0, 0)
    parts = []
    for part in str(v_str).split('.'):
        num_str = ""
        for char in part:
            if char.isdigit():
                num_str += char
            else:
                break
        parts.append(int(num_str) if num_str else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def parse_requirements_txt(filepath):
    dependencies = []
    if not os.path.exists(filepath):
        return dependencies
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Match package==version or package>=version
            match = re.match(r"^([a-zA-Z0-9_\-\[\]]+)==([0-9a-zA-Z\.\-\+]+)", line)
            if match:
                name, version = match.groups()
                dependencies.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "file": os.path.basename(filepath),
                    "full_path": filepath
                })
    return dependencies

def parse_package_json(filepath):
    dependencies = []
    if not os.path.exists(filepath):
        return dependencies
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}
            for name, version_range in all_deps.items():
                version = re.sub(r"[~\^>=<*]", "", str(version_range)).strip()
                if version:
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "file": os.path.basename(filepath),
                        "full_path": filepath
                    })
    except Exception as e:
        print(f"Error parsing package.json: {e}")
    return dependencies

def parse_package_lock_json(filepath):
    """Parses npm package-lock.json (both v1 and v2/v3 formats) for exact locked versions."""
    dependencies = []
    if not os.path.exists(filepath):
        return dependencies
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            # v2/v3 format
            packages = data.get("packages", {})
            if packages:
                for pkg_path, meta in packages.items():
                    if not pkg_path:
                        continue
                    name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                    version = meta.get("version")
                    if name and version:
                        dependencies.append({
                            "name": name,
                            "version": str(version),
                            "ecosystem": "npm",
                            "file": os.path.basename(filepath),
                            "full_path": filepath
                        })
            # v1 format fallback
            deps = data.get("dependencies", {})
            if deps and not dependencies:
                for name, meta in deps.items():
                    version = meta.get("version") if isinstance(meta, dict) else None
                    if name and version:
                        dependencies.append({
                            "name": name,
                            "version": str(version),
                            "ecosystem": "npm",
                            "file": os.path.basename(filepath),
                            "full_path": filepath
                        })
    except Exception as e:
        print(f"Error parsing package-lock.json: {e}")
    return dependencies

def parse_poetry_lock(filepath):
    """Parses poetry.lock for exact locked PyPI versions."""
    dependencies = []
    if not os.path.exists(filepath):
        return dependencies
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            matches = re.findall(r'\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"', content)
            for name, version in matches:
                dependencies.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "file": os.path.basename(filepath),
                    "full_path": filepath
                })
    except Exception as e:
        print(f"Error parsing poetry.lock: {e}")
    return dependencies

async def query_osv(package_name, version, ecosystem):
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(OSV_API_URL, json=payload, timeout=10.0)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"OSV query error for {package_name}: {e}")
    return {}

async def scan_dependencies(repo_path):
    findings = []
    dependencies = []
    dependencies_list = []
    
    # Locate package and lock files
    seen_pkgs = set()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "venv", "__pycache__", "dist", "build"]]
        
        has_npm_lock = "package-lock.json" in files
        has_poetry_lock = "poetry.lock" in files
        
        # Prefer locked versions when lockfiles exist
        if has_npm_lock:
            for dep in parse_package_lock_json(os.path.join(root, "package-lock.json")):
                key = (dep["name"].lower(), dep["ecosystem"])
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    dependencies.append(dep)
        elif "package.json" in files:
            for dep in parse_package_json(os.path.join(root, "package.json")):
                key = (dep["name"].lower(), dep["ecosystem"])
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    dependencies.append(dep)
                    
        if has_poetry_lock:
            for dep in parse_poetry_lock(os.path.join(root, "poetry.lock")):
                key = (dep["name"].lower(), dep["ecosystem"])
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    dependencies.append(dep)
        elif "requirements.txt" in files:
            for dep in parse_requirements_txt(os.path.join(root, "requirements.txt")):
                key = (dep["name"].lower(), dep["ecosystem"])
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    dependencies.append(dep)
                
    # Query OSV for each dependency
    for dep in dependencies:
        result = await query_osv(dep["name"], dep["version"], dep["ecosystem"])
        is_vuln = False
        cve_id = None
        
        if result and "vulns" in result and result["vulns"]:
            is_vuln = True
            vulns = result["vulns"]
            
            max_fix_version = None
            cves = []
            vuln_descriptions = []
            
            for vuln in vulns:
                cve = "Unknown"
                if "aliases" in vuln:
                    cve_aliases = [a for a in vuln["aliases"] if a.startswith("CVE-")]
                    if cve_aliases:
                        cve = cve_aliases[0]
                if cve not in cves:
                    cves.append(cve)
                    
                # Propose fix version
                fix_version = None
                if "affected" in vuln:
                    for affected in vuln["affected"]:
                        if affected.get("package", {}).get("name") == dep["name"]:
                            ranges = affected.get("ranges", [])
                            for r in ranges:
                                if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                                    events = r.get("events", [])
                                    for e in events:
                                        if "fixed" in e:
                                            fix_version = e["fixed"]
                                            
                if fix_version and fix_version != "Check advisory":
                    if max_fix_version is None:
                        max_fix_version = fix_version
                    else:
                        if parse_version_tuple(fix_version) > parse_version_tuple(max_fix_version):
                            max_fix_version = fix_version
                            
                summary = vuln.get("summary", "No summary provided")
                vuln_descriptions.append(f"* **{cve}**: {summary}")
                
            cve_str = ", ".join(cves)
            cve_id = cves[0] if cves else "Unknown"
            
            target_manifest = dep.get("file", "requirements.txt" if dep["ecosystem"] == "PyPI" else "package.json")
            fix_suggestion = None
            original_block = None
            patched_block = None
            
            if max_fix_version:
                if dep["ecosystem"] == "PyPI":
                    fix_suggestion = f"Upgrade `{dep['name']}` from `{dep['version']}` to `{max_fix_version}` in {target_manifest}"
                    original_block = f"{dep['name']}=={dep['version']}"
                    patched_block = f"{dep['name']}=={max_fix_version}"
                elif dep["ecosystem"] == "npm":
                    fix_suggestion = f"Upgrade `{dep['name']}` from `{dep['version']}` to `{max_fix_version}` in {target_manifest}"
                    original_block = f'"{dep["name"]}": "{dep["version"]}"'
                    patched_block = f'"{dep["name"]}": "{max_fix_version}"'
                    
            desc_bullet_points = "\n".join(vuln_descriptions)
            combined_description = f"Multiple vulnerabilities ({len(vulns)}) found in package **{dep['name']}**:\n\n{desc_bullet_points}"
            
            findings.append({
                "id": f"OSV-{dep['name']}",
                "cve": cve_str,
                "tool": "osv",
                "type": f"CVE Vulnerability: {dep['name']}",
                "severity": "High",
                "package": dep["name"],
                "current_version": dep["version"],
                "fixed_version": max_fix_version or "Check advisory",
                "fix_suggestion": fix_suggestion,
                "original_block": original_block,
                "patched_block": patched_block,
                "description": combined_description,
                "file": target_manifest
            })
            
        dependencies_list.append({
            "name": dep["name"],
            "version": dep["version"],
            "ecosystem": dep["ecosystem"],
            "file": dep.get("file"),
            "is_vulnerable": is_vuln,
            "cve": cve_id
        })
        
    return findings, dependencies_list
