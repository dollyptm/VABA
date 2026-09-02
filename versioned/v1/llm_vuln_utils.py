import json
import os
from typing import Dict, Any


def load_vulnerabilities(json_path: str) -> Dict[str, Any]:
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        # minimal validation
        valid = {}
        for key, val in data.items():
            if all(k in val for k in ("title", "description", "poc", "attack_path", "code_snippet", "fix")):
                valid[key] = val
        return valid
    except Exception:
        return {}


def get_selected_vuln(session_obj, all_vulns: Dict[str, Any]):
    vid = session_obj.get('selected_vuln')
    if not vid:
        return None
    return all_vulns.get(vid)


def inject_poc_if_demo(message: str, session_obj, all_vulns: Dict[str, Any]) -> str:
    if not session_obj.get('demo'):
        return message
    v = get_selected_vuln(session_obj, all_vulns)
    if not v:
        return message
    # Only inject once per session to avoid re-staging actions repeatedly
    try:
        if session_obj.get('poc_injected_once'):
            return message
    except Exception:
        pass
    poc = v.get('poc') or ''
    if not poc:
        return message
    try:
        session_obj['poc_injected_once'] = True
    except Exception:
        pass
    return f"{message}\n\n[Injected Vulnerability PoC: {poc}]"


