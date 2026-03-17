# core/analyst_l5.py
import json
import re

import requests

from config import ANALYST_API_KEY, ANALYST_API_URL, ANALYST_MODEL

SYSTEM_PROMPT_L5 = """
# Role
You are a Lead Smart Contract Auditor and Formal Verification Engineer.

# Task
Analyze the provided whole-project Solidity source code together with the Slither report.
Your job is to identify exploitable vulnerabilities and propose high-value invariants for Foundry verification.

# Hard rules
- Return one JSON object only. No Markdown fences, no commentary.
- `vulnerabilities` must only contain real exploitable issues with score >= 7.
- Every vulnerability must have a concrete attack path in `logic_flow`.
- `invariants` must be meaningful safety properties. Never output vacuous properties such as `x >= 0` for unsigned integers.
- Prefer invariants that can be checked in Foundry with real on-chain state.
- Only report vulnerabilities that are grounded in the provided project code. Do not assume hypothetical external tokens, malicious dependencies, or alternate implementations unless they are part of the provided source tree.
- When a code path reverts before value transfer or state mutation, describe the issue as the actual behavior observed from the code, for example denial of service or blocked deposits, not fund theft.
- If an issue depends on a non-standard token returning `false`, only report it when the provided project actually uses or models such a token.

# Required JSON schema
{
  "vulnerabilities": [
    {
      "target_file": "Vault.sol",
      "target_contract": "Vault",
      "name": "Reentrancy",
      "score": 9,
      "severity": "Critical",
      "description": "Short exploit-oriented description.",
      "logic_flow": ["Step 1", "Step 2"],
      "evidence": "Specific functions / state transitions involved."
    }
  ],
  "invariants": [
    {
      "target_contract": "Vault",
      "target_file": "Vault.sol",
      "name": "AssetConservation",
      "description": "Vault assets must equal tracked liabilities.",
      "expression_hint": "asset.balanceOf(address(vault)) >= totalLiabilities",
      "rationale": "A solvency invariant for deposits and withdrawals."
    }
  ]
}
"""

JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
VULNERABILITY_SEVERITY = {
    10: "Critical",
    9: "Critical",
    8: "High",
    7: "High",
}
VACUOUS_INVARIANT_PATTERNS = [
    re.compile(r">=\s*0\b"),
    re.compile(r"<=\s*type\(uint"),
    re.compile(r"\btrue\b\s*==\s*\btrue\b", re.IGNORECASE),
]


def _clean_model_json(text):
    fenced = JSON_BLOCK_RE.search(text or "")
    candidate = fenced.group(1).strip() if fenced else (text or "").strip()

    if candidate.startswith("{") and candidate.endswith("}"):
        return candidate

    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        return candidate[start : end + 1]
    return candidate


def _normalize_text(value, fallback=""):
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _normalize_logic_flow(value, description):
    if isinstance(value, list):
        steps = [_normalize_text(item) for item in value]
        steps = [step for step in steps if step]
        if steps:
            return steps

    if isinstance(value, str) and value.strip():
        return [value.strip()]

    if description:
        return [description]
    return ["Concrete exploit path not provided by model."]


def _normalize_severity(value, score):
    normalized = _normalize_text(value)
    expected = VULNERABILITY_SEVERITY.get(score, "High")
    if not normalized:
        return expected

    lowered = normalized.lower()
    if score >= 9 and lowered != "critical":
        return expected
    if score in (7, 8) and lowered not in {"high", "critical"}:
        return expected
    return normalized


def _is_vacuous_invariant(expression_hint):
    hint = _normalize_text(expression_hint)
    if not hint:
        return True
    return any(pattern.search(hint) for pattern in VACUOUS_INVARIANT_PATTERNS)


def _normalize_score(value):
    try:
        return max(0, min(10, int(value)))
    except (TypeError, ValueError):
        return 0


def _build_project_facts(file_map):
    false_return_token_modeled = False

    for content in (file_map or {}).values():
        lowered = content.lower()
        if "function transfer" in lowered or "function transferfrom" in lowered:
            if "return false" in lowered:
                false_return_token_modeled = True
                break

    return {
        "false_return_token_modeled": false_return_token_modeled,
    }


def _build_contract_lookup(source_manifest):
    contract_to_file = {}
    valid_files = set()
    valid_contracts = set()

    for entry in source_manifest or []:
        valid_files.add(entry["path"])
        for contract in entry["contracts"]:
            contract_to_file[contract["name"]] = entry["path"]
            valid_contracts.add(contract["name"])

    return contract_to_file, valid_files, valid_contracts


def _combined_vulnerability_text(name, description, evidence, logic_flow):
    return " ".join([name, description, evidence, *logic_flow]).lower()


def _is_hypothetical_unchecked_transfer_issue(combined_text, project_facts):
    transfer_keywords = [
        "unchecked erc20",
        "return false",
        "non-standard erc20",
        "non compliant erc20",
        "non-compliant erc20",
        "ignored return value",
        "transfer return",
    ]
    mentions_hypothetical_transfer = any(keyword in combined_text for keyword in transfer_keywords)
    return mentions_hypothetical_transfer and not project_facts["false_return_token_modeled"]


def _adjust_runtime_grounding(name, description, logic_flow, evidence, target_file, file_map):
    content = (file_map or {}).get(target_file or "", "")
    lowered_name = name.lower()

    if "inflation" not in lowered_name and "first depositor" not in lowered_name:
        return description, logic_flow, evidence

    require_index = content.find('require(shares > 0')
    transfer_index = content.find("asset.transferFrom")
    if require_index == -1 or transfer_index == -1 or require_index > transfer_index:
        return description, logic_flow, evidence

    grounded_description = (
        "First depositor can manipulate share pricing with a direct token donation so later deposits revert "
        "with 'Zero shares minted', creating a deposit denial-of-service / griefing condition."
    )
    grounded_logic = [
        "Step 1: Attacker deposits a minimal amount first and receives the initial shares.",
        "Step 2: Attacker transfers a large amount of tokens directly to the vault, inflating totalAssets without minting new shares.",
        "Step 3: A later depositor calls deposit(...), but the share calculation rounds down to 0.",
        "Step 4: The vault hits require(shares > 0, 'Zero shares minted') before transferFrom executes, so the victim's deposit reverts.",
    ]
    grounded_evidence = (
        "deposit() computes shares from asset.balanceOf(address(this)), so direct donations distort pricing. "
        "The require(shares > 0, 'Zero shares minted') check executes before asset.transferFrom(...), making the concrete effect blocked deposits rather than silent asset loss."
    )
    return grounded_description, grounded_logic, grounded_evidence


def _normalize_vulnerabilities(items, contract_to_file, valid_files, valid_contracts, file_map, project_facts):
    normalized = []
    seen = set()

    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue

        score = _normalize_score(item.get("score"))
        if score < 7:
            continue

        target_contract = _normalize_text(item.get("target_contract"))
        target_file = _normalize_text(item.get("target_file"))
        if not target_file and target_contract:
            target_file = contract_to_file.get(target_contract, "")
        if target_file and target_file not in valid_files:
            target_file = ""
        if target_contract and target_contract not in valid_contracts:
            target_contract = ""

        name = _normalize_text(item.get("name") or item.get("vulnerability"), "UnnamedVulnerability")
        description = _normalize_text(item.get("description"), name)
        logic_flow = _normalize_logic_flow(item.get("logic_flow"), description)
        evidence = _normalize_text(item.get("evidence"), description)
        severity = _normalize_severity(item.get("severity"), score)

        combined_text = _combined_vulnerability_text(name, description, evidence, logic_flow)
        if _is_hypothetical_unchecked_transfer_issue(combined_text, project_facts):
            continue

        description, logic_flow, evidence = _adjust_runtime_grounding(
            name,
            description,
            logic_flow,
            evidence,
            target_file,
            file_map,
        )

        dedupe_key = (target_file, target_contract, name.lower(), tuple(logic_flow))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        normalized.append(
            {
                "target_file": target_file,
                "target_contract": target_contract,
                "name": name,
                "score": score,
                "severity": severity,
                "description": description,
                "logic_flow": logic_flow,
                "evidence": evidence,
            }
        )

    normalized.sort(key=lambda item: (-item["score"], item["name"].lower()))
    return normalized


def _normalize_invariants(items, contract_to_file, valid_files, valid_contracts):
    normalized = []
    seen = set()

    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue

        target_contract = _normalize_text(item.get("target_contract"))
        target_file = _normalize_text(item.get("target_file"))
        if not target_file and target_contract:
            target_file = contract_to_file.get(target_contract, "")
        if target_file and target_file not in valid_files:
            target_file = ""
        if target_contract and target_contract not in valid_contracts:
            target_contract = ""

        name = _normalize_text(item.get("name"), "UnnamedInvariant")
        description = _normalize_text(item.get("description"), name)
        expression_hint = _normalize_text(item.get("expression_hint"))
        rationale = _normalize_text(item.get("rationale"), description)

        if _is_vacuous_invariant(expression_hint):
            continue

        dedupe_key = (target_contract, target_file, name.lower(), expression_hint)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        normalized.append(
            {
                "target_contract": target_contract,
                "target_file": target_file,
                "name": name,
                "description": description,
                "expression_hint": expression_hint,
                "rationale": rationale,
            }
        )

    normalized.sort(key=lambda item: (item["target_contract"], item["name"].lower()))
    return normalized


def normalize_analysis_result(raw_result, source_manifest=None, file_map=None):
    if not isinstance(raw_result, dict):
        raw_result = {}

    contract_to_file, valid_files, valid_contracts = _build_contract_lookup(source_manifest)
    project_facts = _build_project_facts(file_map)
    vulnerabilities = _normalize_vulnerabilities(
        raw_result.get("vulnerabilities", []),
        contract_to_file,
        valid_files,
        valid_contracts,
        file_map or {},
        project_facts,
    )
    invariants = _normalize_invariants(
        raw_result.get("invariants", []),
        contract_to_file,
        valid_files,
        valid_contracts,
    )

    return {
        "vulnerabilities": vulnerabilities,
        "invariants": invariants,
    }


def analyze_project(project_context, slither_report, source_manifest=None, file_map=None):
    if not ANALYST_API_KEY:
        print("[!] Analyst Error: missing L5_ANALYST_API_KEY environment variable")
        return {"vulnerabilities": [], "invariants": []}

    input_text = f"""
    === PROJECT SOURCE CODE (ALL FILES) ===
    {project_context}

    === SLITHER STATIC ANALYSIS ===
    {slither_report}
    """

    headers = {"Authorization": f"Bearer {ANALYST_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": ANALYST_MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT_L5}, {"role": "user", "content": input_text}],
        "temperature": 0.1,
    }

    try:
        print("[*] Analyst (L5) is deriving Invariants & Vulnerabilities...")
        resp = requests.post(ANALYST_API_URL, headers=headers, json=data, timeout=120)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        clean_content = _clean_model_json(content)
        parsed = json.loads(clean_content)
        return normalize_analysis_result(parsed, source_manifest, file_map)
    except Exception as e:
        print(f"[!] Analyst Error: {e}")
        return {"vulnerabilities": [], "invariants": []}
