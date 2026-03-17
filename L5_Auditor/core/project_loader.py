# core/project_loader.py
import os
import re

TOP_LEVEL_DECL_RE = re.compile(
    r"^\s*(?:(abstract)\s+)?(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\s+[^"\']*["\']([^"\']+)["\']', re.MULTILINE)


def _describe_source_file(rel_path, content):
    declarations = []
    for match in TOP_LEVEL_DECL_RE.finditer(content):
        abstract_kw, kind, name = match.groups()
        declarations.append(
            {
                "kind": f"{abstract_kw} {kind}".strip() if abstract_kw else kind,
                "name": name,
            }
        )

    return {
        "path": rel_path,
        "contracts": declarations,
        "imports": IMPORT_RE.findall(content),
    }


def load_project_bundle(directory):
    """
    扫描目录下的所有 .sol 文件，拼接成完整上下文，并附带文件/合约清单。
    """
    project_context = ""
    file_map = {}
    source_manifest = []
    contract_map = {}

    print(f"[*] Scanning project directory: {directory}...")

    for root, dirs, files in os.walk(directory):
        dirs.sort()
        for file in sorted(files):
            if not file.endswith(".sol"):
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                project_context += f"\n\n// ================= FILE: {rel_path} =================\n"
                project_context += content
                file_map[rel_path] = content

                descriptor = _describe_source_file(rel_path, content)
                source_manifest.append(descriptor)
                for contract in descriptor["contracts"]:
                    contract_map[contract["name"]] = rel_path

                print(f"    - Loaded: {rel_path}")
            except Exception as e:
                print(f"    [!] Error reading {rel_path}: {e}")

    if not project_context:
        print("[!] No .sol files found in targets/ folder.")
        return None

    source_manifest.sort(key=lambda item: item["path"])
    return {
        "project_context": project_context,
        "file_map": file_map,
        "source_manifest": source_manifest,
        "contract_map": contract_map,
    }


def load_project_context(directory):
    """
    兼容旧接口，返回上下文和文件映射。
    """
    bundle = load_project_bundle(directory)
    if not bundle:
        return None, None
    return bundle["project_context"], bundle["file_map"]
