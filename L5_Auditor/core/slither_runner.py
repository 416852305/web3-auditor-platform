# core/slither_runner.py
import subprocess
import json
import os

def run_slither_on_dir(directory):
    """
    对整个目录运行 Slither (Slither 支持直接分析目录)
    """
    print("[*] Running Slither on project directory...")
    try:
        # slither . --json -
        cmd = ["slither", directory, "--json", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # 提取 JSON
        raw_output = result.stdout + result.stderr
        json_start = raw_output.find('{')
        if json_start == -1:
            return "Slither found no issues or failed to run."
            
        data = json.loads(raw_output[json_start:])
        detectors = data.get('results', {}).get('detectors', [])
        
        simplified = []
        for item in detectors:
            simplified.append({
                "check": item.get('check'),
                "file": item.get('elements', [{}])[0].get('source_mapping', {}).get('filename_relative', 'unknown'),
                "description": item.get('description')
            })
        
        return json.dumps(simplified, indent=2)
    except Exception as e:
        return f"Slither Error: {str(e)}"
