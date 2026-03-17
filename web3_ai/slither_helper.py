# 文件名: slither_helper.py
import os
import subprocess
import json
import re

def run_slither(code_content: str):
    """
    1. 保存代码到 temp.sol
    2. 运行 Slither 扫描
    3. 返回清洗后的 JSON 报告
    """
    filename = "temp_audit.sol"
    
    # Slither 需要文件存在
    with open(filename, "w") as f:
        f.write(code_content)

    # 自动探测版本 (简单处理：默认用 0.8.0，实际生产需要正则匹配 pragma)
    # os.system("solc-select use 0.8.0") 

    try:
        # 运行 slither，输出为 json 格式
        # --json - 表示输出到标准输出
        cmd = ["slither", filename, "--json", "-"]
        
        # 捕获输出
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Slither 的输出通常包含日志，我们需要提取 JSON 部分
        # Slither 有时候会把 JSON 混在日志里，这里做一个简单的提取
        output = result.stdout + result.stderr
        
        # 尝试找到 JSON 结构
        if result.returncode != 0 and not result.stdout:
            return f"Slither Error: {result.stderr}"

        # 解析 Slither 的 JSON (它通常返回一大坨东西)
        try:
            data = json.loads(result.stdout)
            detectors = data.get('results', {}).get('detectors', [])
            
            # 我们只提取关键信息，节省 Token
            simplified_report = []
            for item in detectors:
                simplified_report.append({
                    "check": item.get('check'),
                    "impact": item.get('impact'),
                    "description": item.get('description')
                })
            
            return json.dumps(simplified_report, indent=2)
            
        except json.JSONDecodeError:
            return "Slither failed to generate valid JSON."

    except Exception as e:
        return f"System Error running Slither: {str(e)}"
