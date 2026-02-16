import networkx as nx
import re
from typing import Dict
from .agent_executor import AgentExecutor
from .trace_simulator import simulate_trace
from src.detection.ipi_detector import detect_ipi


class GraphBuilder:
    def __init__(self):
        self.executor = AgentExecutor()

    def build_from_prompt(self, user_input: str, external_data: str = None) -> nx.DiGraph:
        plan = self.executor.generate_execution_plan(user_input, external_data)
        trace_steps, lane_map = simulate_trace(plan)

        G = nx.DiGraph()
        root_id = "user_input"
        G.add_node(root_id, type="user_input", label="User Input", content=user_input[:500], trust="trusted")
        # ✅ 始终创建一个总的 external_data observation，确保 obs_1 存在
        obs_root_id = "obs_1"
        if external_data:
            G.add_node(
                obs_root_id,
                type="observation",
                label="External Data",
                content=external_data[:2500],
                trust="untrusted",
            )
            # 从 user_input 指向 external observation（数据来源）
            G.add_edge(root_id, obs_root_id, type="data_flow")


        id_map = {0: root_id}
        previous_node_id = root_id

        external_return_tools = {"read_url", "read_file", "web_vuln_scan", "web_search"}

        for step in trace_steps:
            step_id = int(step.get("step_id"))
            node_id = f"step_{step_id}"
            node_type = str(step.get("type", "action")).lower()
            tool_name = step.get("tool_name", None)

            label = tool_name if node_type == "tool" else "Action"
            G.add_node(
                node_id,
                type=node_type,
                label=f"{label}: {str(step.get('description',''))[:28]}",
                full_desc=str(step.get("description", "")),
                tool=tool_name,
                trust="trusted",
                lane=int(lane_map.get(step_id, 0)),
            )
            id_map[step_id] = node_id

            deps = step.get("dependencies", []) or []
            if deps:
                for dep_id in deps:
                    parent = id_map.get(int(dep_id), root_id)
                    G.add_edge(parent, node_id, type="control_flow")
            else:
                G.add_edge(previous_node_id, node_id, type="control_flow")
                previous_node_id = node_id

            # ✅ 对 web_search 等外部返回工具，一律落 Observation 节点（审计必需）
            if node_type == "tool" and external_data and tool_name in external_return_tools:
                obs_id = f"obs_{step_id}"
                # 若外部数据包含 IPI，标记 observation 为注入源
                from src.detection.ipi_detector import detect_ipi   
                ipi = detect_ipi(external_data or "")
                if ipi.get("is_ipi"):
                    ipi = detect_ipi(external_data or "")
                    if ipi.get("is_ipi"):
                        target_obs = "obs_1" if G.has_node("obs_1") else None
                        if target_obs:
                            G.nodes[target_obs]["ipi_source"] = True
                            G.nodes[target_obs]["ipi_score"] = float(ipi.get("score", 0.0))
                            G.nodes[target_obs]["ipi_hits"] = ipi.get("hits", [])
                G.add_node(
                    obs_id,
                    type="observation",
                    label="Data Return",
                    content=external_data[:2500],
                    trust="untrusted",
                )
                ipi = detect_ipi(external_data or "")
                if ipi.get("is_ipi"):
                    G.nodes[obs_id]["ipi_source"] = True
                    G.nodes[obs_id]["ipi_score"] = float(ipi.get("score", 0.0))
                    G.nodes[obs_id]["ipi_hits"] = ipi.get("hits", [])

                G.add_edge(node_id, obs_id, type="data_flow")

                # 后续消费该 step_id 的节点，从 obs 接起
                id_map[step_id] = obs_id
                previous_node_id = obs_id
        # 将注入源连到“高影响决策节点”，形成因果链
        ipi_sources = [n for n, d in G.nodes(data=True) if d.get("ipi_source")]
        if ipi_sources:
            decision_nodes = [n for n, d in G.nodes(data=True) if str(d.get("type","")).lower() in ("action",) and any(k in str(d.get("label","")).lower() for k in ["join", "cross", "final", "report"])]
            for src in ipi_sources:
                for dn in decision_nodes:
                    G.add_edge(src, dn, type="taint_flow")

        return G
    
    def _split_search_results(external_data: str) -> Dict[str, str]:
        # 返回 {"AlphaCorp": "...", "BetaLtd": "...", "GammaInc": "..."}
        chunks = re.split(r"===\s*Search Result:\s*", external_data or "")
        out = {}
        for c in chunks:
            c = c.strip()
            if not c:
                continue
            name = c.split("===", 1)[0].strip()
            out[name] = "=== Search Result: " + c
        return out
