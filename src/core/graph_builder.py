import networkx as nx
from .agent_executor import AgentExecutor

class GraphBuilder:
    """Builds execution graphs from prompts using LLM planning"""
    
    def __init__(self):
        self.executor = AgentExecutor()

    def build_from_prompt(self, user_input: str, external_data: str = None) -> nx.DiGraph:
        """
        Builds a DAG. Supports branching if 'dependencies' are provided in the plan.
        """
        # 1. Get execution plan
        plan = self.executor.generate_execution_plan(user_input, external_data)
        
        # 2. Initialize Graph
        G = nx.DiGraph()
        
        # 3. Add Root Node
        root_id = "user_input"
        G.add_node(root_id, type="user_input", label="User Input", content=user_input[:50])
        
        # Map step_id to node_id for dependency resolution
        # 0 is reserved for root
        id_map = {0: root_id} 
        
        # 4. Add Nodes & Edges
        previous_node_id = root_id
        
        for step in plan:
            step_id = step.get('step_id')
            node_id = f"step_{step_id}"
            node_type = step['type']
            label = step.get('tool_name', 'Think') if node_type == 'tool' else 'Action'
            
            # Add Node
            attrs = {
                "type": node_type,
                "label": f"{label}: {step['description'][:15]}...",
                "full_desc": step['description'],
                "tool": step.get('tool_name', None)
            }
            G.add_node(node_id, **attrs)
            
            # Record mapping for future lookups
            id_map[step_id] = node_id
            
            # === 处理依赖关系 (分支结构核心逻辑) ===
            dependencies = step.get('dependencies', [])
            
            if dependencies:
                # 如果有明确的依赖，连接到指定的父节点
                for dep_id in dependencies:
                    # 如果依赖ID不存在（比如依赖根节点），回退到 root_id
                    parent_node = id_map.get(dep_id, root_id)
                    G.add_edge(parent_node, node_id, type="control_flow")
            else:
                # 默认线性连接：连接到上一个节点
                G.add_edge(previous_node_id, node_id, type="control_flow")
            
            # Update previous pointer (for linear fallbacks)
            previous_node_id = node_id
            
            # Special case for External Data Injection (Observation)
            # 如果是工具节点且涉及外部数据，挂载一个 Observation 节点
            if node_type == 'tool' and external_data and step.get('tool_name') in ['read_url', 'read_file', 'web_vuln_scan']:
                 obs_id = f"obs_{step_id}"
                 G.add_node(obs_id, type="observation", label="Data Return", content="External Data")
                 
                 # Data flow edge
                 G.add_edge(node_id, obs_id, type="data_flow")
                 
                 # 更新 id_map，这样依赖此步骤的后续步骤会连接到 Observation（数据返回后继续）
                 id_map[step_id] = obs_id 
                 previous_node_id = obs_id

        return G
