import networkx as nx

class GraphAnomalyDetector:
    """
    Detects anomalies by comparing the 'Benign Graph' (what should happen)
    vs 'Actual Graph' (what happened with external data).
    """
    
    def __init__(self, threshold: float = 0.3):
        self.threshold = threshold

    def detect(self, G_orig: nx.DiGraph, G_mask: nx.DiGraph):
        """
        Compare G_orig (with external data) and G_mask (without external data).
        Returns (is_attack, score).
        """
        # 1. Simple Graph Edit Distance (GED) calculation
        # Node matching rule: types must match
        def node_match(n1, n2):
            return n1['type'] == n2['type'] and n1.get('tool') == n2.get('tool')
            
        try:
            # Optimize: For very large graphs, use approximate methods. 
            # For demo (<50 nodes), generic GED is acceptable but can be slow.
            # Here we use a heuristic based on critical path difference.
            
            tools_orig = [d['tool'] for n, d in G_orig.nodes(data=True) if d['type'] == 'tool']
            tools_mask = [d['tool'] for n, d in G_mask.nodes(data=True) if d['type'] == 'tool']
            
            # Convert to sets to find extra tools invoked
            set_orig = set(tools_orig)
            set_mask = set(tools_mask)
            
            # Dangerous tools appearing in Orig but not Mask
            critical_tools = {'send_email', 'write_file', 'execute_command'}
            unexpected_tools = set_orig - set_mask
            
            risk_score = 0.0
            
            # Calculate Jaccard distance of tools as a proxy for structural change
            intersection = len(set_orig.intersection(set_mask))
            union = len(set_orig.union(set_mask))
            if union > 0:
                structure_diff = 1.0 - (intersection / union)
                risk_score += structure_diff * 0.5
            
            # High penalty for unexpected critical tools
            for tool in unexpected_tools:
                if tool in critical_tools:
                    risk_score += 0.5 # Immediate high risk
            
            # Cap score
            risk_score = min(risk_score, 1.0)
            
            return risk_score > self.threshold, risk_score
            
        except Exception as e:
            print(f"GED Error: {e}")
            return False, 0.0
