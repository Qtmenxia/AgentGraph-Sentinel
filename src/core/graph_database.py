import networkx as nx
from typing import Dict, Optional
import uuid

class GraphDatabase:
    """Simple In-Memory Graph Database using NetworkX"""
    _instance = None
    _graphs: Dict[str, nx.DiGraph] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GraphDatabase, cls).__new__(cls)
        return cls._instance

    def save_graph(self, graph: nx.DiGraph) -> str:
        """Save a graph and return its ID"""
        graph_id = str(uuid.uuid4())
        self._graphs[graph_id] = graph
        return graph_id

    def get_graph(self, graph_id: str) -> Optional[nx.DiGraph]:
        """Retrieve a graph by ID"""
        return self._graphs.get(graph_id)

    def delete_graph(self, graph_id: str):
        if graph_id in self._graphs:
            del self._graphs[graph_id]

    def clear(self):
        self._graphs.clear()
