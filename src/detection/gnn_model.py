"""
GNN风险传播模型（增强版）
- 保持原 predict_risk(node_features) 兼容
- 新增可选 edges 以进行真正的图上传播（无需 torch_geometric）
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class SimpleMLP(nn.Module):
    def __init__(self, input_dim: int = 128, hidden_dim: int = 64):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, 1)

    def forward(self, node_features: torch.Tensor) -> torch.Tensor:
        x = F.relu(self.fc1(node_features))
        x = F.relu(self.fc2(x))
        return torch.sigmoid(self.fc3(x)).squeeze(-1)


class GraphSAGE(nn.Module):
    def __init__(self, input_dim: int = 128, hidden_dim: int = 128, num_layers: int = 2, dropout: float = 0.10, num_edge_types: int = 6):
        super().__init__()
        self.lin_in = nn.Linear(input_dim, hidden_dim)
        self.lin_self = nn.ModuleList([nn.Linear(hidden_dim, hidden_dim) for _ in range(num_layers)])
        self.lin_neigh = nn.ModuleList([nn.Linear(hidden_dim, hidden_dim) for _ in range(num_layers)])
        self.edge_gate = nn.Embedding(num_edge_types, 1)
        self.dropout = dropout

        self.head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_type: Optional[torch.Tensor] = None) -> torch.Tensor:
        N = x.size(0)
        E = edge_index.size(1)
        h = F.relu(self.lin_in(x))

        if edge_type is None:
            edge_type = torch.zeros(E, dtype=torch.long, device=x.device)

        for i in range(len(self.lin_self)):
            src = edge_index[0]
            dst = edge_index[1]

            g = torch.sigmoid(self.edge_gate(edge_type)).view(-1, 1)
            msg = h[src] * g

            agg = torch.zeros_like(h)
            agg.index_add_(0, dst, msg)

            deg = torch.zeros((N, 1), device=h.device)
            deg.index_add_(0, dst, torch.ones((E, 1), device=h.device))
            agg = agg / torch.clamp(deg, min=1.0)

            h = self.lin_self[i](h) + self.lin_neigh[i](agg)
            h = F.relu(h)
            h = F.dropout(h, p=self.dropout, training=self.training)

        return torch.sigmoid(self.head(h)).squeeze(-1)


class GNNRiskPredictor:
    def __init__(self, input_dim: int = 128):
        self.input_dim = input_dim
        self.mlp = SimpleMLP(input_dim=input_dim)
        self.gnn = GraphSAGE(input_dim=input_dim)
        self.mlp.eval()
        self.gnn.eval()

        self.edge_type_map = {
            "data_flow": 0,
            "control_flow": 1,
            "retrieval": 2,
            "write": 3,
            "edge": 4,
            "other": 5,
        }

    def predict_risk(self, node_features: dict, edges: Optional[List[Tuple[str, str, str]]] = None) -> dict:
        if not node_features:
            return {}

        node_ids = list(node_features.keys())
        feats = torch.stack([self._to_tensor(node_features[nid]) for nid in node_ids])

        with torch.no_grad():
            if not edges:
                risk_scores = self.mlp(feats).cpu().numpy()
                return {node_ids[i]: float(risk_scores[i]) for i in range(len(node_ids))}

            id2idx = {nid: i for i, nid in enumerate(node_ids)}
            src_idx, dst_idx, et = [], [], []
            for u, v, t in edges:
                if u not in id2idx or v not in id2idx:
                    continue
                src_idx.append(id2idx[u])
                dst_idx.append(id2idx[v])
                et.append(self.edge_type_map.get(str(t), self.edge_type_map["other"]))
            if not src_idx:
                risk_scores = self.mlp(feats).cpu().numpy()
                return {node_ids[i]: float(risk_scores[i]) for i in range(len(node_ids))}

            edge_index = torch.tensor([src_idx, dst_idx], dtype=torch.long)
            edge_type = torch.tensor(et, dtype=torch.long)
            risk_scores = self.gnn(feats, edge_index, edge_type).cpu().numpy()
            return {node_ids[i]: float(risk_scores[i]) for i in range(len(node_ids))}

    def extract_simple_features(self, node_data: dict) -> torch.Tensor:
        # deterministic hash-based feature; safe for offline demo
        import hashlib
        vec = torch.zeros(self.input_dim, dtype=torch.float32)
        ntype = str(node_data.get("type", "node")).lower()
        tool = str(node_data.get("tool", "")).lower()
        content = str(node_data.get("content", ""))[:500]

        bucket = {
            "user_input": 1,
            "action": 2,
            "tool": 3,
            "observation": 4,
        }.get(ntype, 0)
        vec[0] = float(bucket) / 4.0

        # tool bucket signal
        if tool in ("read_file","read_url","web_search"):
            vec[1] = 0.8
        if tool in ("write_file","send_email","execute_command"):
            vec[2] = 1.0

        h = hashlib.sha256((ntype + "|" + tool + "|" + content).encode("utf-8")).digest()
        for i in range(min(self.input_dim - 3, len(h))):
            vec[i + 3] = (h[i] / 255.0) * 2 - 1
        return vec

    def _to_tensor(self, x: Any) -> torch.Tensor:
        if isinstance(x, torch.Tensor):
            t = x.float().flatten()
        else:
            t = torch.tensor(x, dtype=torch.float32).flatten()
        if t.numel() < self.input_dim:
            t = torch.cat([t, torch.zeros(self.input_dim - t.numel())], dim=0)
        elif t.numel() > self.input_dim:
            t = t[: self.input_dim]
        return t
