"""
GNN风险传播模型 - 基于图神经网络的风险评估
"""
import torch
import torch.nn as nn
import torch.nn.functional as F

class SimpleGNN(nn.Module):
    """简化的GNN模型用于风险传播"""
    
    def __init__(self, input_dim: int = 128, hidden_dim: int = 64):
        """
        初始化GNN模型
        
        Args:
            input_dim: 输入特征维度
            hidden_dim: 隐藏层维度
        """
        super().__init__()
        
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, 1)
        
    def forward(self, node_features: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            node_features: 节点特征 (num_nodes, input_dim)
        
        Returns:
            risk_scores: 风险评分 (num_nodes,)
        """
        x = F.relu(self.fc1(node_features))
        x = F.relu(self.fc2(x))
        risk_scores = torch.sigmoid(self.fc3(x)).squeeze()
        
        return risk_scores


class GNNRiskPredictor:
    """GNN风险预测器"""
    
    def __init__(self, input_dim: int = 128):
        """初始化预测器"""
        self.model = SimpleGNN(input_dim=input_dim)
        self.model.eval()
    
    def predict_risk(self, node_features: dict) -> dict:
        """
        预测每个节点的风险评分
        
        Args:
            node_features: {node_id: feature_vector}
        
        Returns:
            {node_id: risk_score}
        """
        if not node_features:
            return {}
        
        # 转换为tensor
        node_ids = list(node_features.keys())
        features = torch.stack([
            torch.tensor(node_features[nid], dtype=torch.float32)
            for nid in node_ids
        ])
        
        # 预测
        with torch.no_grad():
            risk_scores = self.model(features).numpy()
        
        return {
            node_ids[i]: float(risk_scores[i])
            for i in range(len(node_ids))
        }
    
    def extract_simple_features(self, node_data: dict) -> torch.Tensor:
        """
        提取简单特征向量（用于演示）
        
        Args:
            node_data: 节点数据
        
        Returns:
            特征向量
        """
        # 简化版：随机特征
        feature = torch.randn(128)
        
        # 根据节点类型调整特征
        if node_data.get('type') == 'tool':
            feature[0] = 1.0
        elif node_data.get('type') == 'observation':
            feature[0] = -1.0
        
        return feature