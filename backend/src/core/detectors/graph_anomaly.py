"""
图异常检测器

基于执行图结构的异常检测，包括:
1. 图同构检测 - 对比原始执行图和掩码执行图
2. 攻击模式匹配 - 子图匹配已知攻击模式
3. GNN异常检测 - 基于图神经网络的异常评分
"""

import time
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import networkx as nx
from networkx.algorithms import isomorphism

from src.schemas.detection import (
    DetectionResult,
    DetectorType,
    SeverityLevel,
    ThreatCategory,
    PatternMatchResult,
)
from src.schemas.graph import (
    ExecutionGraph,
    GraphNode,
    GraphEdge,
    AttackPattern,
    GraphDiff,
    NodeType,
    EdgeType,
)
from src.utils.logger import logger, log_execution_time
from src.utils.config import get_config


class GraphEditDistanceCalculator:
    """图编辑距离计算器"""
    
    def __init__(
        self,
        node_insert_cost: float = 1.0,
        node_delete_cost: float = 1.0,
        edge_insert_cost: float = 0.5,
        edge_delete_cost: float = 0.5,
        node_substitute_cost: float = 0.5,
    ):
        self.node_insert_cost = node_insert_cost
        self.node_delete_cost = node_delete_cost
        self.edge_insert_cost = edge_insert_cost
        self.edge_delete_cost = edge_delete_cost
        self.node_substitute_cost = node_substitute_cost
    
    def calculate(
        self,
        graph1: nx.DiGraph,
        graph2: nx.DiGraph,
        timeout: float = 5.0,
    ) -> Tuple[int, GraphDiff]:
        """
        计算两个图的编辑距离
        
        使用简化的贪心算法而非精确算法（NP-hard）
        
        Returns:
            (编辑距离, 差异详情)
        """
        diff = GraphDiff()
        
        nodes1 = set(graph1.nodes())
        nodes2 = set(graph2.nodes())
        
        # 节点差异
        diff.added_nodes = list(nodes2 - nodes1)
        diff.removed_nodes = list(nodes1 - nodes2)
        
        # 边差异
        edges1 = set(graph1.edges())
        edges2 = set(graph2.edges())
        
        diff.added_edges = list(edges2 - edges1)
        diff.removed_edges = list(edges1 - edges2)
        
        # 检查共同节点的属性变化
        common_nodes = nodes1 & nodes2
        for node in common_nodes:
            attrs1 = graph1.nodes[node]
            attrs2 = graph2.nodes[node]
            if attrs1.get("node_type") != attrs2.get("node_type"):
                diff.modified_nodes.append(node)
        
        # 计算编辑距离
        ged = (
            len(diff.added_nodes) * self.node_insert_cost +
            len(diff.removed_nodes) * self.node_delete_cost +
            len(diff.added_edges) * self.edge_insert_cost +
            len(diff.removed_edges) * self.edge_delete_cost +
            len(diff.modified_nodes) * self.node_substitute_cost
        )
        
        diff.graph_edit_distance = int(ged)
        
        # 计算相似度
        total_elements = len(nodes1) + len(nodes2) + len(edges1) + len(edges2)
        if total_elements > 0:
            diff.similarity_score = 1 - (ged / total_elements)
        
        return int(ged), diff


class WeisfeilerLemanCanonicalizer:
    """
    Weisfeiler-Leman图规范化器
    
    用于计算图的签名，快速判断图同构
    """
    
    def __init__(self, iterations: int = 3):
        self.iterations = iterations
    
    def _hash_node_attrs(self, attrs: Dict[str, Any]) -> int:
        """哈希节点属性"""
        # 只使用关键属性
        key_attrs = (
            attrs.get("node_type", ""),
            attrs.get("tool_name", ""),
        )
        return hash(key_attrs)
    
    def compute_signature(self, graph: nx.DiGraph) -> Tuple[int, ...]:
        """
        计算图签名
        
        相同签名的图可能同构，不同签名的图一定不同构
        """
        if len(graph.nodes()) == 0:
            return tuple()
        
        # 初始化节点标签
        labels = {
            node: self._hash_node_attrs(graph.nodes[node])
            for node in graph.nodes()
        }
        
        # 迭代更新标签
        for _ in range(self.iterations):
            new_labels = {}
            for node in graph.nodes():
                # 获取邻居标签
                neighbor_labels = sorted([
                    labels[n] for n in graph.neighbors(node)
                ])
                # 更新标签
                new_labels[node] = hash((
                    labels[node],
                    tuple(neighbor_labels)
                ))
            labels = new_labels
        
        # 返回排序后的标签作为签名
        return tuple(sorted(labels.values()))
    
    def are_potentially_isomorphic(
        self,
        graph1: nx.DiGraph,
        graph2: nx.DiGraph,
    ) -> bool:
        """快速判断两图是否可能同构"""
        sig1 = self.compute_signature(graph1)
        sig2 = self.compute_signature(graph2)
        return sig1 == sig2


class SubgraphMatcher:
    """
    子图匹配器
    
    使用VF2算法进行子图同构匹配
    """
    
    def __init__(self):
        self.wl = WeisfeilerLemanCanonicalizer()
    
    def _node_match(self, n1_attrs: Dict, n2_attrs: Dict) -> bool:
        """节点匹配函数"""
        # 节点类型必须匹配
        type1 = n1_attrs.get("node_type", "")
        type2 = n2_attrs.get("node_type", "")
        
        # 支持正则匹配
        if isinstance(type2, str) and type2.startswith(".*"):
            return True
        
        return type1 == type2
    
    def _edge_match(self, e1_attrs: Dict, e2_attrs: Dict) -> bool:
        """边匹配函数"""
        type1 = e1_attrs.get("edge_type", "")
        type2 = e2_attrs.get("edge_type", "")
        
        if not type2:  # 模式中未指定边类型
            return True
        
        return type1 == type2
    
    def find_subgraph_matches(
        self,
        target_graph: nx.DiGraph,
        pattern_graph: nx.DiGraph,
        max_matches: int = 10,
    ) -> List[Dict[str, str]]:
        """
        在目标图中查找模式子图
        
        Args:
            target_graph: 目标图
            pattern_graph: 模式图
            max_matches: 最大匹配数
        
        Returns:
            匹配列表，每个匹配是节点映射字典
        """
        if len(pattern_graph.nodes()) > len(target_graph.nodes()):
            return []
        
        try:
            matcher = isomorphism.DiGraphMatcher(
                target_graph,
                pattern_graph,
                node_match=self._node_match,
                edge_match=self._edge_match,
            )
            
            matches = []
            for match in matcher.subgraph_isomorphisms_iter():
                matches.append(match)
                if len(matches) >= max_matches:
                    break
            
            return matches
            
        except Exception as e:
            logger.warning(f"子图匹配失败: {e}")
            return []


class AttackPatternMatcher:
    """攻击模式匹配器"""
    
    def __init__(self, pattern_file: Optional[str] = None):
        self.patterns: List[AttackPattern] = []
        self.pattern_graphs: Dict[str, nx.DiGraph] = {}
        self.subgraph_matcher = SubgraphMatcher()
        
        if pattern_file:
            self.load_patterns(pattern_file)
    
    def load_patterns(self, pattern_file: str) -> None:
        """从YAML文件加载攻击模式"""
        import yaml
        from pathlib import Path
        
        path = Path(pattern_file)
        if not path.exists():
            logger.warning(f"模式文件不存在: {pattern_file}")
            return
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        # 解析各类别模式
        for category, patterns in data.items():
            if category in ["matching_config"]:
                continue
            
            if not isinstance(patterns, list):
                continue
            
            for pattern_data in patterns:
                try:
                    pattern = AttackPattern(
                        name=pattern_data.get("name", "unknown"),
                        description=pattern_data.get("description", ""),
                        severity=pattern_data.get("severity", "medium"),
                        category=category,
                        nodes=pattern_data.get("nodes", []),
                        edges=pattern_data.get("edges", []),
                        indicators=pattern_data.get("indicators", []),
                    )
                    self.patterns.append(pattern)
                    
                    # 预编译为NetworkX图
                    if pattern.nodes:
                        self.pattern_graphs[pattern.name] = pattern.to_networkx()
                        
                except Exception as e:
                    logger.warning(f"解析模式失败: {pattern_data.get('name', 'unknown')}: {e}")
        
        logger.info(f"加载了 {len(self.patterns)} 个攻击模式")
    
    def match(
        self,
        execution_graph: ExecutionGraph,
        categories: Optional[List[str]] = None,
    ) -> List[PatternMatchResult]:
        """
        匹配攻击模式
        
        Args:
            execution_graph: 执行图
            categories: 要匹配的类别列表
        
        Returns:
            匹配结果列表
        """
        # 转换为NetworkX图
        nx_graph = execution_graph.to_networkx()
        
        results = []
        
        for pattern in self.patterns:
            # 过滤类别
            if categories and pattern.category not in categories:
                continue
            
            # 获取模式图
            pattern_graph = self.pattern_graphs.get(pattern.name)
            if pattern_graph is None:
                continue
            
            # 执行匹配
            matches = self.subgraph_matcher.find_subgraph_matches(
                nx_graph, pattern_graph
            )
            
            if matches:
                result = PatternMatchResult(
                    pattern_name=pattern.name,
                    pattern_category=pattern.category,
                    matched=True,
                    similarity_score=1.0,
                    matched_nodes=[str(n) for n in matches[0].keys()],
                    description=pattern.description,
                    indicators=pattern.indicators,
                )
                results.append(result)
        
        return results


class MELONDetector:
    """
    MELON检测器
    
    基于掩码重执行的行为对比检测
    """
    
    def __init__(self, similarity_threshold: float = 0.9):
        self.similarity_threshold = similarity_threshold
        self.ged_calculator = GraphEditDistanceCalculator()
        self.wl = WeisfeilerLemanCanonicalizer()
    
    def detect(
        self,
        original_graph: ExecutionGraph,
        masked_graph: ExecutionGraph,
    ) -> DetectionResult:
        """
        对比原始执行和掩码执行
        
        Args:
            original_graph: 原始执行图
            masked_graph: 掩码执行图（用户输入被替换为中性提示）
        
        Returns:
            检测结果
        """
        start_time = time.perf_counter()
        
        # 转换为NetworkX图
        nx_original = original_graph.to_networkx()
        nx_masked = masked_graph.to_networkx()
        
        # 快速同构检测
        potentially_iso = self.wl.are_potentially_isomorphic(nx_original, nx_masked)
        
        # 计算图编辑距离
        ged, diff = self.ged_calculator.calculate(nx_original, nx_masked)
        
        # 提取工具调用序列
        original_tools = self._extract_tool_sequence(original_graph)
        masked_tools = self._extract_tool_sequence(masked_graph)
        
        # 计算工具调用相似度
        tool_similarity = self._sequence_similarity(original_tools, masked_tools)
        
        # 判断是否存在攻击
        # MELON核心思想：如果外部数据是纯数据，掩码后行为应该不同
        # 如果行为高度相似，说明Agent行为不依赖用户输入，可能受到注入影响
        
        is_threat = False
        confidence = 0.0
        description = ""
        
        if ged == 0 and tool_similarity > self.similarity_threshold:
            # 高度相似 = 可疑
            is_threat = True
            confidence = tool_similarity
            description = f"掩码执行与原始执行高度相似(相似度={tool_similarity:.2%})，可能存在注入攻击"
        elif not potentially_iso and ged > 5:
            # 正常情况：掩码后行为不同
            confidence = 0.0
            description = "掩码执行与原始执行差异正常"
        else:
            # 中间情况
            confidence = max(0, 1 - ged / 10) * tool_similarity
            if confidence > 0.5:
                is_threat = True
                description = f"检测到可疑行为模式(GED={ged}, 工具相似度={tool_similarity:.2%})"
        
        latency = (time.perf_counter() - start_time) * 1000
        
        return DetectionResult(
            detector_type=DetectorType.GRAPH_ANOMALY,
            is_threat=is_threat,
            confidence=confidence,
            severity=SeverityLevel.HIGH if is_threat else SeverityLevel.INFO,
            threat_category=ThreatCategory.INDIRECT_INJECTION if is_threat else None,
            description=description,
            evidence=[
                f"GED={ged}",
                f"工具相似度={tool_similarity:.2%}",
                f"原始工具: {original_tools}",
                f"掩码工具: {masked_tools}",
            ],
            latency_ms=latency,
        )
    
    def _extract_tool_sequence(self, graph: ExecutionGraph) -> List[str]:
        """提取工具调用序列"""
        tool_nodes = sorted(
            [n for n in graph.nodes.values() if n.node_type == NodeType.TOOL_CALL],
            key=lambda x: x.sequence_number
        )
        return [n.tool_name or "unknown" for n in tool_nodes]
    
    def _sequence_similarity(self, seq1: List[str], seq2: List[str]) -> float:
        """计算序列相似度（Jaccard）"""
        if not seq1 and not seq2:
            return 1.0
        if not seq1 or not seq2:
            return 0.0
        
        set1, set2 = set(seq1), set(seq2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0


class GNNAnomalyDetector(nn.Module):
    """
    基于GNN的异常检测器
    
    使用图自编码器，通过重构误差检测异常
    """
    
    def __init__(
        self,
        input_dim: int = 16,  # 节点特征维度
        hidden_dim: int = 64,
        output_dim: int = 32,
        num_layers: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        
        # 编码器
        self.encoder_layers = nn.ModuleList()
        
        dims = [input_dim] + [hidden_dim] * (num_layers - 1) + [output_dim]
        for i in range(len(dims) - 1):
            self.encoder_layers.append(
                nn.Linear(dims[i], dims[i + 1])
            )
        
        self.dropout = nn.Dropout(dropout)
        
        # 解码器（用于重构边）
        self.decoder = nn.Sequential(
            nn.Linear(output_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )
        
        # 异常阈值
        self.anomaly_threshold = 0.5
    
    def encode(
        self,
        node_features: torch.Tensor,
        adjacency: torch.Tensor,
    ) -> torch.Tensor:
        """图编码"""
        x = node_features
        
        for i, layer in enumerate(self.encoder_layers):
            # 简单的图卷积：聚合邻居特征
            # x' = σ(A * x * W)
            x = torch.mm(adjacency, x)
            x = layer(x)
            
            if i < len(self.encoder_layers) - 1:
                x = F.relu(x)
                x = self.dropout(x)
        
        return x
    
    def decode(self, z: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """边重构"""
        src, dst = edge_index
        z_src = z[src]
        z_dst = z[dst]
        
        # 拼接源和目标节点嵌入
        edge_features = torch.cat([z_src, z_dst], dim=-1)
        
        return self.decoder(edge_features).squeeze()
    
    def forward(
        self,
        node_features: torch.Tensor,
        adjacency: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """前向传播"""
        z = self.encode(node_features, adjacency)
        edge_probs = self.decode(z, edge_index)
        return z, edge_probs
    
    def compute_anomaly_score(
        self,
        graph: ExecutionGraph,
    ) -> float:
        """
        计算图的异常分数
        
        Args:
            graph: 执行图
        
        Returns:
            异常分数 (0-1)
        """
        if len(graph.nodes) < 2:
            return 0.0
        
        # 构建特征矩阵
        node_ids = list(graph.nodes.keys())
        node_id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
        
        # 节点特征
        features = []
        for node_id in node_ids:
            node = graph.nodes[node_id]
            features.append(node.to_feature_vector())
        
        node_features = torch.tensor(features, dtype=torch.float32)
        
        # 确保特征维度正确
        if node_features.shape[1] != self.input_dim:
            # 填充或截断
            if node_features.shape[1] < self.input_dim:
                padding = torch.zeros(
                    node_features.shape[0],
                    self.input_dim - node_features.shape[1]
                )
                node_features = torch.cat([node_features, padding], dim=1)
            else:
                node_features = node_features[:, :self.input_dim]
        
        # 邻接矩阵
        n = len(node_ids)
        adjacency = torch.eye(n)  # 自环
        
        edge_index = []
        for edge in graph.edges:
            if edge.source_id in node_id_to_idx and edge.target_id in node_id_to_idx:
                src_idx = node_id_to_idx[edge.source_id]
                dst_idx = node_id_to_idx[edge.target_id]
                adjacency[src_idx, dst_idx] = 1
                edge_index.append([src_idx, dst_idx])
        
        if not edge_index:
            return 0.0
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).T
        
        # 归一化邻接矩阵
        degree = adjacency.sum(dim=1, keepdim=True)
        degree[degree == 0] = 1
        adjacency = adjacency / degree
        
        # 前向传播
        self.eval()
        with torch.no_grad():
            z, edge_probs = self.forward(node_features, adjacency, edge_index)
        
        # 计算重构误差
        # 真实边应该有高概率
        reconstruction_error = 1 - edge_probs.mean().item()
        
        return float(reconstruction_error)


class GraphAnomalyDetector:
    """图异常检测器（组合多种方法）"""
    
    def __init__(
        self,
        pattern_file: Optional[str] = None,
        ged_threshold: int = 3,
        use_gnn: bool = True,
    ):
        self.ged_threshold = ged_threshold
        self.use_gnn = use_gnn
        
        # 初始化组件
        self.pattern_matcher = AttackPatternMatcher(pattern_file)
        self.melon_detector = MELONDetector()
        self.ged_calculator = GraphEditDistanceCalculator()
        
        # GNN模型
        self.gnn_model = None
        if use_gnn:
            self.gnn_model = GNNAnomalyDetector()
    
    @log_execution_time
    def detect(
        self,
        execution_graph: ExecutionGraph,
        masked_graph: Optional[ExecutionGraph] = None,
        categories: Optional[List[str]] = None,
    ) -> DetectionResult:
        """
        执行图异常检测
        
        Args:
            execution_graph: 执行图
            masked_graph: 掩码执行图（用于MELON检测）
            categories: 要检测的攻击类别
        
        Returns:
            检测结果
        """
        start_time = time.perf_counter()
        
        is_threat = False
        max_confidence = 0.0
        descriptions = []
        evidence = []
        matched_patterns = []
        
        # 1. 攻击模式匹配
        pattern_results = self.pattern_matcher.match(execution_graph, categories)
        for pr in pattern_results:
            if pr.matched:
                is_threat = True
                max_confidence = max(max_confidence, 0.9)
                descriptions.append(f"匹配攻击模式: {pr.pattern_name}")
                matched_patterns.append(pr.pattern_name)
                evidence.extend(pr.indicators)
        
        # 2. MELON检测（如果提供了掩码图）
        if masked_graph:
            melon_result = self.melon_detector.detect(execution_graph, masked_graph)
            if melon_result.is_threat:
                is_threat = True
                max_confidence = max(max_confidence, melon_result.confidence)
                descriptions.append(melon_result.description)
                evidence.extend(melon_result.evidence or [])
        
        # 3. GNN异常检测
        if self.use_gnn and self.gnn_model:
            try:
                anomaly_score = self.gnn_model.compute_anomaly_score(execution_graph)
                if anomaly_score > 0.7:
                    is_threat = True
                    max_confidence = max(max_confidence, anomaly_score)
                    descriptions.append(f"GNN异常分数: {anomaly_score:.2%}")
                    evidence.append(f"anomaly_score={anomaly_score:.4f}")
            except Exception as e:
                logger.warning(f"GNN检测失败: {e}")
        
        # 4. 结构异常检测
        structural_issues = self._check_structural_anomalies(execution_graph)
        if structural_issues:
            is_threat = True
            max_confidence = max(max_confidence, 0.7)
            descriptions.extend(structural_issues)
        
        latency = (time.perf_counter() - start_time) * 1000
        
        return DetectionResult(
            detector_type=DetectorType.GRAPH_ANOMALY,
            is_threat=is_threat,
            confidence=max_confidence,
            severity=self._calculate_severity(max_confidence, len(matched_patterns)),
            threat_category=self._infer_category(matched_patterns),
            description="; ".join(descriptions) if descriptions else "未检测到异常",
            evidence=evidence[:10],
            matched_patterns=matched_patterns,
            latency_ms=latency,
        )
    
    def _check_structural_anomalies(self, graph: ExecutionGraph) -> List[str]:
        """检查结构异常"""
        issues = []
        
        # 检查工具调用数量
        tool_calls = graph.get_tool_call_nodes()
        if len(tool_calls) > 15:
            issues.append(f"工具调用次数异常: {len(tool_calls)}")
        
        # 检查高风险节点
        high_risk_nodes = graph.get_high_risk_nodes(threshold=0.7)
        if high_risk_nodes:
            issues.append(f"存在 {len(high_risk_nodes)} 个高风险节点")
        
        # 检查污染节点
        tainted_nodes = graph.get_tainted_nodes()
        if len(tainted_nodes) > len(graph.nodes) * 0.5:
            issues.append(f"超过50%的节点被污染")
        
        return issues
    
    def _calculate_severity(
        self,
        confidence: float,
        pattern_count: int,
    ) -> SeverityLevel:
        """计算严重程度"""
        if confidence >= 0.9 or pattern_count >= 2:
            return SeverityLevel.CRITICAL
        elif confidence >= 0.7 or pattern_count >= 1:
            return SeverityLevel.HIGH
        elif confidence >= 0.5:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _infer_category(
        self,
        matched_patterns: List[str],
    ) -> Optional[ThreatCategory]:
        """推断威胁类别"""
        if not matched_patterns:
            return None
        
        # 根据模式名推断
        for pattern in matched_patterns:
            pattern_lower = pattern.lower()
            if "exfil" in pattern_lower:
                return ThreatCategory.DATA_EXFILTRATION
            elif "escalation" in pattern_lower:
                return ThreatCategory.PRIVILEGE_ESCALATION
            elif "injection" in pattern_lower:
                return ThreatCategory.INDIRECT_INJECTION
            elif "poison" in pattern_lower:
                return ThreatCategory.RAG_POISONING
            elif "tool" in pattern_lower:
                return ThreatCategory.TOOL_MANIPULATION
        
        return ThreatCategory.UNKNOWN


# 单例模式
_detector_instance: Optional[GraphAnomalyDetector] = None


def get_graph_anomaly_detector() -> GraphAnomalyDetector:
    """获取图异常检测器实例"""
    global _detector_instance
    
    if _detector_instance is None:
        config = get_config()
        ga_config = config.detection.graph_anomaly
        
        _detector_instance = GraphAnomalyDetector(
            pattern_file=config.graph.patterns.pattern_file,
            ged_threshold=ga_config.ged_threshold,
            use_gnn=ga_config.enabled,
        )
    
    return _detector_instance


# 导出
__all__ = [
    "GraphEditDistanceCalculator",
    "WeisfeilerLemanCanonicalizer",
    "SubgraphMatcher",
    "AttackPatternMatcher",
    "MELONDetector",
    "GNNAnomalyDetector",
    "GraphAnomalyDetector",
    "get_graph_anomaly_detector",
]