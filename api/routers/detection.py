"""
检测API路由
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uuid

from src.core.graph_builder import GraphBuilder
from src.detection.graph_anomaly import GraphAnomalyDetector
from src.detection.node_embedding import NodeEmbeddingDetector
from src.detection.taint_analysis import TaintAnalyzer
from src.detection.rule_engine import RuleEngine
from src.models.detection_result import ComprehensiveDetectionResult, DetectionResult

router = APIRouter(prefix="/api/detection", tags=["detection"])

# 初始化检测器
graph_builder = GraphBuilder()
anomaly_detector = GraphAnomalyDetector()
node_detector = NodeEmbeddingDetector()
taint_analyzer = TaintAnalyzer()
rule_engine = RuleEngine()

class DetectionRequest(BaseModel):
    """检测请求"""
    user_input: str
    external_data: Optional[str] = None
    context: Dict[str, Any] = {}
    # 外部数据来源：手动输入 / 文件上传等，便于后续可视化和审计
    external_data_source: Optional[str] = "manual"  # 'manual' | 'file' | 'demo' 等
    external_data_filename: Optional[str] = None

class DetectionResponse(BaseModel):
    """检测响应"""
    trace_id: str
    result: ComprehensiveDetectionResult

@router.post("/analyze", response_model=DetectionResponse)
async def analyze_input(request: DetectionRequest):
    """
    分析用户输入
    
    Args:
        request: 检测请求
    
    Returns:
        检测结果
    """
    try:
        trace_id = str(uuid.uuid4())
        
        # 1. 构建执行图
        G_orig = graph_builder.build_from_prompt(
            request.user_input,
            request.external_data
        )
        
        # 2. 构建掩码图（用于MELON检测）
        G_mask = graph_builder.build_from_prompt(
            request.user_input,
            None  # 不包含外部数据
        )
        
        # 3. 图异动检测
        is_anomaly, anomaly_score = anomaly_detector.detect(G_orig, G_mask)
        graph_anomaly_result = DetectionResult(
            is_attack=is_anomaly,
            confidence=anomaly_score,
            detection_method="graph_anomaly",
            details={'ged_score': anomaly_score}
        )
        
        # 4. 节点嵌入检测
        node_risks = {}
        if request.external_data:
            is_mal, conf, det = node_detector.scan_observation_node(
                request.external_data
            )
            node_embedding_result = DetectionResult(
                is_attack=is_mal,
                confidence=conf,
                detection_method="node_embedding",
                details=det
            )
            if is_mal:
                node_risks['obs_0'] = conf
        else:
            node_embedding_result = DetectionResult(
                is_attack=False,
                confidence=0.0,
                detection_method="node_embedding",
                details={}
            )
        
        # 5. 污点分析
        trust_levels = taint_analyzer.analyze_graph(G_orig)
        taint_summary = taint_analyzer.get_risk_summary(trust_levels)
        taint_analysis_result = DetectionResult(
            is_attack=taint_summary['risk_score'] > 0.5,
            confidence=taint_summary['risk_score'],
            detection_method="taint_analysis",
            details=taint_summary
        )
        
        # 6. 规则引擎检测
        combined_text = f"{request.user_input}\n{request.external_data or ''}"
        rule_result = rule_engine.check(combined_text)
        rule_engine_result = DetectionResult(
            is_attack=rule_result['is_malicious'],
            confidence=1.0 if rule_result['is_malicious'] else 0.0,
            detection_method="rule_engine",
            details=rule_result
        )
        
        # 7. 综合判定
        overall_risk = max(
            anomaly_score,
            node_embedding_result.confidence,
            taint_summary['risk_score'],
            1.0 if rule_result['is_malicious'] else 0.0
        )
        
        is_attack = overall_risk > 0.5
        
        # 8. 防御建议
        if overall_risk > 0.8:
            recommended_action = "block"
        elif overall_risk > 0.5:
            recommended_action = "sanitize"
        else:
            recommended_action = "allow"
        
        # 9. 构建完整结果
        result = ComprehensiveDetectionResult(
            trace_id=trace_id,
            is_attack=is_attack,
            overall_risk_score=overall_risk,
            graph_anomaly_result=graph_anomaly_result,
            node_embedding_result=node_embedding_result,
            taint_analysis_result=taint_analysis_result,
            rule_engine_result=rule_engine_result,
            graph_metrics={
                'num_nodes': G_orig.number_of_nodes(),
                'num_edges': G_orig.number_of_edges()
            },
            high_risk_nodes=[
                node for node, score in node_risks.items()
                if score > 0.7
            ],
            recommended_action=recommended_action,
            external_data_source=request.external_data_source,
            external_data_filename=request.external_data_filename,
        )
        
        return DetectionResponse(trace_id=trace_id, result=result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))