"""
可视化API路由
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import networkx as nx

from src.core.graph_builder import GraphBuilder
from src.utils.graph_utils import visualize_graph_data, calculate_graph_metrics

router = APIRouter(prefix="/api/visualization", tags=["visualization"])

class GraphRequest(BaseModel):
    """图数据请求"""
    user_input: str
    external_data: str = None

class GraphResponse(BaseModel):
    """图数据响应"""
    graph_data: Dict[str, Any]
    metrics: Dict[str, Any]

@router.post("/graph", response_model=GraphResponse)
async def get_graph_visualization(request: GraphRequest):
    """
    获取执行图可视化数据
    
    Args:
        request: 图数据请求
    
    Returns:
        可视化数据
    """
    try:
        graph_builder = GraphBuilder()
        
        # 构建执行图
        G = graph_builder.build_from_prompt(
            request.user_input,
            request.external_data
        )
        
        # 转换为可视化数据
        graph_data = visualize_graph_data(G)
        
        # 计算图指标
        metrics = calculate_graph_metrics(G)
        
        return GraphResponse(
            graph_data=graph_data,
            metrics=metrics
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))