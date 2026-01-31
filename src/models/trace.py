"""
执行轨迹数据模型
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class TraceStep(BaseModel):
    """单步执行轨迹"""
    step_id: str
    step_type: str  # 'action', 'tool', 'observation'
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

class ExecutionTrace(BaseModel):
    """完整执行轨迹"""
    trace_id: str
    user_input: str
    steps: List[TraceStep]
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: str = "running"  # 'running', 'completed', 'blocked'
    
    def add_step(self, step: TraceStep):
        """添加执行步骤"""
        self.steps.append(step)
    
    def complete(self):
        """标记为完成"""
        self.status = "completed"
        self.end_time = datetime.now()