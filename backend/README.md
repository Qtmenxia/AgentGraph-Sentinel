# AgentShield 🛡️

**基于动态执行图的AI Agent全链路可信防护系统**

> 2026年CISCN全国大学生信息安全竞赛作品赛参赛项目

## 📋 项目简介

AgentShield是一个针对AI Agent外部数据安全的创新防护平台，采用**图结构检测**与**多层防御**相结合的技术路线，有效防御间接提示词注入(IPI)、工具投毒、RAG投毒等攻击。

### 核心创新点

1. **执行图同构检测** - 将Agent执行轨迹建模为DAG，通过图编辑距离和子图匹配检测异常行为
2. **可信度传播污点分析** - 基于图着色的信息流追踪，实现外部数据的信任传播
3. **动态防火墙注入** - 运行时根据风险评估动态插入Sanitizer节点
4. **检测-防护-评估一体化** - 集成AgentDojo/ASB基准的完整评测体系

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Gradio/Streamlit 前端                     │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│  实时检测   │  攻击演示   │  安全报告   │  评测基准       │
└─────────────┴──────┬──────┴──────┬──────┴─────────────────┘
                     ↓              ↓
         ┌───────────────────────────────────────┐
         │          FastAPI 后端服务              │
         │  ┌──────────────┐  ┌──────────────┐   │
         │  │ 图检测引擎   │  │  防火墙模块  │   │
         │  │(GNN+VF2)     │  │(Input/Output)│   │
         │  └──────────────┘  └──────────────┘   │
         │  ┌──────────────┐  ┌──────────────┐   │
         │  │ 污点追踪引擎 │  │ MCP安全扫描  │   │
         │  └──────────────┘  └──────────────┘   │
         └───────────────────────────────────────┘
                          ↓
         ┌───────────────────────────────────────┐
         │      LangGraph Agent 集成层           │
         │    (执行轨迹捕获 + 工具调用监控)       │
         └───────────────────────────────────────┘
```

## 🚀 快速开始

### 环境要求

- Python 3.10+
- CUDA 11.8+ (可选，用于GPU加速)

### 安装

```bash
# 克隆项目
git clone https://github.com/your-team/agentshield.git
cd agentshield

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 安装开发依赖
pip install -r requirements-dev.txt
```

### 配置

```bash
# 复制配置模板
cp configs/config.example.yaml configs/config.yaml

# 编辑配置文件，填入API密钥
vim configs/config.yaml
```

### 运行

```bash
# 启动后端服务
python -m uvicorn src.api.main:app --reload --port 8000

# 启动演示界面
python demo/app.py
```

## 📁 项目结构

```
agentshield/
├── src/                          # 源代码
│   ├── api/                      # FastAPI接口层
│   │   ├── v1/                   # API v1路由
│   │   │   ├── scan.py           # 扫描检测接口
│   │   │   ├── protect.py        # 防护接口
│   │   │   └── benchmark.py      # 评测接口
│   │   ├── main.py               # FastAPI应用入口
│   │   └── dependencies.py       # 依赖注入
│   ├── core/                     # 核心模块
│   │   ├── detectors/            # 检测器
│   │   │   ├── prompt_injection.py   # 提示词注入检测
│   │   │   ├── graph_anomaly.py      # 图异常检测
│   │   │   └── ensemble.py           # 集成检测器
│   │   ├── graph/                # 图计算模块
│   │   │   ├── builder.py        # 执行图构建器
│   │   │   ├── patterns.py       # 攻击模式库
│   │   │   ├── isomorphism.py    # 图同构检测
│   │   │   └── gnn_model.py      # GNN模型
│   │   ├── guardrails/           # 防护栏模块
│   │   │   ├── input_guard.py    # 输入防护
│   │   │   ├── output_guard.py   # 输出防护
│   │   │   └── taint_engine.py   # 污点追踪引擎
│   │   └── firewall/             # 动态防火墙
│   │       ├── injector.py       # 节点注入器
│   │       └── sanitizer.py      # 数据清洗器
│   ├── agents/                   # Agent集成
│   │   ├── base.py               # 基础Agent类
│   │   ├── monitored_agent.py    # 受监控Agent
│   │   └── tools.py              # 工具定义
│   ├── schemas/                  # 数据模型
│   │   ├── detection.py          # 检测结果模型
│   │   ├── graph.py              # 图结构模型
│   │   └── request.py            # 请求响应模型
│   └── utils/                    # 工具函数
│       ├── logger.py             # 日志模块
│       ├── metrics.py            # 指标计算
│       └── config.py             # 配置加载
├── demo/                         # 演示界面
│   └── app.py                    # Gradio演示应用
├── training/                     # 模型训练
│   ├── train_detector.py         # 检测器训练脚本
│   ├── train_gnn.py              # GNN模型训练
│   ├── data/                     # 训练数据
│   └── models/                   # 模型权重
├── tests/                        # 测试
│   ├── unit/                     # 单元测试
│   ├── integration/              # 集成测试
│   └── evaluation/               # 评测脚本
│       └── benchmark.py          # AgentDojo/ASB评测
├── configs/                      # 配置文件
│   ├── config.yaml               # 主配置
│   └── attack_patterns.yaml      # 攻击模式配置
├── docs/                         # 文档
├── scripts/                      # 脚本
└── requirements.txt              # 依赖
```

## 📊 性能指标

| 指标 | 目标值 | 当前值 |
|-----|-------|-------|
| ASR (AgentDojo) | <0.5% | - |
| Utility (UA) | >65% | - |
| 检测延迟 | <100ms | - |
| 误报率 (FPR) | <5% | - |

## 🔬 技术栈

- **后端框架**: FastAPI + Pydantic
- **Agent框架**: LangChain + LangGraph
- **图计算**: NetworkX + PyTorch Geometric
- **ML检测**: Transformers (DeBERTa) + PyTorch
- **前端展示**: Gradio / Streamlit
- **评测基准**: AgentDojo + ASB

## 📚 参考文献

1. MELON: Provable Defense Against Indirect Prompt Injection Attacks (ICML 2025)
2. Spotlighting: Defending Against Indirect Prompt Injection (Microsoft, 2024)
3. AgentDojo: A Dynamic Environment to Evaluate Prompt Injection (NeurIPS 2024)
4. Agent Security Bench: Formalizing Attacks and Defenses (ICLR 2025)

## 📄 许可证

MIT License

## 👥 团队

CISCN 2026 参赛团队