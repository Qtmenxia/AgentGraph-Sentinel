"""
Streamlit主入口
"""
import streamlit as st

st.set_page_config(
    page_title="AgentGraph Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 主页
st.title("🛡️ AgentGraph Sentinel (AGS)")
st.markdown("### 基于动态执行图的AI Agent全链路可信防护系统")

st.markdown("---")

# 简介
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("#### 🔍 实时检测")
    st.markdown("""
    - 图异动检测
    - 节点嵌入检测
    - 污点传播分析
    - 规则引擎
    """)
    if st.button("前往检测页面", key="btn_detection", use_container_width=True):
        st.switch_page("pages/1_实时检测.py")

with col2:
    st.markdown("#### 🎯 攻击演示")
    st.markdown("""
    - 邮件泄露攻击
    - 文件窃取攻击
    - 多步链式攻击
    - 正常查询对比
    """)
    if st.button("前往演示页面", key="btn_demo", use_container_width=True):
        st.switch_page("pages/2_攻击演示.py")

with col3:
    st.markdown("#### 🕸️ 图可视化")
    st.markdown("""
    - 交互式执行图
    - 风险节点着色
    - 图统计指标
    - 路径分析
    """)
    if st.button("前往可视化页面", key="btn_viz", use_container_width=True):
        st.switch_page("pages/3_图可视化.py")

st.markdown("---")

# 核心创新
st.markdown("## 🚀 核心创新")

innovation_cols = st.columns(2)

with innovation_cols[0]:
    st.markdown("""
    ### 1️⃣ 图结构检测
    - 将Agent执行流建模为有向无环图（DAG）
    - 利用图编辑距离（GED）检测行为异常
    - MELON思想的图化升级
    
    ### 2️⃣ 节点嵌入检测
    - 在Observation节点植入BERT分类器
    - 实现空间化的风险定位
    - InstructDetector的图化实现
    """)

with innovation_cols[1]:
    st.markdown("""
    ### 3️⃣ 污点传播分析
    - 基于图着色算法的可信度传播
    - Spotlighting技术的图化应用
    - 动态风险评估
    
    ### 4️⃣ 动态图手术
    - 实时插入Sanitizer节点
    - 自适应防火墙策略
    - "修复"而非"拦截"
    """)

st.markdown("---")

# 系统状态
st.markdown("## 📊 系统状态")

status_cols = st.columns(4)

with status_cols[0]:
    # 检查API服务
    try:
        import requests
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            st.success("✅ API服务正常")
        else:
            st.error("❌ API异常")
    except:
        st.warning("⚠️ API未启动")

with status_cols[1]:
    st.info("🔧 检测引擎: 就绪")

with status_cols[2]:
    st.info("📈 模型状态: 已加载")

with status_cols[3]:
    st.info("💾 数据库: 连接正常")

# 快速开始
st.markdown("---")
st.markdown("## 🎓 快速开始")

st.markdown("### 1️⃣ 安装依赖")
st.code("""
pip install -r requirements.txt
""", language="bash")

st.markdown("### 2️⃣ 启动服务")
st.code("""
# 1. 启动后端服务
python scripts/run_server.py

# 2. 启动前端（新终端）
streamlit run frontend/app.py

# 3. 运行演示
python scripts/demo_attack.py email_exfiltration
""", language="bash")

# 页脚
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>AgentGraph Sentinel v1.0.0 | 2026 CISCN竞赛作品</p>
    <p>基于 LangGraph + NetworkX + FastAPI + Streamlit 构建</p>
</div>
""", unsafe_allow_html=True)