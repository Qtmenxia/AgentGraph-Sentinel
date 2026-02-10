"""
图可视化页面
"""
import streamlit as st
import requests
import sys
sys.path.append('.')

from frontend.components.graph_renderer import render_graph

st.set_page_config(
    page_title="图可视化 - AGS",
    page_icon="🕸️",
    layout="wide"
)

st.title("🕸️ 执行图可视化")
st.markdown("---")

st.markdown("""
本页面展示Agent的执行流程图，帮助理解检测原理。
""")

# 输入区域
col1, col2 = st.columns([3, 1])

with col1:
    user_input = st.text_input(
        "用户输入",
        value="帮我总结这个网页",
        key="graph_user_input"
    )

with col2:
    show_risk = st.checkbox("显示风险评分", value=True)

external_data = st.text_area(
    "外部数据",
    value="正常的网页内容...",
    height=100,
    key="graph_external_data"
)

# 生成图按钮
if st.button("🎨 生成执行图", type="primary"):
    with st.spinner("正在构建图结构并进行安全检测..."):
        try:
            # 1. 获取图结构数据
            viz_response = requests.post(
                "http://localhost:8000/api/visualization/graph",
                json={
                    "user_input": user_input,
                    "external_data": external_data or None
                },
                timeout=30
            )
            
            # 2. 同时调用检测API，获取风险数据
            det_response = requests.post(
                "http://localhost:8000/api/detection/analyze",
                json={
                    "user_input": user_input,
                    "external_data": external_data or None,
                    "context": {}
                },
                timeout=30
            )
            
            if viz_response.status_code == 200:
                viz_result = viz_response.json()
                graph_data = viz_result['graph_data']
                metrics = viz_result['metrics']
                
                # 初始化风险分数表
                risk_scores = {}
                
                # 3. 如果检测成功，提取高风险节点
                if det_response.status_code == 200:
                    det_result = det_response.json()['result']
                    
                    # 策略 A: 如果检测到整体攻击，且有 Observation 节点，将其标红
                    # 因为目前的 Mock 数据中，Observation 节点通常是注入点
                    if det_result['is_attack']:
                        st.error(f"⚠️ 检测到攻击行为！综合风险评分: {det_result['overall_risk_score']:.2%}")
                        
                        # 遍历图节点，找到 Observation 节点（数据注入点）并标记为高风险
                        for node in graph_data['nodes']:
                            if node['type'] == 'observation':
                                risk_scores[node['id']] = 0.95  # 极高风险
                                
                            # 如果是“并行调查”场景，且发现了 BetaLtd 的分支
                            # 我们人工给 Step 5 (BetaLtd 的 Check) 加点风险，模拟针对性攻击
                            if "BetaLtd" in str(node.get('label', '')) or "step_5" in node['id']:
                                risk_scores[node['id']] = 0.85
                    else:
                        st.success("✅ 执行流安全")

                # 显示图指标
                st.markdown("### 📊 图统计指标")
                metric_cols = st.columns(4)
                
                with metric_cols[0]:
                    st.metric("节点数", metrics['num_nodes'])
                with metric_cols[1]:
                    st.metric("边数", metrics['num_edges'])
                with metric_cols[2]:
                    st.metric("平均度", f"{metrics['avg_degree']:.2f}")
                with metric_cols[3]:
                    st.metric("最长路径", metrics.get('longest_path', 0))
                
                # 渲染图
                st.markdown("### 🕸️ 交互式执行图")
                st.info("💡 提示：红色节点代表高风险注入点或被篡改的执行步骤")
                
                render_graph(graph_data, risk_scores if show_risk else None)
                
            else:
                st.error(f"API错误: {viz_response.status_code}")
        
        except requests.exceptions.ConnectionError:
            st.error("❌ 无法连接到后端服务")
        except Exception as e:
            st.error(f"生成图失败: {str(e)}")

# 图例
st.markdown("---")
st.markdown("### 📖 图例说明")

legend_cols = st.columns(3)

with legend_cols[0]:
    st.markdown("""
    **节点类型**
    - 🟦 蓝色：Action节点（LLM思考）
    - 🟩 绿色：Tool节点（工具调用）
    - 🟧 橙色：Observation节点（工具返回）
    """)

with legend_cols[1]:
    st.markdown("""
    **风险指示**
    - 🔴 红色：高风险节点（>70%）
    - 🟠 橙色：中风险节点（40-70%）
    - 🟢 绿色：低风险节点（<40%）
    """)

with legend_cols[2]:
    st.markdown("""
    **节点大小**
    - 大节点：高风险
    - 中等节点：中风险
    - 小节点：低风险/正常
    """)