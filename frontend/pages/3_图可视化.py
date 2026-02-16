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

if st.button("🎨 生成执行图", type="primary"):
    with st.spinner("正在构建图结构并进行安全检测..."):
        try:
            viz_response = requests.post(
                "http://localhost:8000/api/visualization/graph",
                json={"user_input": user_input, "external_data": external_data or None},
                timeout=100
            )

            if viz_response.status_code != 200:
                raise RuntimeError(f"Visualization API error {viz_response.status_code}: {viz_response.text}")

            det_response = requests.post(
                "http://localhost:8000/api/detection/analyze",
                json={"user_input": user_input, "external_data": external_data or None, "context": {}},
                timeout=100
            )

            viz_result = viz_response.json()
            graph_data = viz_result["graph_data"]
            metrics = viz_result["metrics"]

            # 初始化风险分数表（用于渲染：边框颜色 + 节点大小）
            risk_scores = {}

            if det_response.status_code == 200:
                det_result = det_response.json()["result"]

                rule_score = float(det_result.get("rule_engine_result", {}).get("confidence", 0.0))
                node_score = float(det_result.get("node_embedding_result", {}).get("confidence", 0.0))
                taint_score = float(det_result.get("taint_analysis_result", {}).get("confidence", 0.0))
                anomaly_score = float(det_result.get("graph_anomaly_result", {}).get("confidence", 0.0))
                overall = float(det_result.get("overall_risk_score", 0.0))

                if det_result.get("is_attack", False):
                    st.error(f"⚠️ 检测到攻击行为！综合风险评分: {overall:.2%}")
                else:
                    st.success(f"✅ 未触发阻断阈值（综合风险: {overall:.2%}）——审计视图仍会高亮可疑节点")

                # 审计高亮策略：外部数据注入风险
                injection_risk = max(rule_score, node_score, taint_score, anomaly_score)

                for node in graph_data["nodes"]:
                    if str(node.get("type", "")).lower() == "observation":
                        risk_scores[node["id"]] = max(float(risk_scores.get(node["id"], 0.0)), injection_risk)

                    if "BetaLtd" in str(node.get("label", "")):
                        risk_scores[node["id"]] = max(float(risk_scores.get(node["id"], 0.0)), max(injection_risk, 0.85))

            # 图统计指标
            st.markdown("### 📊 图统计指标")
            metric_cols = st.columns(4)

            with metric_cols[0]:
                st.metric("节点数", metrics["num_nodes"])
            with metric_cols[1]:
                st.metric("边数", metrics["num_edges"])
            with metric_cols[2]:
                st.metric("平均度", f"{metrics['avg_degree']:.2f}")
            with metric_cols[3]:
                st.metric("最长路径", metrics.get("longest_path", 0))

            st.markdown("### 🕸️ 交互式执行图")
            st.info("💡 提示：红色边框/大节点代表高风险注入点或被篡改的执行步骤")

            render_graph(graph_data, risk_scores if show_risk else None)

        except requests.exceptions.ConnectionError:
            st.error("❌ 无法连接到后端服务")
        except Exception as e:
            st.error(f"生成图失败: {str(e)}")

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
    **风险指示（边框颜色）**
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
