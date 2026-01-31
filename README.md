# AgentGraph-Sentinel
核心创新1：世界首个基于执行图的Agent安全检测框架  将Agent执行流建模为有向无环图（DAG）  利用图同构算法检测行为异常（MELON思想的图化升级）  创新性：从"文本对比"升级为"执行路径对比"  核心创新2：图神经网络驱动的风险传播模型  基于GNN的污点分析（Taint Analysis）  节点嵌入检测器（InstructDetector的空间化实现）  创新性：首次将GNN应用于LLM安全防御  核心创新3：动态图手术防御机制  实时插入Sanitizer节点（Minimizer-Sanitizer的图化）  自适应防火墙策略（基于风险评分动态调整）  创新性：防御不再是"拦截"而是"修复"
