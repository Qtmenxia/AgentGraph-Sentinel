import os
import requests
import sys
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

# 1. 强制加载 .env 文件
# 假设脚本在 scripts/ 目录下，.env 在上一级目录
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
env_path = os.path.join(project_root, '.env')

print(f"📂 正在尝试加载 .env 文件路径: {env_path}")
load_dotenv(env_path)

def test_environment():
    print("\n" + "="*50)
    print("TEST 1: 环境变量检查")
    print("="*50)
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    model = os.getenv("OPENROUTER_MODEL", "openai/gpt-3.5-turbo")

    if not api_key:
        print("❌ 错误: 未找到 OPENROUTER_API_KEY。请检查 .env 文件！")
        return False, None, None, None
    
    # 打印部分 Key 以验证读取是否正确（防止读取到空字符串）
    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else "***"
    print(f"✅ API Key 已加载: {masked_key}")
    print(f"✅ Base URL: {base_url}")
    print(f"✅ Model: {model}")
    return True, api_key, base_url, model

def test_raw_http(api_key, base_url, model):
    print("\n" + "="*50)
    print("TEST 2: 原生 HTTP 请求测试 (绕过 LangChain)")
    print("="*50)
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "http://localhost:8501", # OpenRouter 要求的头
        "X-Title": "Debug-Script",
        "Content-Type": "application/json"
    }
    
    # OpenRouter 的 Chat 完成接口通常是 /chat/completions
    # 如果 base_url 结尾有 /v1，则拼接 /chat/completions
    target_url = base_url.rstrip('/') + "/chat/completions"
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Say 'Hello' if you can hear me."}],
    }

    print(f"📡 发送请求到: {target_url}")
    try:
        response = requests.post(target_url, headers=headers, json=payload, timeout=10)
        
        print(f"🔄 HTTP 状态码: {response.status_code}")
        
        if response.status_code == 200:
            print(f"✅ 响应成功: {response.json()['choices'][0]['message']['content']}")
            return True
        else:
            print(f"❌ 请求失败. 响应内容:\n{response.text}")
            return False
    except Exception as e:
        print(f"❌ 连接异常: {e}")
        return False

def test_langchain(api_key, base_url, model):
    print("\n" + "="*50)
    print("TEST 3: LangChain 集成测试")
    print("="*50)
    
    try:
        # 模拟 agent_executor.py 中的初始化方式
        llm = ChatOpenAI(
            openai_api_key=api_key,      # 注意：LangChain内部参数名通常是 openai_api_key
            openai_api_base=base_url,    # 注意：旧版可能用 openai_api_base，新版用 base_url
            model_name=model,
            temperature=0,
            default_headers={
                "HTTP-Referer": "http://localhost:8501",
                "X-Title": "AgentGraph-Debug"
            }
        )
        
        print("🤖 正在调用 LLM invoke()...")
        response = llm.invoke([HumanMessage(content="Test connection.")])
        print(f"✅ LangChain 调用成功: {response.content}")
        return True
    except Exception as e:
        print(f"❌ LangChain 调用失败: {e}")
        # 打印更多调试信息
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success_env, key, url, model = test_environment()
    
    if success_env:
        success_http = test_raw_http(key, url, model)
        
        if success_http:
            test_langchain(key, url, model)
        else:
            print("\n⚠️ 跳过 Test 3，因为原生 HTTP 请求已失败。请先解决 Key 或网络问题。")
