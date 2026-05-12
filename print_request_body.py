# -*- coding: utf-8 -*-
"""
打印 qwen-plus API 的完整请求体
"""
import os
import json
import sys

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 加载 .env
def load_env_file():
    """加载 .env 文件"""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip("'").strip('"')

load_env_file()

# 获取 API Key
api_key = os.environ.get('DASHSCOPE_API_KEY', '')

# 构建完整的提示词
prompt = """【系统角色】
你是 SQL 注入攻击检测专家，对各类 SQL 注入技术有深入研究。

【任务描述】
专门检测请求中是否包含 SQL 注入攻击特征。

【待分析请求】
- IP：192.168.1.100
- URL: /api/users?id=1 OR 1=1--
- 参数：id=1 OR 1=1--
- 完整请求：GET /api/users?id=1 OR 1=1--?id=1 OR 1=1--
- 状态码：200

【常见 SQL 注入手法】
1. 联合查询注入：UNION SELECT, UNION ALL
2. 布尔盲注：AND 1=1, AND 1=2, OR 1=1
3. 时间盲注：SLEEP(), BENCHMARK(), WAITFOR DELAY
4. 报错注入：CONVERT(), EXTRACTVALUE(), UPDATEXML()
5. 堆叠注入：分号;分隔多条 SQL
6. 宽字节注入：%df' 绕过过滤
7. Base64 注入：编码绕过检测

【检测步骤】
1. 检查参数中是否包含 SQL 关键字（SELECT, UNION, INSERT, UPDATE, DELETE, DROP）
2. 分析特殊字符（单引号'、双引号"、分号;、注释--、/*）
3. 判断参数语义是否试图操纵 SQL 查询
4. 检查编码绕过技巧（URL编码、Unicode、Hex）
5. 综合评估注入可能性和风险等级

【输出 JSON】
{
  "attack_type": "SQL注入",
  "injection_type": "联合查询/布尔盲注/时间盲注/报错注入/堆叠注入/无",
  "risk_level": "low/medium/high/critical",
  "payload_detected": "检测到的恶意payload（如有）",
  "conclusion": "简要结论",
  "reason": "详细分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["防护建议"]
}

【注意】如无注入特征，返回 injection_type="无"，risk_level="low"
"""

# 构建请求体
payload = {
    'model': 'qwen-plus',
    'input': {
        'messages': [
            {'role': 'user', 'content': prompt}
        ]
    },
    'parameters': {
        'result_format': 'message',
        'max_tokens': 512,
        'temperature': 0.1
    }
}

# 打印 API 端点
api_url = 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'

print("=" * 70)
print("阿里云 DashScope (qwen-plus) API 完整请求体")
print("=" * 70)

print("\n📌 请求 URL:")
print(f"   {api_url}")

print("\n📌 请求头 (Headers):")
print(json.dumps({
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {api_key[:10]}...{api_key[-4:]}' if api_key else 'Bearer (未设置)'
}, indent=2, ensure_ascii=False))

print("\n📌 请求体 (Request Body):")
print(json.dumps(payload, indent=2, ensure_ascii=False))

print("\n📌 请求体详细参数说明:")
print("-" * 70)
print("""
1. model: str
   - 模型名称，这里是 'qwen-plus'

2. input: object
   - 输入对象，包含对话消息

3. input.messages: array
   - 消息数组，每个消息包含：
     * role: str - 角色 ('system', 'user', 'assistant')
     * content: str - 消息内容（上面的 prompt）

4. parameters: object
   - 参数对象，包含生成参数

5. parameters.result_format: str
   - 结果格式，这里是 'message'

6. parameters.max_tokens: int
   - 最大生成 token 数，这里是 512

7. parameters.temperature: float
   - 温度参数，控制随机性（0.1 = 较确定性）
   - 范围: 0.0-1.0，越低越确定
""")

print("\n📌 Prompt 内容长度:")
print(f"   {len(prompt)} 字符")
print(f"   约 {len(prompt) * 2} token (中文约2字符/token)")

print("\n📌 总请求体大小:")
print(f"   {len(json.dumps(payload, ensure_ascii=False))} 字符")
