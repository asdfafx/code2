# -*- coding: utf-8 -*-
"""
LLM 分析服务 - 核心模块
基于阿里云 Qwen / DeepSeek 的智能日志安全分析
设计要点：
- max_tokens=512: 保证结果严谨
- temperature=0.1: 降低随机性，保证结果稳定
- timeout=10s: 避免系统卡顿
- 提示词模板: 角色设定 + 任务描述 + 日志信息 + 输出格式
"""

import json
import re
import requests
from sqlalchemy import text as sa_text


class PromptTemplateManager:
    """提示词模板管理器"""
    
    # ============ 通用分析模板 ============
    GENERAL_TEMPLATE = """【系统角色】
你是一位专业的网络安全专家，精通 Web 安全、渗透测试和日志分析。

【任务描述】
请分析以下 HTTP 请求日志，判断是否存在安全威胁。

【日志信息】
- 文件名：{filename}
- IP 地址：{ip_address}
- 请求时间：{request_time}
- 请求方法：{method}
- 请求 URL: {url}
- 请求参数：{parameters}
- 状态码：{status_code}
- User-Agent: {user_agent}
- 来源页面：{referer}
- 原始日志：{raw_log}

【初筛风险】
匹配到的风险关键词：{risk_keywords}
初步风险评分：{initial_risk_score}/100

【分析要求】
请从以下几个方面进行深入分析：
1. SQL 注入攻击（联合查询、布尔盲注、时间盲注、报错注入）
2. XSS 跨站脚本攻击（反射型、存储型、DOM 型）
3. 目录遍历/文件包含攻击
4. 命令注入攻击
5. 其他异常行为

【输出格式 - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！攻击类型，如：SQL注入/XSS攻击/目录遍历/命令注入/正常访问/无攻击",
  "risk_level": "必须填写！风险等级，只能是：low/medium/high/critical 中的一个",
  "conclusion": "简要结论（30字以内）",
  "reason": "详细分析理由（150字以内）",
  "confidence": 0.0-1.0之间的置信度分数,
  "suggestions": ["安全建议1", "建议2"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 如果检测到攻击，填写具体攻击类型（如：SQL注入、XSS攻击、目录遍历等）
   - 如果是正常请求，填写：正常访问 或 无攻击
   - 如果无法确定，填写：未知 或 待分析
   
2. risk_level（风险等级）- 必填！只能是以下五个值之一：
   - "正常": 完全正常的请求，无任何可疑特征
   - "低风险": 轻微可疑，但大概率是正常请求
   - "中风险": 中风险（可疑行为、轻度异常）
   - "高风险": 高风险（明显攻击特征）
   - "严重风险": 严重风险（高危漏洞利用、数据泄露风险）

【输出示例】
✅ 正确示例1（检测到攻击）：
{{
  "attack_type": "SQL注入",
  "risk_level": "高风险",
  "conclusion": "检测到SQL注入攻击",
  "reason": "参数中包含UNION SELECT语句",
  "confidence": 0.95,
  "suggestions": ["使用参数化查询", "过滤SQL关键字"]
}}

✅ 正确示例2（正常请求）：
{{
  "attack_type": "正常访问",
  "risk_level": "正常",
  "conclusion": "正常HTTP请求",
  "reason": "未检测到攻击特征",
  "confidence": 0.99,
  "suggestions": []
}}

✅ 正确示例3（低风险请求）：
{{
  "attack_type": "正常访问",
  "risk_level": "低风险",
  "conclusion": "基本正常的请求",
  "reason": "存在轻微可疑特征，但大概率是正常行为",
  "confidence": 0.85,
  "suggestions": ["建议持续监控"]
}}

❌ 错误示例（不要这样返回）：
- 缺少 attack_type 或 risk_level 字段
- risk_level 填写了 "无"/"正常"/"异常" 等无效值
- 返回了 JSON 以外的文本

【注意事项】
- 请基于请求的语义内容进行判断
- 对于正常请求，attack_type="正常访问", risk_level="正常"
- 如果无法确定，attack_type="未知", risk_level="medium"
- 只返回 JSON，不要返回任何解释性文本
"""
    
    # ============ SQL 注入专用模板 ============
    SQL_INJECTION_TEMPLATE = """【系统角色】
你是 SQL 注入攻击检测专家，对各类 SQL 注入技术有深入研究。

【任务描述】
专门检测请求中是否包含 SQL 注入攻击特征。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 参数：{parameters}
- 完整请求：{raw_request}
- 状态码：{status_code}

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

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！SQL注入 或 正常访问",
  "injection_type": "联合查询/布尔盲注/时间盲注/报错注入/堆叠注入/无",
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "payload_detected": "检测到的恶意payload（如有）",
  "conclusion": "简要结论",
  "reason": "详细分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["防护建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到SQL注入：填写 "SQL注入"
   - 正常请求：填写 "正常访问"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "正常": 正常请求、无注入特征
   - "中风险": 可疑参数、可能存在注入点
   - "高风险": 明显SQL注入攻击
   - "严重风险": 高危SQL注入、已成功利用

【输出示例】
✅ 正确示例1（检测到注入）：
{{
  "attack_type": "SQL注入",
  "injection_type": "联合查询",
  "risk_level": "高风险",
  "payload_detected": "UNION SELECT NULL, NULL, NULL",
  "conclusion": "检测到联合查询注入",
  "reason": "参数中包含UNION SELECT语句",
  "confidence": 0.95,
  "suggestions": ["使用参数化查询", "过滤SQL关键字"]
}}

✅ 正确示例2（正常请求）：
{{
  "attack_type": "正常访问",
  "injection_type": "无",
  "risk_level": "正常",
  "payload_detected": "",
  "conclusion": "正常HTTP请求",
  "reason": "未检测到SQL注入特征",
  "confidence": 0.99,
  "suggestions": []
}}

【注意】只返回 JSON，不要返回任何解释性文本
"""
    
    # ============ XSS 攻击专用模板 ============
    XSS_TEMPLATE = """【系统角色】
你是 XSS 跨站脚本攻击检测专家，精通各类 XSS 攻击和绕过技术。

【任务描述】
识别请求中是否包含 XSS 攻击代码。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 参数：{parameters}
- Referer: {referer}
- User-Agent: {user_agent}

【常见 XSS 手法】
1. 反射型 XSS：恶意脚本通过 URL 参数注入
2. 存储型 XSS：恶意内容被存储到服务器
3. DOM 型 XSS：利用 JavaScript 操作 DOM
4. 绕过技巧：
   - 大小写混合：<ScRiPt>
   - 编码绕过：HTML实体、URL编码、Unicode
   - 标签绕过：<img src=x onerror=...>
   - 事件处理器：onerror, onclick, onload
   - JavaScript 协议：javascript:alert()

【检测要点】
1. 查找危险标签：<script>, <iframe>, <object>, <embed>
2. 检查事件处理器：onerror=, onload=, onclick=, onmouseover=
3. 识别协议：javascript:, vbscript:, data:
4. 注意编码绕过和大小写混合

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！XSS攻击 或 正常访问",
  "xss_type": "反射型/存储型/DOM型/无",
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "malicious_tags": ["检测到的恶意标签或payload"],
  "conclusion": "简要结论",
  "reason": "详细分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["防护建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到XSS攻击：填写 "XSS攻击"
   - 正常请求：填写 "正常访问"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "low": 正常请求、无XSS特征
   - "medium": 可疑参数、可能包含恶意脚本
   - "high": 明显XSS攻击
   - "critical": 高危XSS、已成功注入

【输出示例】
✅ 正确示例1（检测到XSS）：
{{
  "attack_type": "XSS攻击",
  "xss_type": "反射型",
  "risk_level": "high",
  "malicious_tags": ["<script>alert('XSS')</script>"],
  "conclusion": "检测到反射型XSS攻击",
  "reason": "参数中包含<script>标签",
  "confidence": 0.95,
  "suggestions": ["对输出进行HTML编码", "使用CSP策略"]
}}

✅ 正确示例2（正常请求）：
{{
  "attack_type": "正常访问",
  "xss_type": "无",
  "risk_level": "low",
  "malicious_tags": [],
  "conclusion": "正常HTTP请求",
  "reason": "未检测到XSS特征",
  "confidence": 0.99,
  "suggestions": []
}}

【注意】只返回 JSON，不要返回任何解释性文本
"""
    
    # ============ 目录遍历专用模板 ============
    DIRECTORY_TRAVERSAL_TEMPLATE = """【系统角色】
你是目录遍历和文件包含攻击检测专家。

【任务描述】
检测请求中是否包含目录遍历或文件包含攻击。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 参数：{parameters}
- 完整请求：{raw_request}

【常见目录遍历手法】
1. 经典遍历：../, ..\\, ../
2. URL 编码：%2e%2e%2f, %2e%2e/
3. Unicode 编码：..%c0%af, ..%c1%9c
4. 空字节绕过：..%00.txt
5. 双编码：%252e%252e%252f
6. 路径混淆：....//....//....//
7. 服务器特定：/etc/passwd, C:\\Windows\\System32

【常见目标文件】
- 系统文件：/etc/passwd, C:\\boot.ini
- 配置文件：config.php, web.config, .htaccess
- 日志文件：access.log, error.log
- 敏感数据：.env, database.sql

【检测要点】
1. 检查路径穿越序列：../, ..\\, ../
2. 识别敏感文件路径
3. 分析编码绕过技巧
4. 评估攻击可行性

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！目录遍历 或 正常访问",
  "traversal_type": "经典遍历/编码绕过/文件包含/无",
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "target_file": "尝试访问的目标文件（如有）",
  "conclusion": "简要结论",
  "reason": "详细分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["防护建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到目录遍历：填写 "目录遍历"
   - 正常请求：填写 "正常访问"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "low": 正常请求、无目录遍历特征
   - "medium": 可疑参数、可能包含路径遍历
   - "high": 明显目录遍历攻击
   - "critical": 高危目录遍历、已成功访问敏感文件

【输出示例】
✅ 正确示例1（检测到目录遍历）：
{{
  "attack_type": "目录遍历",
  "traversal_type": "经典遍历",
  "risk_level": "high",
  "target_file": "/etc/passwd",
  "conclusion": "检测到目录遍历攻击",
  "reason": "参数中包含../尝试访问/etc/passwd",
  "confidence": 0.95,
  "suggestions": ["验证文件路径", "使用白名单机制"]
}}

✅ 正确示例2（正常请求）：
{{
  "attack_type": "正常访问",
  "traversal_type": "无",
  "risk_level": "low",
  "target_file": "",
  "conclusion": "正常HTTP请求",
  "reason": "未检测到目录遍历特征",
  "confidence": 0.99,
  "suggestions": []
}}

【注意】只返回 JSON，不要返回任何解释性文本
"""
    
    # ============ 流式规则分析模板 ============
    STREAM_TEMPLATE = """【系统角色】
你是实时安全监控专家，擅长流式日志分析和实时威胁检测。

【任务描述】
基于规则模式对连续日志流进行实时威胁检测和关联分析。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 参数：{parameters}
- 时间：{request_time}
- 状态码：{status_code}
- 风险关键词：{risk_keywords}

【流式分析规则】
1. 频率规则：同一IP在短时间内的请求频率
2. 模式规则：相同请求参数的重复访问
3. 序列规则：攻击链中的典型请求序列（如探测→注入→利用）
4. 异常规则：与正常基线偏离的行为

【关联分析要点】
1. 同一IP的历史请求模式
2. 相同参数的跨IP访问
3. 攻击阶段的自动识别（侦察→尝试→利用→维持）
4. Bot/Crawler 与真实用户的区分

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！流式检测 或 正常访问 或 具体攻击类型",
  "pattern_match": ["匹配到的规则1", "规则2"],
  "attack_stage": "侦察/尝试/利用/维持/无",
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "conclusion": "简要结论",
  "reason": "关联分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到攻击：填写具体攻击类型（如：SQL注入、XSS攻击、目录遍历等）
   - 正常请求：填写 "正常访问"
   - 流式检测但无明确攻击：填写 "流式检测"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "low": 正常请求、无异常特征
   - "medium": 可疑行为、可能违反安全策略
   - "high": 明显攻击行为
   - "critical": 高危攻击、已成功利用

【注意】只返回 JSON，不要返回任何解释性文本
"""

    # ============ 地理分布分析模板 ============
    GEO_TEMPLATE = """【系统角色】
你是网络安全情报分析师，专注于基于地理位置的威胁情报分析。

【任务描述】
基于IP地址地理位置分析攻击来源分布、威胁地域特征和攻击趋势。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 攻击类型：{risk_keywords}
- 时间：{request_time}
- 状态码：{status_code}

【地理位置分析维度】
1. IP归属地分析：国家/地区/城市/ISP
2. 威胁情报关联：该地区的历史攻击记录
3. 攻击源分类：IDC服务器/僵尸网络/真实用户/代理/VPN
4. 地理攻击热力：高频攻击来源地区

【高危地区特征】
- 东南亚：博彩类攻击较多
- 东欧：黑客组织活跃
- 北美：成熟APT组织
- 国内：内鬼和竞争对手

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！地理威胁 或 正常访问 或 具体攻击类型",
  "ip_location": "推测的地理位置",
  "threat_region": "高危/中危/低危地区",
  "threat_source_type": "IDC/僵尸网络/代理/真实用户",
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "regional_trend": "该地区攻击趋势描述",
  "conclusion": "简要结论",
  "reason": "地理分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["情报建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到攻击：填写具体攻击类型（如：SQL注入、XSS攻击等）
   - 地理位置可疑但无具体攻击：填写 "地理威胁"
   - 正常请求：填写 "正常访问"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "low": 正常请求、来自安全地区
   - "medium": 可疑地区、可能使用代理
   - "high": 来自高危地区、疑似僵尸网络
   - "critical": 已知恶意IP、高危攻击源

【注意】只返回 JSON，不要返回任何解释性文本
"""

    # ============ 行为时间线分析模板 ============
    TIMELINE_TEMPLATE = """【系统角色】
你是攻击行为分析专家，精通攻击链重构和时间序列分析。

【任务描述】
重构攻击者的完整攻击过程，识别攻击阶段、意图演变和关键时间节点。

【待分析请求】
- IP：{ip_address}
- URL: {url}
- 参数：{parameters}
- 时间：{request_time}
- 方法：{method}
- 攻击类型：{risk_keywords}

【攻击阶段模型】
1. 侦察阶段(Recon)：robots.txt探测、目录扫描、指纹识别
2. 突破阶段(Infiltration)：SQL注入、XSS、文件上传
3. 利用阶段(Exploitation)：获取数据、权限提升
4. 维持阶段(Persistence)：后门植入、权限维持
5. 横向移动(Lateral Movement)：内部探测、扩散攻击

【时间线分析要点】
1. 攻击者首次出现的探测行为
2. 攻击手法的演变和升级
3. 攻击时间间隔（快=自动化工具，慢=人工）
4. 成功与失败尝试的比例
5. 攻击目标的选择逻辑

【输出 JSON - 严格要求】
⚠️ 必须严格按照以下 JSON 格式返回，不得有任何其他输出！

{{
  "attack_type": "必须填写！行为时间线 或 具体攻击类型",
  "attack_stage": "侦察/突破/利用/维持/横向",
  "stage_transition": "上一阶段→当前阶段",
  "timeline_order": 1,
  "risk_level": "必须填写！只能是：low/medium/high/critical 中的一个",
  "attack_timeline": "时间线描述",
  "threat_evolution": "攻击手法演变",
  "conclusion": "简要结论",
  "reason": "时间线分析理由",
  "confidence": 0.0-1.0,
  "suggestions": ["处置建议"]
}}

【字段要求说明】
1. attack_type（攻击类型）- 必填！
   - 检测到攻击：填写具体攻击类型（如：SQL注入、XSS攻击等）
   - 仅分析时间线：填写 "行为时间线"
   - 正常请求：填写 "正常访问"
   
2. risk_level（风险等级）- 必填！只能是以下四个值之一：
   - "low": 正常请求、仅侦察行为
   - "medium": 可疑行为、可能尝试攻击
   - "high": 明显攻击行为、已突破防线
   - "critical": 已成功利用、正在维持访问

【注意】只返回 JSON，不要返回任何解释性文本
"""
    
    # ============ 多模型分析模板 ============
    
    # 模板映射
    TEMPLATES = {
        'general': GENERAL_TEMPLATE,
        'sql_injection': SQL_INJECTION_TEMPLATE,
        'xss': XSS_TEMPLATE,
        'directory_traversal': DIRECTORY_TRAVERSAL_TEMPLATE,
        'stream': STREAM_TEMPLATE,
        'geo': GEO_TEMPLATE,
        'timeline': TIMELINE_TEMPLATE
    }
    
    def __init__(self):
        self.templates = self.TEMPLATES
    
    def get_template(self, template_name):
        """获取指定模板"""
        return self.templates.get(template_name, self.GENERAL_TEMPLATE)
    
    def build_prompt(self, log_entry, risk_keywords, analysis_type='general', filename=None):
        """构建提示词"""
        template = self.get_template(analysis_type)
        template_labels = {
            'general': '通用安全分析',
            'sql_injection': 'SQL注入检测',
            'xss': 'XSS攻击检测',
            'directory_traversal': '目录遍历检测',
            'stream': '流式规则分析',
            'geo': '地理分布分析',
            'timeline': '行为时间线分析'
        }
        risk_keyword_labels = [template_labels.get(keyword, keyword) for keyword in risk_keywords]
        
        # 处理时间格式
        request_time = log_entry.get('request_time', '')
        if hasattr(request_time, 'strftime'):
            request_time = request_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # 构建完整请求
        raw_request = f"{log_entry.get('method', '')} {log_entry.get('url', '')}"
        if log_entry.get('parameters'):
            raw_request += f"?{log_entry.get('parameters')}"
        
        # 初筛风险评分转等级
        initial_score = log_entry.get('initial_risk_score', 0)
        if initial_score >= 60:
            risk_level = 'high'
        elif initial_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        prompt = template.format(
            ip_address=log_entry.get('ip_address', '未知'),
            request_time=request_time or '未知',
            method=log_entry.get('method', '未知'),
            url=log_entry.get('url', '未知'),
            parameters=log_entry.get('parameters', '无'),
            status_code=log_entry.get('status_code', 0),
            user_agent=log_entry.get('user_agent', '未知'),
            referer=log_entry.get('referer', '无'),
            raw_log=log_entry.get('raw_log', '无'),
            risk_keywords=', '.join(risk_keyword_labels) if risk_keyword_labels else '无',
            initial_risk_score=initial_score,
            raw_request=raw_request,
            risk_level=risk_level,
            filename=filename or '未知文件'  # 添加文件名
        )
        
        return prompt


class LLMService:
    """
    LLM 分析服务
    
    调用参数（根据系统设计）：
    - max_tokens=512: 保证结果严谨
    - temperature=0.1: 降低随机性
    - timeout=10s: 避免系统卡顿
    """
    
    # 响应验证 Schema
    RESPONSE_SCHEMA = {
        "type": "object",
        "required": ["attack_type", "risk_level", "reason"],
        "properties": {
            "attack_type": {"type": "string"},
            "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "conclusion": {"type": "string"},
            "reason": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "suggestions": {"type": "array", "items": {"type": "string"}}
        }
    }
    
    def __init__(self, api_endpoint, model_name, api_key=None, thinking_enabled=False, reasoning_effort='high'):
        """
        初始化 LLM 服务
        
        Args:
            api_endpoint: API 地址
            model_name: 模型名称
            api_key: API 密钥
            thinking_enabled: 是否启用思考模式 (DeepSeek)
            reasoning_effort: 思考强度 (low/medium/high/max)
        """
        self.api_endpoint = api_endpoint.rstrip('/')
        self.model_name = model_name
        self.api_key = api_key
        self.prompt_manager = PromptTemplateManager()
        
        # DeepSeek 思考模式配置
        self.thinking_enabled = thinking_enabled
        self.reasoning_effort = reasoning_effort
        
        # 根据 API 类型设置默认参数（系统设计要求）
        self.max_tokens = 512
        self.temperature = 0.5  # 严谨模式
        
        # 从环境变量或配置获取超时设置，默认30秒
        import os
        self.timeout = int(os.environ.get('LLM_TIMEOUT', 180))
        
        # 判断 API 类型
        self.is_dashscope = 'dashscope' in self.api_endpoint.lower() or 'aliyun' in self.api_endpoint.lower()
        self.is_deepseek = 'deepseek' in self.api_endpoint.lower()
    
    def analyze(self, log_entry, risk_keywords, analysis_type, filename):
        """
        分析单个日志条目
        
        Args:
            log_entry: 日志条目字典
            risk_keywords: 风险关键词列表
            analysis_type: 分析类型 (general/sql_injection/xss/directory_traversal)
            filename: 文件名（用于插入数据库，必填）
        
        Returns:
            分析结果字典
        """
        try:
            # 1. 构建提示词（传入 filename）
            prompt = self.prompt_manager.build_prompt(log_entry, risk_keywords, analysis_type, filename)
            
            print(f"\n{'='*80}")
            print(f"[LLM 分析] 开始分析")
            print(f"{'='*80}")
            print(f"文件名: {filename}")
            print(f"分析类型: {analysis_type}")
            print(f"API 端点: {self.api_endpoint}")
            print(f"模型名称: {self.model_name}")
            print(f"API Key: {'已配置' if self.api_key else '未配置'}")
            print(f"日志URL: {log_entry.get('url', 'N/A')[:100]}")
            print(f"{'='*80}\n")
            
            # 2. 调用 LLM API
            response = self._call_llm_api(prompt)
            
            # 3. 解析响应
            result = self._parse_response(response)
            
            # 4. 确保必需字段存在
            self._ensure_required_fields(result)
            
            # 5. 保存原始信息
            result['prompt'] = prompt
            result['raw_response'] = response
            result['analysis_type'] = analysis_type
            
            # 6. 添加 filename（从参数中获取）
            if filename:
                result['filename'] = filename
            
            # 6. 添加 entry_id 和 import_id（从 log_entry 中获取）
            # 保持外键关系：entry_id 指向 log_entries.entry_id
            if 'entry_id' in log_entry:
                result['entry_id'] = log_entry['entry_id']
            # if 'import_id' in log_entry:
            #     result['import_id'] = log_entry['import_id']
            
            # 6. 插入数据库（如果提供了 filename）

            self._save_to_database(result, filename)
            
            print(f"[LLM 分析] ✅ 分析成功: attack_type={result.get('attack_type')}, risk_level={result.get('risk_level')}")
            
            return result
            
        except Exception as e:
            print(f"\n{'='*80}")
            print(f"[LLM 分析] ❌ 分析失败")
            print(f"{'='*80}")
            print(f"错误信息: {str(e)}")
            print(f"{'='*80}\n")
            import traceback
            traceback.print_exc()
            
            # ⚠️ 禁用降级机制，直接抛出异常
            raise Exception(f"LLM API 调用失败：{str(e)}。请检查 API Key 是否正确、网络连接是否正常。")
    
    def _save_to_database(self, result, filename):
        """
        将分析结果保存到数据库（使用原生SQL，直接插入）
        
        Args:
            result: 分析结果字典
            filename: 文件名
        """
        try:
            from app import db
            from datetime import datetime, timezone
            
            # 处理 attack_type
            attack_type = result.get('attack_type', '未知')
            if attack_type in ['none', 'None', '无', ''] or not attack_type:
                attack_type = '正常访问'
            
            # 处理 risk_level
            raw_risk_level = result.get('risk_level', '中风险')
            if attack_type == '正常访问':
                risk_level = '低风险'
            else:
                risk_level = raw_risk_level
            
            # 获取结论和原因
            conclusion = result.get('conclusion', result.get('llm_conclusion', ''))
            reason = result.get('reason', result.get('analysis_reason', ''))
            
            # 使用原生 SQL 直接插入，每次操作后立即提交
            # 插入新记录（entry_id 先插入 NULL，然后用 result_id 填充）
            insert_sql = """
                INSERT INTO analysis_results 
                (entry_id, filename, attack_type, risk_level, llm_conclusion, 
                 analysis_reason, confidence_score, prompt_template, llm_response_raw, analysis_time)
                VALUES 
                (:entry_id, :filename, :attack_type, :risk_level, :llm_conclusion,
                 :analysis_reason, :confidence_score, :prompt_template, :llm_response_raw, :analysis_time)
            """
            
            insert_params = {
                "entry_id": result.get('entry_id', 0),  # 使用 result 中的 entry_id
                "filename": filename or ' ',
                "attack_type": attack_type,
                "risk_level": risk_level,
                "llm_conclusion": conclusion,
                "analysis_reason": reason,
                "confidence_score": result.get('confidence', 0.5),
                "prompt_template": result.get('prompt', ''),
                "llm_response_raw": str(result),
                "analysis_time": datetime.now(timezone.utc)
            }
            
            print(f"[LLM Service] 准备保存分析结果:")
            print(f"  entry_id: {insert_params['entry_id']}")
            print(f"  filename: {insert_params['filename']}")
            print(f"  attack_type: {insert_params['attack_type']}")
            print(f"  risk_level: {insert_params['risk_level']}")
            
            db.session.execute(sa_text(insert_sql), insert_params)
            db.session.commit()
            
            print(f"[LLM Service] ✅ 分析结果已保存到数据库")
                    
        except Exception as save_error:
            print(f"[LLM Service] ❌ 保存失败: {str(save_error)}")
            import traceback
            print(traceback.format_exc())
            db.session.rollback()
    
    def _call_llm_api(self, prompt):
        """调用 LLM API"""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        if self.is_dashscope:
            # 阿里云百炼 API
            payload = {
                'model': self.model_name,
                'input': {
                    'messages': [
                        {'role': 'user', 'content': prompt}
                    ]
                },
                'parameters': {
                    'result_format': 'message',
                    'max_tokens': self.max_tokens,
                    'temperature': self.temperature
                }
            }
            api_url = f"{self.api_endpoint}/services/aigc/text-generation/generation"
            
            # 完整打印 DashScope 请求体
            print(f"\n{'='*70}")
            print(f"[DEBUG] 阿里云百炼 DashScope API 完整请求体")
            print(f"{'='*70}")
            
            print(f"\n📌 请求 URL:")
            print(f"   {api_url}")
            
            print(f"\n📌 请求头 (Headers):")
            print(json.dumps(headers, indent=2, ensure_ascii=False))
            
            print(f"\n📌 请求体 (Request Body):")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            
            print(f"\n📌 请求体详细参数:")
            print(f"   - model: {payload['model']}")
            print(f"   - input.messages[0].role: {payload['input']['messages'][0]['role']}")
            print(f"   - input.messages[0].content 长度: {len(prompt)} 字符")
            print(f"   - parameters.result_format: {payload['parameters']['result_format']}")
            print(f"   - parameters.max_tokens: {payload['parameters']['max_tokens']}")
            print(f"   - parameters.temperature: {payload['parameters']['temperature']}")
            
            print(f"\n📌 Token 估算:")
            print(f"   - Prompt token ≈ {len(prompt) // 2} (中文)")
            print(f"   - 预计总 token ≈ {len(prompt) // 2 + self.max_tokens}")
            
            print(f"\n📌 总请求体大小: {len(json.dumps(payload, ensure_ascii=False))} 字符")
            print(f"{'='*70}\n")
            
        elif self.is_deepseek:
            # DeepSeek API - 官方格式
            # 注意：对于需要 JSON 输出的场景，禁用思考模式
            payload = {
                'model': self.model_name,
                'messages': [
                    {'role': 'system', 'content': '你是一位专业的网络安全专家，精通 Web 安全、渗透测试和日志分析。'},
                    {'role': 'user', 'content': prompt}
                ],
                'max_tokens': self.max_tokens,
                'temperature': self.temperature,
                'stream': False  # 非流式输出
                # 注意：已移除 thinking 和 reasoning_effort，因为思考模式会导致 content 为空
            }
            
            api_url = f"{self.api_endpoint}/chat/completions"
            
            print(f"\n{'='*80}")
            print(f"[DeepSeek API] 请求配置")
            print(f"{'='*80}")
            print(f"URL: {api_url}")
            print(f"Model: {self.model_name}")
            print(f"Temperature: {self.temperature}")
            print(f"Max Tokens: {self.max_tokens}")
            print(f"Thinking: disabled (JSON 输出需要)")
            print(f"Stream: false")
            print(f"{'='*80}\n")
            
        else:
            # Ollama 或兼容 OpenAI 格式
            payload = {
                'model': self.model_name,
                'messages': [{'role': 'user', 'content': prompt}],
                'max_tokens': self.max_tokens,
                'temperature': self.temperature
            }
            if '/v1' not in self.api_endpoint:
                api_url = f"{self.api_endpoint}/api/chat"
            else:
                api_url = f"{self.api_endpoint}/chat/completions"
        
        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            
            # 解析不同 API 的响应格式
            if self.is_dashscope:
                # DashScope 响应格式
                return result.get('output', {}).get('choices', [{}])[0].get('message', {}).get('content', '')
            elif self.is_deepseek:
                # DeepSeek 响应格式
                message = result['choices'][0]['message']
                content = message.get('content', '')
                
                # 返回最终答案
                return content
            else:
                return result.get('choices', [{}])[0].get('message', {}).get('content', '')
                
        except requests.Timeout:
            raise Exception("LLM API 请求超时（10秒）")
        except requests.RequestException as e:
            raise Exception(f"LLM API 调用失败：{str(e)}")
    
    def _parse_response(self, response_text):
        """解析 LLM 响应"""
        if not response_text:
            return self._get_default_result()
        
        # 尝试直接解析 JSON
        try:
            return json.loads(response_text.strip())
        except json.JSONDecodeError:
            pass
        
        # 尝试从文本中提取 JSON
        return self._extract_json_from_text(response_text)
    
    def _extract_json_from_text(self, text):
        """从文本中提取 JSON"""
        # 查找 JSON 块
        json_patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*\{.*?\}\s*```',
            r'\{[^{}]*"[^{}]*":[^{}]*\}'
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    json_str = match.group(0)
                    # 清理 markdown 代码块标记
                    json_str = re.sub(r'```json\s*', '', json_str)
                    json_str = re.sub(r'```\s*', '', json_str)
                    return json.loads(json_str)
                except:
                    pass
        
        # 尝试查找第一个 { 到最后一个 }
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end+1])
            except:
                pass
        
        # 无法解析，返回默认结果
        return self._get_default_result(text)
    
    def _get_default_result(self, raw_text=''):
        """获取默认结果"""
        return {
            'attack_type': '分析异常',
            'risk_level': 'medium',
            'conclusion': '无法解析 LLM 响应',
            'reason': f'LLM 返回格式异常，已使用默认分析结果。原始响应: {raw_text[:100]}',
            'confidence': 0.5
        }
    def _ensure_required_fields(self, result):
        """确保必需字段存在"""
        required_fields = {
            'attack_type': '未知攻击',
            'risk_level': '中风险',
            'conclusion': '',
            'reason': '',
            'confidence': 0.5,
            'suggestions': ['建议人工审核']
        }
        
        for field, default_value in required_fields.items():
            if field not in result or result[field] is None:
                result[field] = default_value
        
        # 验证 risk_level（支持中文和英文）
        valid_levels_cn = ['正常', '低风险', '中风险', '高风险', '严重风险']
        valid_levels_en = ['normal', 'low', 'medium', 'high', 'critical']
        
        risk_level = str(result.get('risk_level', '中风险')).strip().lower()
        
        # 如果是英文，转换为中文
        if risk_level in valid_levels_en:
            level_map = {'normal': '正常', 'low': '低风险', 'medium': '中风险', 'high': '高风险', 'critical': '严重风险'}
            result['risk_level'] = level_map[risk_level]
        elif risk_level not in [v.lower() for v in valid_levels_cn]:
            # 模糊匹配
            if 'normal' in risk_level or '正常' in risk_level:
                result['risk_level'] = '正常'
            elif 'low' in risk_level or '低' in risk_level:
                result['risk_level'] = '低风险'
            elif 'medium' in risk_level or '中' in risk_level:
                result['risk_level'] = '中风险'
            elif 'high' in risk_level or '高' in risk_level:
                result['risk_level'] = '高风险'
            elif 'critical' in risk_level or '严重' in risk_level:
                result['risk_level'] = '严重风险'
            else:
                result['risk_level'] = '中风险'
        else:
            # 保持中文格式
            for cn_level in valid_levels_cn:
                if cn_level.lower() in risk_level:
                    result['risk_level'] = cn_level
                    break
        
        # 验证 confidence
        confidence = result.get('confidence', 0.5)
        if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
            try:
                result['confidence'] = float(confidence)
            except:
                result['confidence'] = 0.5
    
    def _fallback_analysis(self, log_entry, risk_keywords, error_msg, analysis_type):
        """降级分析（当 LLM 不可用时）"""
        return {
            'attack_type': '规则匹配',
            'risk_level': '中风险',
            'conclusion': f'检测到风险：{", ".join(risk_keywords[:3]) if risk_keywords else "无"}',
            'reason': f'LLM 分析失败：{error_msg}。基于规则匹配发现潜在风险。',
            'confidence': 0.6,
            'suggestions': ['建议人工审核', '检查相关安全策略'],
            'is_fallback': True,
            'analysis_type': analysis_type
        }
