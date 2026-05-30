# 规则初筛服务
"""基于关键词和简单启发式规则的日志初筛服务。

规则初筛用于在调用 LLM 之前快速标记高风险请求，并为 LLM 选择更合适的提示词模板。
"""
import re


class RuleFilter:
    """按攻击类型关键词计算风险分，并输出后续分析所需的上下文。"""

    PROMPT_TEMPLATE_LABELS = {
        # 内部模板名到前端展示文案的映射。
        'general': '通用安全分析',
        'sql_injection': 'SQL 注入检测',
        'xss': 'XSS 攻击检测',
        'directory_traversal': '目录遍历检测',
        'stream': '流式规则分析',
        'geo': '地理分布分析',
        'timeline': '行为时间线分析'
    }

    ATTACK_TYPE_TEMPLATE_MAP = {
        # 初筛命中的攻击类型到 LLM 提示词模板的映射。
        'SQL注入': 'sql_injection',
        'SQL 注入': 'sql_injection',
        'sql_injection': 'sql_injection',
        'XSS': 'xss',
        'XSS攻击': 'xss',
        'xss': 'xss',
        '目录遍历': 'directory_traversal',
        'directory_traversal': 'directory_traversal',
        '命令注入': 'general'
    }
    
    # SQL 注入关键词
    SQL_INJECTION_KEYWORDS = [
        'select', 'union', 'drop', 'insert', 'update', 'delete',
        'or 1=1', 'and 1=1', "' or '", '" or "',
        '--', ';', '/*', '*/',
        'sleep(', 'waitfor', 'benchmark(',
        'convert(', 'cast(', 'substring(',
        'exec(', 'execute(', 'xp_', 'sp_'
    ]
    
    # XSS 攻击关键词
    XSS_KEYWORDS = [
        '<script', '</script>', 'javascript:',
        'onerror=', 'onclick=', 'onload=', 'onmouseover=',
        'eval(', 'alert(', 'prompt(', 'confirm(',
        'document.cookie', 'document.write',
        '<img', '<iframe', '<svg', '<body',
        'expression(', 'vbscript:'
    ]
    
    # 目录遍历关键词
    PATH_TRAVERSAL_KEYWORDS = [
        '../', '..\\', '%2e%2e', '%252e',
        '/etc/passwd', '/etc/shadow',
        'c:\\windows', 'c:/windows',
        'boot.ini', 'win.ini'
    ]
    
    # 命令注入关键词
    COMMAND_INJECTION_KEYWORDS = [
        '|', ';', '&', '`', '$(',
        '/bin/sh', '/bin/bash', 'cmd.exe',
        'wget ', 'curl ', 'nc ', 'netcat',
        'chmod ', 'chown ', 'rm -rf'
    ]
    
    def __init__(self, config=None):
        self.config = config or {}
        self.risk_weights = {
            'sql_injection': 30,
            'xss': 25,
            'path_traversal': 25,
            'command_injection': 30
        }
    
    def analyze_entry(self, log_entry):
        """分析单个日志条目，返回风险分、命中类型和推荐提示词模板。"""
        risk_score = 0
        raw_matched_keywords = []
        prompt_templates = []
        attack_types = []
        
        # 组合需要检查的内容：URL、参数和 UA 是 Web 攻击 payload 最常出现的位置。
        check_content = f"{log_entry.get('url', '')} {log_entry.get('parameters', '')} {log_entry.get('user_agent', '')}".lower()
        raw_log = log_entry.get('raw_log', '').lower()
        
        # SQL 注入检测
        sql_matches = self._check_keywords(check_content, self.SQL_INJECTION_KEYWORDS)
        if sql_matches:
            risk_score += self.risk_weights['sql_injection']
            raw_matched_keywords.extend(sql_matches)
            prompt_templates.append('sql_injection')
            attack_types.append('SQL注入')
        
        # XSS 检测
        xss_matches = self._check_keywords(check_content, self.XSS_KEYWORDS)
        if xss_matches:
            risk_score += self.risk_weights['xss']
            raw_matched_keywords.extend(xss_matches)
            prompt_templates.append('xss')
            attack_types.append('XSS攻击')
        
        # 目录遍历检测
        path_matches = self._check_keywords(check_content, self.PATH_TRAVERSAL_KEYWORDS)
        if path_matches:
            risk_score += self.risk_weights['path_traversal']
            raw_matched_keywords.extend(path_matches)
            prompt_templates.append('directory_traversal')
            attack_types.append('目录遍历')
        
        # 命令注入检测
        cmd_matches = self._check_keywords(check_content, self.COMMAND_INJECTION_KEYWORDS)
        if cmd_matches:
            risk_score += self.risk_weights['command_injection']
            raw_matched_keywords.extend(cmd_matches)
            prompt_templates.append('general')
            attack_types.append('命令注入')
        
        # 状态码异常本身不是攻击，但大量 4xx/5xx 常见于探测和利用失败。
        status_code = log_entry.get('status_code', 0)
        if status_code >= 400 and status_code < 500:
            risk_score += 5
        elif status_code >= 500:
            risk_score += 10
        
        # URL 编码绕过检测
        if self._check_encoded_bypass(raw_log):
            risk_score += 15
            raw_matched_keywords.append('encoded_bypass')
        
        # 限制最高分，并去重提示词模板，避免同一攻击类型重复触发。
        risk_score = min(risk_score, 100)
        prompt_templates = list(dict.fromkeys(prompt_templates))
        template_labels = [self.PROMPT_TEMPLATE_LABELS.get(t, t) for t in prompt_templates]
        primary_attack_type = attack_types[0] if attack_types else ''
        
        return {
            'risk_score': risk_score,
            # 前端只展示一个清晰的初筛类别，避免暴露杂乱 payload 关键字。
            'matched_keywords': [primary_attack_type] if primary_attack_type else [],
            'prompt_templates': prompt_templates,
            'template_labels': template_labels,
            'raw_matched_keywords': list(dict.fromkeys(raw_matched_keywords)),
            'attack_types': attack_types,
            'should_analyze': risk_score >= 20  # 阈值
        }

    def classify_keyword(self, keyword):
        """根据命中词或攻击类型推断最合适的 LLM 提示词模板。"""
        if keyword in self.ATTACK_TYPE_TEMPLATE_MAP:
            return self.ATTACK_TYPE_TEMPLATE_MAP[keyword]
        keyword_lower = (keyword or '').lower()
        if keyword_lower in [kw.lower() for kw in self.SQL_INJECTION_KEYWORDS]:
            return 'sql_injection'
        if keyword_lower in [kw.lower() for kw in self.XSS_KEYWORDS]:
            return 'xss'
        if keyword_lower in [kw.lower() for kw in self.PATH_TRAVERSAL_KEYWORDS]:
            return 'directory_traversal'
        if keyword_lower in [kw.lower() for kw in self.COMMAND_INJECTION_KEYWORDS]:
            return 'general'
        return 'general'
    
    def _check_keywords(self, content, keywords):
        """检查关键词匹配"""
        matches = []
        for keyword in keywords:
            if keyword in content:
                matches.append(keyword)
        return matches
    
    def _check_encoded_bypass(self, content):
        """检查编码绕过"""
        # URL 编码检测
        if '%27' in content or '%22' in content:  # ' 和 "
            return True
        # Unicode 编码检测
        if '\\u0027' in content or '\\u0022' in content:
            return True
        return True if re.search(r'%[0-9a-fA-F]{2}', content) else False
    
    def get_risk_level(self, score):
        """根据分数获取风险等级"""
        if score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'low'
    
    def batch_filter(self, entries):
        """批量筛选日志条目，并按风险分从高到低排序。"""
        results = []
        
        for entry in entries:
            analysis = self.analyze_entry(entry)
            entry['initial_risk_score'] = analysis['risk_score']
            entry['risk_keywords'] = ','.join(analysis['matched_keywords'])
            entry['should_analyze'] = analysis['should_analyze']
            results.append(entry)
        
        # 按风险分数排序
        results.sort(key=lambda x: x['initial_risk_score'], reverse=True)
        
        return results
