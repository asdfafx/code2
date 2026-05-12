# 多模型LLM服务 - 支持OpenAI、文心一言、Ollama等
import requests
import json
from datetime import datetime


class MultiModelLLMService:
    """多模型LLM服务"""
    
    def __init__(self):
        self.supported_models = {
            'ollama': self._call_ollama,
            'openai': self._call_openai,
            'qianfan': self._call_qianfan  # 文心一言
        }
    
    def analyze_log(self, log_entry, model_config):
        """
        分析日志条目
        
        Args:
            log_entry: 日志条目字典
            model_config: 模型配置，包含model_type, api_endpoint, api_key等
        
        Returns:
            分析结果字典
        """
        model_type = model_config.get('model_type', 'ollama').lower()
        
        if model_type not in self.supported_models:
            raise ValueError(f"不支持的模型类型: {model_type}")
        
        # 构建提示词
        prompt = self._build_prompt(log_entry)
        
        # 调用对应的模型
        try:
            result = self.supported_models[model_type](prompt, model_config)
            return result
        except Exception as e:
            print(f"调用 {model_type} 模型失败: {e}")
            raise
    
    def _build_prompt(self, log_entry):
        """构建分析提示词"""
        ip_address = log_entry.get('ip_address', '')
        url = log_entry.get('url', '')
        method = log_entry.get('method', 'GET')
        status_code = log_entry.get('status_code', 0)
        parameters = log_entry.get('parameters', '')
        
        prompt = f"""请分析以下Web访问日志，判断是否存在可疑行为或攻击。

日志信息：
- IP地址: {ip_address}
- 请求方法: {method}
- URL: {url}
- 状态码: {status_code}
- 参数: {parameters}

请按照以下JSON格式返回分析结果（只返回JSON，不要其他文字）：
{{
  "risk_score": 0-100的整数，表示风险分数,
  "is_suspicious": true或false,
  "attack_type": "SQL注入/XSS/目录遍历/命令注入/暴力破解/正常访问等",
  "keywords": ["触发风险的关键词列表"],
  "reason": "简短的分析理由（50字以内）"
}}

请仔细分析URL和参数中是否包含攻击特征。"""
        
        return prompt
    
    def _call_ollama(self, prompt, config):
        """调用Ollama本地模型"""
        api_endpoint = config.get('api_endpoint', 'http://localhost:11434')
        model_name = config.get('model_name', 'qwen:7b')
        max_tokens = config.get('max_tokens', 512)
        temperature = config.get('temperature', 0.7)
        
        url = f"{api_endpoint}/api/generate"
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature
            }
        }
        
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        content = result.get('response', '')
        
        return self._parse_llm_response(content)
    
    def _call_openai(self, prompt, config):
        """调用OpenAI API"""
        api_key = config.get('api_key')
        if not api_key:
            raise ValueError("OpenAI API密钥未配置")
        
        model_name = config.get('model_name', 'gpt-3.5-turbo')
        api_endpoint = config.get('api_endpoint', 'https://api.openai.com/v1/chat/completions')
        max_tokens = config.get('max_tokens', 512)
        temperature = config.get('temperature', 0.7)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": "你是一个专业的网络安全分析师，擅长检测Web攻击和可疑行为。"},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        response = requests.post(api_endpoint, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        content = result['choices'][0]['message']['content']
        
        return self._parse_llm_response(content)
    
    def _call_qianfan(self, prompt, config):
        """调用百度文心一言"""
        api_key = config.get('api_key')
        secret_key = config.get('secret_key')
        
        if not api_key or not secret_key:
            raise ValueError("文心一言API密钥未配置")
        
        model_name = config.get('model_name', 'eb-instant')
        max_tokens = config.get('max_tokens', 512)
        temperature = config.get('temperature', 0.7)
        
        # 获取access token
        token_url = "https://aip.baidubce.com/oauth/2.0/token"
        token_params = {
            "grant_type": "client_credentials",
            "client_id": api_key,
            "client_secret": secret_key
        }
        
        token_response = requests.post(token_url, params=token_params, timeout=30)
        token_response.raise_for_status()
        access_token = token_response.json().get('access_token')
        
        # 调用文心一言API
        api_url = f"https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/{model_name}"
        
        headers = {"Content-Type": "application/json"}
        
        payload = {
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_output_tokens": max_tokens,
            "temperature": temperature
        }
        
        response = requests.post(
            f"{api_url}?access_token={access_token}",
            json=payload,
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        
        result = response.json()
        content = result.get('result', '')
        
        return self._parse_llm_response(content)
    
    def _parse_llm_response(self, content):
        """解析LLM响应，提取JSON"""
        try:
            # 尝试直接解析JSON
            content = content.strip()
            
            # 如果包含```json标记，提取其中的内容
            if '```json' in content:
                start = content.find('```json') + 7
                end = content.find('```', start)
                content = content[start:end].strip()
            elif '```' in content:
                start = content.find('```') + 3
                end = content.find('```', start)
                content = content[start:end].strip()
            
            # 解析JSON
            result = json.loads(content)
            
            # 验证必要字段
            required_fields = ['risk_score', 'is_suspicious', 'attack_type', 'keywords', 'reason']
            for field in required_fields:
                if field not in result:
                    result[field] = None if field != 'keywords' else []
            
            # 确保risk_score是数字
            if isinstance(result.get('risk_score'), str):
                try:
                    result['risk_score'] = int(result['risk_score'])
                except:
                    result['risk_score'] = 0
            
            return result
            
        except Exception as e:
            print(f"解析LLM响应失败: {e}")
            print(f"原始内容: {content[:200]}")
            
            # 返回默认结果
            return {
                'risk_score': 0,
                'is_suspicious': False,
                'attack_type': '未知',
                'keywords': [],
                'reason': f'解析失败: {str(e)}'
            }
    
    def compare_models(self, log_entry, model_configs):
        """
        多模型对比分析
        
        Args:
            log_entry: 日志条目
            model_configs: 模型配置列表，每个配置包含name和config
        
        Returns:
            对比结果列表
        """
        results = []
        
        for model_info in model_configs:
            model_name = model_info.get('name', 'Unknown')
            model_config = model_info.get('config', {})
            
            try:
                analysis = self.analyze_log(log_entry, model_config)
                results.append({
                    'model_name': model_name,
                    'success': True,
                    'analysis': analysis,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                results.append({
                    'model_name': model_name,
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results


# 全局实例
multi_model_service = MultiModelLLMService()
