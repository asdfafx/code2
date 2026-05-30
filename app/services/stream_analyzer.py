# 实时流式分析服务
"""实时流式日志分析引擎。

它在规则初筛基础上维护最近分析结果和风险基线，用于动态阈值、异常识别和实时看板。
"""
import threading
from collections import deque
from datetime import datetime
from app.services.rule_filter import RuleFilter


class StreamAnalyzer:
    """对单条或连续日志流执行轻量级实时风险分析。"""
    
    def __init__(self):
        self.rule_filter = RuleFilter()
        self.analysis_buffer = deque(maxlen=1000)  # 分析结果缓冲区
        self.risk_thresholds = {
            'low': 20,
            'medium': 40,
            'high': 60
        }
        self.dynamic_threshold_enabled = True
        self.baseline_risk_scores = []  # 基线风险分数
        self.lock = threading.Lock()
        
    def analyze_stream_entry(self, log_entry):
        """分析单个流式日志条目，并更新缓冲区和风险基线。"""
        try:
            # 1. 规则初筛
            analysis = self.rule_filter.analyze_entry(log_entry)
            risk_score = analysis['risk_score']
            keywords = analysis['matched_keywords']
            
            # 2. 动态阈值调整：结合近期基线避免静态阈值过于死板。
            adjusted_risk_score = self._adjust_risk_score(risk_score)
            
            # 3. 确定风险等级
            risk_level = self._determine_risk_level(adjusted_risk_score)
            
            # 4. 判断攻击类型：优先使用规则分类，缺失时再做轻量文本判断。
            attack_type = ', '.join(analysis['attack_types']) if analysis['attack_types'] else self._detect_attack_type(keywords, log_entry)
            
            # 5. 构建分析结果
            analysis_result = {
                'entry_id': log_entry.get('entry_id'),
                'ip_address': log_entry.get('ip_address'),
                'url': log_entry.get('url'),
                'method': log_entry.get('method'),
                'timestamp': datetime.now().isoformat(),
                'original_risk_score': risk_score,
                'adjusted_risk_score': adjusted_risk_score,
                'risk_level': risk_level,
                'attack_type': attack_type,
                'keywords': keywords,
                'is_anomaly': self._is_anomaly(adjusted_risk_score)
            }
            
            # 6. 添加到缓冲区
            with self.lock:
                self.analysis_buffer.append(analysis_result)
                
                # 更新基线数据（用于动态阈值）
                if len(self.baseline_risk_scores) < 100:
                    self.baseline_risk_scores.append(risk_score)
            
            return analysis_result
            
        except Exception as e:
            import traceback
            print(f"流式分析失败: {e}")
            print(traceback.format_exc())
            return None
    
    def _adjust_risk_score(self, original_score):
        """根据近期基线用 Z-score 动态调整风险分数。"""
        if not self.dynamic_threshold_enabled or len(self.baseline_risk_scores) < 10:
            return original_score
        
        # 计算基线统计信息
        mean_score = sum(self.baseline_risk_scores) / len(self.baseline_risk_scores)
        std_dev = (sum((x - mean_score) ** 2 for x in self.baseline_risk_scores) / len(self.baseline_risk_scores)) ** 0.5
        
        # 如果标准差为0，返回原始分数
        if std_dev == 0:
            return original_score
        
        # 计算Z-score
        z_score = (original_score - mean_score) / std_dev
        
        # 根据Z-score调整分数
        if z_score > 2:  # 异常高
            adjusted_score = min(original_score * 1.2, 100)
        elif z_score > 1:  # 偏高
            adjusted_score = original_score * 1.1
        elif z_score < -1:  # 偏低
            adjusted_score = original_score * 0.9
        else:  # 正常范围
            adjusted_score = original_score
        
        return round(adjusted_score, 2)
    
    def _determine_risk_level(self, risk_score):
        """根据动态阈值确定风险等级"""
        if risk_score >= self.risk_thresholds['high']:
            return 'critical'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'high'
        elif risk_score >= self.risk_thresholds['low']:
            return 'medium'
        else:
            return 'low'
    
    def _detect_attack_type(self, keywords, log_entry):
        """在规则未给出攻击类型时，从 URL/参数/原始日志中做兜底判断。"""
        if not keywords:
            return None
        
        url = log_entry.get('url', '').lower()
        parameters = log_entry.get('parameters', '').lower()
        raw_log = log_entry.get('raw_log', '').lower()
        combined = f"{url} {parameters} {raw_log}"
        
        # SQL注入检测（优先级最高）
        sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', '--', ';', 'or 1=1', "' or '"]
        if any(kw in combined for kw in sql_keywords):
            return 'SQL注入'
        
        # XSS检测
        xss_keywords = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie', '<img', '<svg']
        if any(kw in combined for kw in xss_keywords):
            return 'XSS'
        
        # 命令注入检测
        command_keywords = ['; cat ', '| whoami', '`id`', '$(cat', '&& net', '|| ls', '; rm ']
        if any(kw in combined for kw in command_keywords):
            return '命令注入'
        
        # 目录遍历检测（需要多个 ../ 或访问敏感文件，降低普通路径误报）。
        traversal_count = url.count('../') + url.count('..\\')
        sensitive_files = ['/etc/passwd', '/etc/shadow', '/windows/system32', 'boot.ini', 'web.config']
        
        if traversal_count >= 2 or (traversal_count >= 1 and any(f in url for f in sensitive_files)):
            return '目录遍历'
        
        return '可疑行为'
    
    def _is_anomaly(self, risk_score):
        """判断风险分是否显著偏离近期基线。"""
        if len(self.baseline_risk_scores) < 10:
            return risk_score > self.risk_thresholds['high']
        
        mean_score = sum(self.baseline_risk_scores) / len(self.baseline_risk_scores)
        std_dev = (sum((x - mean_score) ** 2 for x in self.baseline_risk_scores) / len(self.baseline_risk_scores)) ** 0.5
        
        if std_dev == 0:
            return risk_score > self.risk_thresholds['high']
        
        z_score = (risk_score - mean_score) / std_dev
        return z_score > 2  # 超过2个标准差视为异常
    
    def update_thresholds(self, low=None, medium=None, high=None):
        """手动更新阈值"""
        if low is not None:
            self.risk_thresholds['low'] = low
        if medium is not None:
            self.risk_thresholds['medium'] = medium
        if high is not None:
            self.risk_thresholds['high'] = high
    
    def enable_dynamic_threshold(self, enabled=True):
        """启用/禁用动态阈值"""
        self.dynamic_threshold_enabled = enabled
    
    def get_recent_analyses(self, count=50):
        """获取最近的分析结果"""
        with self.lock:
            return list(self.analysis_buffer)[-count:]
    
    def get_statistics(self):
        """汇总缓冲区中的风险分布、攻击类型和异常比例。"""
        with self.lock:
            if not self.analysis_buffer:
                return {
                    'total_analyzed': 0,
                    'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                    'attack_types': {},
                    'anomaly_count': 0,
                    'avg_risk_score': 0
                }
            
            total = len(self.analysis_buffer)
            risk_dist = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            attack_types = {}
            anomaly_count = 0
            total_risk = 0
            
            for analysis in self.analysis_buffer:
                risk_level = analysis.get('risk_level', 'low')
                risk_dist[risk_level] = risk_dist.get(risk_level, 0) + 1
                
                attack_type = analysis.get('attack_type')
                if attack_type:
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                if analysis.get('is_anomaly'):
                    anomaly_count += 1
                
                total_risk += analysis.get('adjusted_risk_score', 0)
            
            return {
                'total_analyzed': total,
                'risk_distribution': risk_dist,
                'attack_types': attack_types,
                'anomaly_count': anomaly_count,
                'anomaly_rate': round(anomaly_count / total * 100, 2) if total > 0 else 0,
                'avg_risk_score': round(total_risk / total, 2) if total > 0 else 0,
                'dynamic_threshold_enabled': self.dynamic_threshold_enabled,
                'current_thresholds': self.risk_thresholds.copy()
            }
    
    def reset_baseline(self):
        """重置基线数据"""
        with self.lock:
            self.baseline_risk_scores.clear()
    
    def clear_buffer(self):
        """清空分析结果缓冲区"""
        with self.lock:
            self.analysis_buffer.clear()


# 全局实例，路由层直接复用同一份实时缓冲区。
stream_analyzer = StreamAnalyzer()
