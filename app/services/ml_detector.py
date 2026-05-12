# 机器学习异常检测服务
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime


class MLAnomalyDetector:
    """基于机器学习的异常检测器"""
    
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # 假设 10% 是异常
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def extract_features(self, entries):
        """
        从日志条目中提取特征
        
        Args:
            entries: 日志条目列表
            
        Returns:
            np.array: 特征矩阵
            list: 特征名称
        """
        features = []
        feature_names = [
            'risk_score',
            'url_length',
            'param_length',
            'has_special_chars',
            'status_code_abnormal',
            'response_size_abnormal',
            'request_frequency'
        ]
        
        for entry in entries:
            risk_score = entry.initial_risk_score if hasattr(entry, 'initial_risk_score') else entry.get('initial_risk_score', 0)
            url = entry.url if hasattr(entry, 'url') else entry.get('url', '')
            params = entry.parameters if hasattr(entry, 'parameters') else entry.get('parameters', '')
            status_code = entry.status_code if hasattr(entry, 'status_code') else entry.get('status_code', 200)
            response_size = entry.response_size if hasattr(entry, 'response_size') else entry.get('response_size', 0)
            
            # 特征工程
            url_length = len(url) if url else 0
            param_length = len(params) if params else 0
            has_special_chars = sum(1 for c in url + params if c in ["'", '"', '<', '>', ';', '--', '/*'])
            status_code_abnormal = 1 if status_code >= 400 else 0
            response_size_abnormal = 1 if response_size > 10000 or response_size == 0 else 0
            
            features.append([
                risk_score,
                url_length,
                param_length,
                has_special_chars,
                status_code_abnormal,
                response_size_abnormal,
                0  # request_frequency 需要后续计算
            ])
        
        # 计算请求频率（按 IP）
        ip_counts = {}
        for i, entry in enumerate(entries):
            ip = entry.ip_address if hasattr(entry, 'ip_address') else entry.get('ip_address')
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        for i, entry in enumerate(entries):
            ip = entry.ip_address if hasattr(entry, 'ip_address') else entry.get('ip_address')
            features[i][6] = ip_counts.get(ip, 0)
        
        return np.array(features), feature_names
    
    def fit(self, entries):
        """
        训练异常检测模型
        
        Args:
            entries: 日志条目列表（用于训练的数据）
        """
        if len(entries) < 10:
            raise ValueError("训练数据太少，至少需要 10 条记录")
        
        X, _ = self.extract_features(entries)
        
        # 标准化特征
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练模型
        self.model.fit(X_scaled)
        self.is_fitted = True
    
    def predict(self, entries):
        """
        预测异常
        
        Args:
            entries: 日志条目列表
            
        Returns:
            list: 预测结果（-1 表示异常，1 表示正常）
            list: 异常分数
        """
        if not self.is_fitted:
            raise RuntimeError("模型尚未训练，请先调用 fit() 方法")
        
        X, _ = self.extract_features(entries)
        X_scaled = self.scaler.transform(X)
        
        # 预测
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)
        
        return predictions.tolist(), scores.tolist()
    
    def get_anomalies(self, entries, threshold=-0.5):
        """
        获取异常条目
        
        Args:
            entries: 日志条目列表
            threshold: 异常阈值（越小越严格）
            
        Returns:
            list: 异常条目及其分数
        """
        predictions, scores = self.predict(entries)
        
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1 and score < threshold:
                entry = entries[i]
                anomalies.append({
                    'entry_id': entry.entry_id if hasattr(entry, 'entry_id') else entry.get('entry_id'),
                    'ip_address': entry.ip_address if hasattr(entry, 'ip_address') else entry.get('ip_address'),
                    'url': entry.url if hasattr(entry, 'url') else entry.get('url'),
                    'risk_score': entry.initial_risk_score if hasattr(entry, 'initial_risk_score') else entry.get('initial_risk_score', 0),
                    'anomaly_score': float(score),
                    'timestamp': (entry.request_time if hasattr(entry, 'request_time') else entry.get('request_time')).isoformat() if (entry.request_time if hasattr(entry, 'request_time') else entry.get('request_time')) else None
                })
        
        # 按异常分数排序
        anomalies.sort(key=lambda x: x['anomaly_score'])
        
        return anomalies
    
    def compare_with_rules(self, entries):
        """
        对比 ML 检测结果与规则检测结果
        
        Args:
            entries: 日志条目列表
            
        Returns:
            dict: 对比分析结果
        """
        # ML 检测
        ml_anomalies = self.get_anomalies(entries)
        ml_anomaly_ids = set(a['entry_id'] for a in ml_anomalies)
        
        # 规则检测
        rule_anomalies = [
            e for e in entries
            if (e.initial_risk_score if hasattr(e, 'initial_risk_score') else e.get('initial_risk_score', 0)) > 20
        ]
        rule_anomaly_ids = set(
            e.entry_id if hasattr(e, 'entry_id') else e.get('entry_id')
            for e in rule_anomalies
        )
        
        # 计算交集和差集
        both_detected = ml_anomaly_ids & rule_anomaly_ids
        only_ml = ml_anomaly_ids - rule_anomaly_ids
        only_rule = rule_anomaly_ids - ml_anomaly_ids
        
        total = len(entries)
        
        return {
            'total_entries': total,
            'ml_detected': len(ml_anomaly_ids),
            'rule_detected': len(rule_anomaly_ids),
            'both_detected': len(both_detected),
            'only_ml_detected': len(only_ml),
            'only_rule_detected': len(only_rule),
            'ml_rate': round(len(ml_anomaly_ids) / total * 100, 2) if total > 0 else 0,
            'rule_rate': round(len(rule_anomaly_ids) / total * 100, 2) if total > 0 else 0,
            'agreement_rate': round(len(both_detected) / max(len(ml_anomaly_ids | rule_anomaly_ids), 1) * 100, 2),
            'ml_anomalies': ml_anomalies[:20],  # 最多返回 20 个
            'comparison_summary': {
                'precision_improvement': 'ML 可以发现规则无法检测的隐蔽攻击',
                'recall_improvement': '规则可以捕获明显的已知攻击模式',
                'recommendation': '建议结合使用 ML 和规则检测以提高准确率'
            }
        }


# 创建全局实例
ml_detector = MLAnomalyDetector()
