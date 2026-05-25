# 攻击行为时间线服务
from datetime import datetime
from collections import defaultdict


class AttackTimelineService:
    """攻击行为时间线分析服务"""
    
    def __init__(self):
        pass
    
    def get_ip_timeline(self, ip_address, entries, time_window=3600):
        """
        获取单个 IP 的攻击行为时间线
        
        Args:
            ip_address: IP 地址
            entries: 日志条目列表
            time_window: 时间窗口（秒），默认 1 小时
            
        Returns:
            dict: 时间线数据
        """
        # 过滤该 IP 的所有条目
        ip_entries = [e for e in entries if e.ip_address == ip_address]
        
        if not ip_entries:
            return None
        
        # 按时间排序
        ip_entries.sort(key=lambda x: x.request_time if hasattr(x, 'request_time') else x.get('request_time'))
        
        # 构建时间线
        timeline = []
        attack_sequences = []
        current_sequence = []
        
        for entry in ip_entries:
            request_time = entry.request_time if hasattr(entry, 'request_time') else entry.get('request_time')
            risk_score = entry.initial_risk_score if hasattr(entry, 'initial_risk_score') else entry.get('initial_risk_score', 0)
            
            event = {
                'timestamp': request_time.isoformat() if request_time else None,
                'method': entry.method if hasattr(entry, 'method') else entry.get('method'),
                'url': entry.url if hasattr(entry, 'url') else entry.get('url'),
                'status_code': entry.status_code if hasattr(entry, 'status_code') else entry.get('status_code'),
                'risk_score': risk_score,
                'is_attack': risk_score > 20
            }
            
            timeline.append(event)
            
            # 检测攻击序列
            if event['is_attack']:
                current_sequence.append(event)
            else:
                if current_sequence:
                    attack_sequences.append(current_sequence)
                    current_sequence = []
        
        if current_sequence:
            attack_sequences.append(current_sequence)
        
        # 统计信息
        total_requests = len(ip_entries)
        attack_count = sum(1 for e in timeline if e['is_attack'])
        attack_rate = round(attack_count / total_requests * 100, 2) if total_requests > 0 else 0
        
        # 时间跨度
        if timeline:
            first_time = timeline[0]['timestamp']
            last_time = timeline[-1]['timestamp']
            if first_time and last_time:
                duration = (datetime.fromisoformat(last_time) - datetime.fromisoformat(first_time)).total_seconds()
            else:
                duration = 0
        else:
            duration = 0
            first_time = None
            last_time = None
        
        return {
            'ip_address': ip_address,
            'timeline': timeline,
            'attack_sequences': attack_sequences,
            'statistics': {
                'total_requests': total_requests,
                'attack_count': attack_count,
                'attack_rate': attack_rate,
                'duration_seconds': duration,
                'first_seen': first_time,
                'last_seen': last_time,
                'sequence_count': len(attack_sequences)
            }
        }
    
    def get_attack_chain(self, entries, time_threshold=300):
        """
        检测攻击链路（多个 IP 的协同攻击）
        
        Args:
            entries: 日志条目列表
            time_threshold: 时间阈值（秒），默认 5 分钟
            
        Returns:
            list: 攻击链路列表
        """
        # 只关注高风险请求
        attacks = [e for e in entries if (e.initial_risk_score if hasattr(e, 'initial_risk_score') else e.get('initial_risk_score', 0)) > 40]
        
        if not attacks:
            return []
        
        # 按时间排序
        attacks.sort(key=lambda x: x.request_time if hasattr(x, 'request_time') else x.get('request_time'))
        
        # 检测攻击链路
        chains = []
        current_chain = [attacks[0]]
        
        for i in range(1, len(attacks)):
            prev_time = attacks[i-1].request_time if hasattr(attacks[i-1], 'request_time') else attacks[i-1].get('request_time')
            curr_time = attacks[i].request_time if hasattr(attacks[i], 'request_time') else attacks[i].get('request_time')
            
            if prev_time and curr_time:
                time_diff = (curr_time - prev_time).total_seconds()
                
                if time_diff <= time_threshold:
                    current_chain.append(attacks[i])
                else:
                    if len(current_chain) >= 3:  # 至少 3 个攻击才算链路
                        chains.append(self._analyze_chain(current_chain))
                    current_chain = [attacks[i]]
            else:
                current_chain.append(attacks[i])
        
        if len(current_chain) >= 3:
            chains.append(self._analyze_chain(current_chain))
        
        return chains
    
    def _analyze_chain(self, chain):
        """分析单个攻击链路"""
        unique_ips = set(e.ip_address if hasattr(e, 'ip_address') else e.get('ip_address') for e in chain)
        attack_types = set()
        
        for e in chain:
            if hasattr(e, 'analysis_result') and e.analysis_result:
                attack_types.add(e.analysis_result.attack_type)
        
        start_time = chain[0].request_time if hasattr(chain[0], 'request_time') else chain[0].get('request_time')
        end_time = chain[-1].request_time if hasattr(chain[-1], 'request_time') else chain[-1].get('request_time')
        
        duration = (end_time - start_time).total_seconds() if start_time and end_time else 0
        
        return {
            'chain_length': len(chain),
            'unique_ips': list(unique_ips),
            'ip_count': len(unique_ips),
            'attack_types': list(attack_types),
            'start_time': start_time.isoformat() if start_time else None,
            'end_time': end_time.isoformat() if end_time else None,
            'duration_seconds': duration,
            'severity': 'critical' if len(unique_ips) > 3 else 'high' if len(unique_ips) > 1 else 'medium',
            'events': [{
                'ip': e.ip_address if hasattr(e, 'ip_address') else e.get('ip_address'),
                'time': (e.request_time if hasattr(e, 'request_time') else e.get('request_time')).isoformat(),
                'url': e.url if hasattr(e, 'url') else e.get('url'),
                'risk_score': e.initial_risk_score if hasattr(e, 'initial_risk_score') else e.get('initial_risk_score')
            } for e in chain[:20]]  # 最多 20 个事件
        }
    
    def get_behavior_patterns(self, entries):
        """
        识别行为模式
        
        Args:
            entries: 日志条目列表
            
        Returns:
            dict: 行为模式分析结果
        """
        # 按 IP 分组
        ip_groups = defaultdict(list)
        for entry in entries:
            ip = entry.ip_address if hasattr(entry, 'ip_address') else entry.get('ip_address')
            ip_groups[ip].append(entry)
        
        patterns = {
            'brute_force': [],  # 暴力破解
            'scanning': [],     # 扫描行为
            'distributed': [],  # 分布式攻击
            'persistent': []    # 持续攻击
        }
        
        for ip, ip_entries in ip_groups.items():
            stats = self._analyze_ip_pattern(ip, ip_entries)
            
            if stats['is_brute_force']:
                patterns['brute_force'].append(stats)
            if stats['is_scanning']:
                patterns['scanning'].append(stats)
            if stats['is_persistent']:
                patterns['persistent'].append(stats)
        
        # 检测分布式攻击（多个 IP 攻击同一目标）
        patterns['distributed'] = self._detect_distributed_attack(entries)
        
        return patterns
    
    def _analyze_ip_pattern(self, ip, entries):
        """分析单个 IP 的行为模式"""
        total = len(entries)
        attacks = [e for e in entries if (e.initial_risk_score if hasattr(e, 'initial_risk_score') else e.get('initial_risk_score', 0)) > 20]
        attack_count = len(attacks)
        attack_rate = attack_count / total if total > 0 else 0
        
        # 检测暴力破解（大量登录失败）
        login_attempts = [e for e in entries if 'login' in (e.url if hasattr(e, 'url') else e.get('url', '')).lower()]
        is_brute_force = len(login_attempts) > 10 and attack_rate > 0.5
        
        # 检测扫描行为（访问多个不同 URL）
        unique_urls = set(e.url if hasattr(e, 'url') else e.get('url') for e in entries)
        is_scanning = len(unique_urls) > 20 and total > 30
        
        # 检测持续攻击（长时间持续）
        if entries:
            times = [e.request_time for e in entries if hasattr(e, 'request_time') and e.request_time]
            if len(times) >= 2:
                duration = (max(times) - min(times)).total_seconds()
                is_persistent = duration > 3600 and attack_count > 10  # 持续 1 小时以上且攻击超过 10 次
            else:
                is_persistent = False
        else:
            is_persistent = False
        
        return {
            'ip': ip,
            'total_requests': total,
            'attack_count': attack_count,
            'attack_rate': round(attack_rate * 100, 2),
            'unique_urls': len(unique_urls),
            'is_brute_force': is_brute_force,
            'is_scanning': is_scanning,
            'is_persistent': is_persistent
        }
    
    def _detect_distributed_attack(self, entries, threshold=5):
        """检测分布式攻击"""
        # 按时间窗口分组（5 分钟）
        time_windows = defaultdict(list)
        
        for entry in entries:
            if (entry.initial_risk_score if hasattr(entry, 'initial_risk_score') else entry.get('initial_risk_score', 0)) > 40:
                request_time = entry.request_time if hasattr(entry, 'request_time') else entry.get('request_time')
                if request_time:
                    # 按 5 分钟分组
                    window_key = request_time.replace(second=0, microsecond=0)
                    window_key = window_key.replace(minute=(window_key.minute // 5) * 5)
                    time_windows[window_key].append(entry)
        
        distributed_attacks = []
        
        for window_time, window_entries in time_windows.items():
            unique_ips = set(e.ip_address if hasattr(e, 'ip_address') else e.get('ip_address') for e in window_entries)
            
            if len(unique_ips) >= threshold:
                distributed_attacks.append({
                    'time_window': window_time.isoformat(),
                    'unique_ips': len(unique_ips),
                    'ip_list': list(unique_ips)[:10],
                    'total_attacks': len(window_entries),
                    'severity': 'critical' if len(unique_ips) > 10 else 'high'
                })
        
        return distributed_attacks


# 创建全局实例
timeline_service = AttackTimelineService()
