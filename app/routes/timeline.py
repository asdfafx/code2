# 攻击行为时间线路由
"""攻击行为时间线、攻击链和攻击者排行接口。"""
from flask import Blueprint, request, jsonify, session
from app import csrf
from app.models import LogEntry, LogImport
from app.services.timeline import timeline_service
from functools import wraps

bp = Blueprint('timeline', __name__)

# 为 API 蓝图禁用 CSRF 保护
csrf.exempt(bp)


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/ip/<ip_address>', methods=['GET'])
@login_required
def get_ip_timeline(ip_address):
    """获取单个 IP 在当前用户日志中的行为时间线。"""
    try:
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询，默认跨所有导入批次，也可用 import_id 限定范围。
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            LogEntry.ip_address == ip_address
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        if not entries:
            return jsonify({'error': '未找到该 IP 的记录'}), 404
        
        # 获取时间线
        timeline_data = timeline_service.get_ip_timeline(ip_address, entries)
        
        return jsonify({'timeline': timeline_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/chains', methods=['GET'])
@login_required
def get_attack_chains():
    """检测当前用户日志中的连续高风险攻击链路。"""
    try:
        import_id = request.args.get('import_id', type=int)
        time_threshold = request.args.get('time_threshold', 300, type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 检测攻击链路
        chains = timeline_service.get_attack_chain(entries, time_threshold)
        
        return jsonify({
            'chains': chains,
            'total_chains': len(chains)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/patterns', methods=['GET'])
@login_required
def get_behavior_patterns():
    """获取暴力破解、扫描、分布式攻击和持续攻击等模式。"""
    try:
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 分析行为模式
        patterns = timeline_service.get_behavior_patterns(entries)
        
        return jsonify({
            'patterns': patterns,
            'summary': {
                'brute_force_count': len(patterns['brute_force']),
                'scanning_count': len(patterns['scanning']),
                'distributed_count': len(patterns['distributed']),
                'persistent_count': len(patterns['persistent'])
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/top-attackers', methods=['GET'])
@login_required
def get_top_attackers():
    """按攻击次数统计排名靠前的来源 IP。"""
    try:
        import_id = request.args.get('import_id', type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # 构建查询 - 查询所有条目
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 按 IP 聚合请求数、攻击数、风险分和首次/最后出现时间。
        ip_stats = {}
        for entry in entries:
            ip = entry.ip_address
            if ip not in ip_stats:
                ip_stats[ip] = {
                    'ip_address': ip,
                    'total_requests': 0,
                    'attack_count': 0,
                    'first_seen': None,
                    'last_seen': None,
                    'risk_scores': []
                }
            
            ip_stats[ip]['total_requests'] += 1
            
            # 统计攻击次数
            if entry.initial_risk_score > 20:
                ip_stats[ip]['attack_count'] += 1
                ip_stats[ip]['risk_scores'].append(entry.initial_risk_score)
            
            # 记录时间范围
            if hasattr(entry, 'request_time') and entry.request_time:
                if ip_stats[ip]['first_seen'] is None or entry.request_time < ip_stats[ip]['first_seen']:
                    ip_stats[ip]['first_seen'] = entry.request_time
                if ip_stats[ip]['last_seen'] is None or entry.request_time > ip_stats[ip]['last_seen']:
                    ip_stats[ip]['last_seen'] = entry.request_time
        
        # 计算攻击率、平均风险和活跃持续时间。
        attackers = []
        for ip, stats in ip_stats.items():
            attack_rate = (stats['attack_count'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
            avg_risk = round(sum(stats['risk_scores']) / len(stats['risk_scores']), 2) if stats['risk_scores'] else 0
            
            # 计算持续时间（秒）
            duration_seconds = 0
            if stats['first_seen'] and stats['last_seen']:
                try:
                    from datetime import datetime
                    if isinstance(stats['first_seen'], str):
                        first = datetime.fromisoformat(stats['first_seen'])
                    else:
                        first = stats['first_seen']
                    
                    if isinstance(stats['last_seen'], str):
                        last = datetime.fromisoformat(stats['last_seen'])
                    else:
                        last = stats['last_seen']
                    
                    duration_seconds = int((last - first).total_seconds())
                except:
                    pass
            
            attackers.append({
                'ip_address': ip,
                'total_requests': stats['total_requests'],
                'attack_count': stats['attack_count'],
                'attack_rate': round(attack_rate, 2),
                'avg_risk_score': avg_risk,
                'duration_seconds': duration_seconds,
                'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
                'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None
            })
        
        # 按攻击次数排序
        attackers.sort(key=lambda x: x['attack_count'], reverse=True)
        top_attackers = attackers[:limit]
        
        return jsonify({
            'attackers': top_attackers,
            'total_unique_attackers': len(attackers)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
