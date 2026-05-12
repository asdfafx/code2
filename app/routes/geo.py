# IP 地理位置分析路由
from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.models import LogEntry, LogImport, AnalysisResult
from app.services.ip_geo import ip_geo_service
from functools import wraps

bp = Blueprint('geo', __name__)

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
def get_ip_location(ip_address):
    """查询单个 IP 的地理位置"""
    try:
        location = ip_geo_service.query_ip_location(ip_address)
        return jsonify({'location': location})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/stats', methods=['GET'])
@login_required
def get_location_stats():
    """获取地理位置统计信息"""
    try:
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 获取地理位置统计
        stats_dict = ip_geo_service.get_ip_stats(entries)
        
        # 将字典转换为数组格式
        location_distribution = []
        for country, data in stats_dict.items():
            location_distribution.append({
                'country': country,
                'ip_count': data['unique_ips'],
                'total_requests': data['count'],
                'attack_count': data['attacks'],
                'attack_rate': data['attack_rate'],
                'cities': data['cities']
            })
        
        # 按请求数排序
        location_distribution.sort(key=lambda x: x['total_requests'], reverse=True)
        
        # 检测异常地区
        anomalies = ip_geo_service.detect_anonymous_regions(entries)
        
        # 计算平均攻击率
        avg_attack_rate = 0
        if location_distribution:
            total_attacks = sum(item['attack_count'] for item in location_distribution)
            total_requests = sum(item['total_requests'] for item in location_distribution)
            avg_attack_rate = (total_attacks / total_requests * 100) if total_requests > 0 else 0
        
        return jsonify({
            'location_distribution': location_distribution,
            'anomalies': anomalies,
            'total_countries': len(location_distribution),
            'total_ips': sum(item['ip_count'] for item in location_distribution),
            'avg_attack_rate': round(avg_attack_rate, 2)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/map-data', methods=['GET'])
@login_required
def get_map_data():
    """获取地图可视化数据"""
    try:
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 收集所有唯一的 IP
        unique_ips = set(entry.ip_address for entry in entries)
        
        # 查询每个 IP 的位置
        map_points = []
        for ip in unique_ips:
            location = ip_geo_service.query_ip_location(ip)
            
            if location['latitude'] and location['longitude']:
                # 统计该 IP 的请求数和攻击数
                ip_entries = [e for e in entries if e.ip_address == ip]
                attack_count = sum(1 for e in ip_entries if e.initial_risk_score > 20)
                
                map_points.append({
                    'ip_address': ip,
                    'country': location['country'],
                    'region': location['region'],
                    'city': location['city'],
                    'latitude': location['latitude'],
                    'longitude': location['longitude'],
                    'requests': len(ip_entries),
                    'attacks': attack_count,
                    'risk_level': '高风险' if attack_count > len(ip_entries) * 0.5 else '中风险' if attack_count > 0 else '正常'
                })
        
        return jsonify({
            'locations': map_points,
            'total_points': len(map_points)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/anomalies', methods=['GET'])
@login_required
def get_anomalies():
    """获取异常地区告警"""
    try:
        threshold = request.args.get('threshold', 30, type=int)
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        # 检测异常
        anomalies = ip_geo_service.detect_anonymous_regions(entries, threshold)
        
        return jsonify({
            'anomalies': anomalies,
            'total_anomalies': len(anomalies),
            'threshold': threshold
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
