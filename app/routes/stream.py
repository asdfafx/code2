# 实时流式分析路由
from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.services.stream_analyzer import stream_analyzer
from app.models import LogEntry, LogImport
from functools import wraps

bp = Blueprint('stream', __name__)

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


@bp.route('/analyze', methods=['POST'])
@login_required
def analyze_stream():
    """实时流式分析单个日志条目"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': '请求体不能为空'}), 400
        
        # 验证必要字段
        required_fields = ['ip_address', 'url']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'缺少必要字段: {", ".join(missing_fields)}'}), 400
        
        # 执行流式分析
        result = stream_analyzer.analyze_stream_entry(data)
        
        if result:
            return jsonify({
                'message': '分析完成',
                'analysis': result
            })
        else:
            return jsonify({'error': '分析失败，请检查日志格式'}), 500
            
    except Exception as e:
        import traceback
        from flask import current_app
        current_app.logger.error(f'流式分析失败: {str(e)}')
        current_app.logger.error(traceback.format_exc())
        return jsonify({'error': f'分析失败: {str(e)}'}), 500


@bp.route('/batch-analyze', methods=['POST'])
@login_required
def batch_analyze_stream():
    """批量流式分析"""
    try:
        data = request.get_json()
        entries = data.get('entries', [])
        
        if not entries:
            return jsonify({'error': '没有提供日志条目'}), 400
        
        results = []
        for entry in entries:
            result = stream_analyzer.analyze_stream_entry(entry)
            if result:
                results.append(result)
        
        return jsonify({
            'message': f'批量分析完成，共{len(results)}条',
            'results': results,
            'total': len(results)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/analyze-import', methods=['POST'])
@login_required
def analyze_import_stream():
    """对指定导入任务的日志进行流式分析"""
    try:
        data = request.get_json()
        import_id = data.get('import_id')
        
        if not import_id:
            return jsonify({'error': '请提供 import_id'}), 400
        
        # 验证 import_id 属于当前用户
        log_import = LogImport.query.filter_by(
            import_id=import_id,
            user_id=session['user_id']
        ).first()
        
        if not log_import:
            return jsonify({'error': '导入任务不存在或无权访问'}), 404
        
        # 重置流式分析器状态
        stream_analyzer.reset_baseline()
        stream_analyzer.clear_buffer()
        
        # 获取该导入任务的所有日志
        log_entries = LogEntry.query.filter_by(import_id=import_id).all()
        
        if not log_entries:
            return jsonify({'error': '该任务没有日志数据'}), 404
        
        # 逐条进行流式分析
        results = []
        attack_types_count = {}
        
        for idx, entry in enumerate(log_entries):
            log_data = {
                'entry_id': entry.entry_id,
                'ip_address': entry.ip_address or '',
                'url': entry.url or '',
                'method': entry.method or 'GET',
                'parameters': entry.parameters or '',
                'status_code': entry.status_code or 0,
                'user_agent': entry.user_agent or '',
                'raw_log': entry.raw_log or ''
            }
            
            result = stream_analyzer.analyze_stream_entry(log_data)
            if result:
                results.append(result)
                # 统计攻击类型
                attack_type = result.get('attack_type', '未知')
                attack_types_count[attack_type] = attack_types_count.get(attack_type, 0) + 1
        
        return jsonify({
            'message': f'流式分析完成，共分析 {len(results)} 条日志',
            'total': len(results),
            'import_id': import_id,
            'filename': log_import.filename,
            'attack_types': attack_types_count
        })
        
    except Exception as e:
        import traceback
        from flask import current_app
        current_app.logger.error(f'导入任务流式分析失败: {str(e)}')
        current_app.logger.error(traceback.format_exc())
        return jsonify({'error': f'分析失败: {str(e)}'}), 500


@bp.route('/recent', methods=['GET'])
@login_required
def get_recent_analyses():
    """获取最近的流式分析结果"""
    try:
        count = request.args.get('count', 50, type=int)
        analyses = stream_analyzer.get_recent_analyses(count)
        
        return jsonify({
            'analyses': analyses,
            'total': len(analyses)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/statistics', methods=['GET'])
@login_required
def get_stream_statistics():
    """获取流式分析统计信息"""
    try:
        stats = stream_analyzer.get_statistics()
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/thresholds', methods=['GET'])
@login_required
def get_thresholds():
    """获取当前阈值配置"""
    try:
        return jsonify({
            'thresholds': stream_analyzer.risk_thresholds,
            'dynamic_enabled': stream_analyzer.dynamic_threshold_enabled
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/thresholds', methods=['PUT'])
@login_required
def update_thresholds():
    """更新风险阈值"""
    try:
        data = request.get_json()
        
        low = data.get('low')
        medium = data.get('medium')
        high = data.get('high')
        
        # 验证阈值合理性
        if low is not None and (low < 0 or low > 100):
            return jsonify({'error': '低风险阈值必须在0-100之间'}), 400
        if medium is not None and (medium < 0 or medium > 100):
            return jsonify({'error': '中风险阈值必须在0-100之间'}), 400
        if high is not None and (high < 0 or high > 100):
            return jsonify({'error': '高风险阈值必须在0-100之间'}), 400
        
        if low is not None and medium is not None and low >= medium:
            return jsonify({'error': '低风险阈值必须小于中风险阈值'}), 400
        if medium is not None and high is not None and medium >= high:
            return jsonify({'error': '中风险阈值必须小于高风险阈值'}), 400
        
        stream_analyzer.update_thresholds(low=low, medium=medium, high=high)
        
        return jsonify({
            'message': '阈值已更新',
            'thresholds': stream_analyzer.risk_thresholds
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/dynamic-threshold', methods=['POST'])
@login_required
def toggle_dynamic_threshold():
    """切换动态阈值功能"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        stream_analyzer.enable_dynamic_threshold(enabled)
        
        return jsonify({
            'message': f'动态阈值已{"启用" if enabled else "禁用"}',
            'dynamic_enabled': stream_analyzer.dynamic_threshold_enabled
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/reset-baseline', methods=['POST'])
@login_required
def reset_baseline():
    """重置基线数据和缓冲区"""
    try:
        stream_analyzer.reset_baseline()
        stream_analyzer.clear_buffer()  # 清空缓冲区
        
        return jsonify({'message': '基线数据和缓冲区已重置'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/anomalies', methods=['GET'])
@login_required
def get_anomalies():
    """获取检测到的异常"""
    try:
        count = request.args.get('count', 20, type=int)
        analyses = stream_analyzer.get_recent_analyses(count * 2)  # 获取更多以便筛选
        
        # 筛选出异常
        anomalies = [a for a in analyses if a.get('is_anomaly')]
        
        # 返回最近的count个异常
        recent_anomalies = anomalies[-count:] if len(anomalies) > count else anomalies
        
        return jsonify({
            'anomalies': recent_anomalies,
            'total_anomalies': len(anomalies),
            'total_analyzed': len(analyses)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
