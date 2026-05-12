# 机器学习异常检测路由
from flask import Blueprint, request, jsonify, session, current_app
from app import db, csrf
from app.models import LogEntry, LogImport
from app.services.ml_detector import ml_detector
from functools import wraps

bp = Blueprint('ml', __name__)

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


@bp.route('/train', methods=['POST'])
@login_required
def train_model():
    """训练异常检测模型"""
    try:
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        if len(entries) < 10:
            return jsonify({'error': '数据量不足，至少需要 10 条记录'}), 400
        
        # 训练模型
        ml_detector.fit(entries)
        
        return jsonify({
            'message': '模型训练成功',
            'training_samples': len(entries)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/detect', methods=['GET'])
@login_required
def detect_anomalies():
    """检测异常"""
    try:
        import_id = request.args.get('import_id', type=int)
        threshold = request.args.get('threshold', -0.5, type=float)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        if not entries:
            return jsonify({'error': '没有数据'}), 400
        
        # 如果模型未训练，先训练
        if not ml_detector.is_fitted:
            ml_detector.fit(entries)
        
        # 检测异常
        anomalies = ml_detector.get_anomalies(entries, threshold)
        
        return jsonify({
            'anomalies': anomalies,
            'total_anomalies': len(anomalies),
            'total_entries': len(entries),
            'anomaly_rate': round(len(anomalies) / len(entries) * 100, 2)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/compare', methods=['GET'])
@login_required
def compare_detection():
    """对比 ML 和规则检测结果"""
    try:
        from app.services.rule_filter import RuleFilter
        
        import_id = request.args.get('import_id', type=int)
        
        # 构建查询
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        entries = query.all()
        
        current_app.logger.info(f'ML 对比: 找到 {len(entries)} 条日志')
        
        if not entries:
            return jsonify({
                'error': '没有日志数据，请先导入日志',
                'total_entries': 0,
                'ml_detected': 0,
                'rule_detected': 0,
                'both_detected': 0,
                'only_ml_detected': 0,
                'only_rule_detected': 0,
                'ml_rate': 0,
                'rule_rate': 0,
                'agreement_rate': 0,
                'comparison_summary': {
                    'recommendation': '请先导入日志文件后再进行对比分析'
                }
            }), 400
        
        # 检查是否需要重新计算风险评分
        zero_risk_count = sum(1 for e in entries if e.initial_risk_score == 0)
        if zero_risk_count > len(entries) * 0.8:  # 超过 80% 的日志风险评分为 0
            current_app.logger.warning(f'检测到 {zero_risk_count}/{len(entries)} 条日志风险评分为 0，重新计算...')
            rule_filter = RuleFilter()
            
            for entry in entries:
                entry_data = {
                    'ip_address': entry.ip_address,
                    'request_time': entry.request_time,
                    'method': entry.method,
                    'url': entry.url,
                    'parameters': entry.parameters,
                    'status_code': entry.status_code,
                    'response_size': entry.response_size,
                    'user_agent': entry.user_agent,
                    'raw_log': entry.raw_log
                }
                analysis = rule_filter.analyze_entry(entry_data)
                entry.initial_risk_score = analysis['risk_score']
                entry.risk_keywords = ','.join(analysis['matched_keywords'])
            
            db.session.commit()
            current_app.logger.info('风险评分重新计算完成')
        
        # 如果模型未训练，先训练
        if not ml_detector.is_fitted:
            try:
                current_app.logger.info('开始训练 ML 模型...')
                ml_detector.fit(entries)
                current_app.logger.info('ML 模型训练完成')
            except ValueError as e:
                current_app.logger.error(f'ML 模型训练失败: {str(e)}')
                return jsonify({
                    'error': f'数据量不足，需要至少 10 条日志（当前 {len(entries)} 条）',
                    'total_entries': len(entries),
                    'ml_detected': 0,
                    'rule_detected': 0,
                    'both_detected': 0,
                    'only_ml_detected': 0,
                    'only_rule_detected': 0,
                    'ml_rate': 0,
                    'rule_rate': 0,
                    'agreement_rate': 0,
                    'comparison_summary': {
                        'recommendation': f'需要至少 10 条日志才能进行 ML 分析，当前只有 {len(entries)} 条'
                    }
                }), 400
        
        # 对比分析
        comparison = ml_detector.compare_with_rules(entries)
        current_app.logger.info(f'对比结果: ML={comparison["ml_detected"]}, 规则={comparison["rule_detected"]}')
        
        return jsonify(comparison)
        
    except Exception as e:
        current_app.logger.error(f'ML 对比失败: {str(e)}')
        import traceback
        current_app.logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
