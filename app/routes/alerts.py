# 告警通知路由
"""告警配置、告警测试和告警历史接口。"""
from flask import Blueprint, request, jsonify, session
from app import csrf
from app.models import LogEntry, LogImport
from app.services.alert_service import alert_service
from functools import wraps

bp = Blueprint('alerts', __name__)

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


def admin_required(f):
    """管理员权限验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        
        # 检查用户是否为管理员
        from app.models import User
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': '需要管理员权限'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/config', methods=['GET'])
@admin_required
def get_alert_config():
    """获取告警配置。

    当前返回默认配置；如果后续需要持久化，可在这里改为读取数据库。
    """
    try:
        # 从配置文件或数据库中获取告警配置
        # 这里简化处理，返回默认配置
        config = {
            'email_enabled': False,
            'email_recipients': [],
            'sms_enabled': False,
            'phone_numbers': [],
            'webhook_enabled': False,
            'webhook_url': '',
            'high_risk_threshold': 70,  # 高风险阈值
            'medium_risk_threshold': 40  # 中风险阈值
        }
        
        return jsonify({'config': config})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/config', methods=['PUT'])
@admin_required
def update_alert_config():
    """更新告警配置。

    当前仅校验并回显请求配置，后续可接入数据库或配置文件保存。
    """
    try:
        data = request.get_json()
        
        # 验证和保存配置
        # 在实际应用中，应该将配置保存到数据库
        config = {
            'email_enabled': data.get('email_enabled', False),
            'email_recipients': data.get('email_recipients', []),
            'sms_enabled': data.get('sms_enabled', False),
            'phone_numbers': data.get('phone_numbers', []),
            'webhook_enabled': data.get('webhook_enabled', False),
            'webhook_url': data.get('webhook_url', ''),
            'high_risk_threshold': data.get('high_risk_threshold', 70),
            'medium_risk_threshold': data.get('medium_risk_threshold', 40)
        }
        
        # 这里应该将配置保存到数据库或配置文件
        # 为了简化，我们只返回成功响应
        
        return jsonify({'message': '告警配置已更新', 'config': config})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/test-email', methods=['POST'])
@admin_required
def test_email_alert():
    """发送一封测试邮件，验证邮件通道配置是否可用。"""
    try:
        data = request.get_json()
        recipients = data.get('recipients', [])
        
        if not recipients:
            return jsonify({'error': '请提供收件人邮箱地址'}), 400
        
        subject = "测试告警 - 日志分析系统"
        message = "<p>这是一封测试邮件，用于验证邮件告警功能是否正常工作。</p>"
        
        success = alert_service.send_email_alert(subject, message, recipients)
        
        if success:
            return jsonify({'message': '测试邮件已发送'})
        else:
            return jsonify({'error': '邮件发送失败'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/test-sms', methods=['POST'])
@admin_required
def test_sms_alert():
    """发送一条测试短信，验证短信通道配置是否可用。"""
    try:
        data = request.get_json()
        phone_numbers = data.get('phone_numbers', [])
        
        if not phone_numbers:
            return jsonify({'error': '请提供手机号码'}), 400
        
        message = "【日志分析系统】这是一条测试短信，用于验证短信告警功能是否正常工作。"
        
        success = alert_service.send_sms_alert(message, phone_numbers)
        
        if success:
            return jsonify({'message': '测试短信已发送'})
        else:
            return jsonify({'error': '短信发送失败'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/history', methods=['GET'])
@login_required
def get_alert_history():
    """基于当前用户高风险日志生成告警历史列表。"""
    try:
        limit = request.args.get('limit', 20, type=int)
        entries = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            LogEntry.initial_risk_score >= 40
        ).order_by(LogEntry.request_time.desc(), LogEntry.created_at.desc()).limit(limit).all()

        # 这里没有独立告警表，直接从风险分较高的日志条目派生告警记录。
        alerts = []
        for entry in entries:
            risk_score = entry.initial_risk_score or 0
            alert_type = 'critical_risk' if risk_score >= 70 else 'high_risk'
            timestamp = entry.request_time or entry.created_at
            alerts.append({
                'id': entry.entry_id,
                'type': alert_type,
                'message': f'检测到高风险请求，风险分 {risk_score}',
                'ip_address': entry.ip_address,
                'url': entry.url,
                'risk_score': risk_score,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else None,
                'status': 'active'
            })
        
        return jsonify({'alerts': alerts, 'total': len(alerts)})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
