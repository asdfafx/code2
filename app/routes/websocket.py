# WebSocket 实时日志监控路由
from flask import Blueprint, request, session, jsonify
from flask_socketio import emit, join_room, leave_room
from app import socketio
from app.services.realtime_monitor import real_time_monitor
from functools import wraps
import uuid

bp = Blueprint('websocket', __name__)


def login_required_ws(f):
    """WebSocket 登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            emit('error', {'message': '请先登录'})
            return
        return f(*args, **kwargs)
    return decorated_function


@socketio.on('connect')
def handle_connect():
    """处理客户端连接"""
    if 'user_id' not in session:
        return False
    
    client_id = str(uuid.uuid4())
    real_time_monitor.add_client(client_id, emit)
    
    # 发送最近的日志给新连接的客户端
    recent_logs = real_time_monitor.get_recent_logs(20)
    for log_entry in recent_logs:
        emit('new_log', log_entry['data'])
    
    emit('connected', {'client_id': client_id, 'message': '已连接到实时监控系统'})
    return True


@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开"""
    # 在实际应用中，需要从请求中获取client_id
    # 这里简化处理
    pass


@socketio.on('subscribe_logs')
@login_required_ws
def handle_subscribe_logs(data):
    """订阅日志流"""
    emit('subscribed', {'message': '已订阅日志流'})


@socketio.on('unsubscribe_logs')
@login_required_ws
def handle_unsubscribe_logs():
    """取消订阅日志流"""
    emit('unsubscribed', {'message': '已取消订阅日志流'})


@socketio.on('get_stats')
@login_required_ws
def handle_get_stats():
    """获取监控统计信息"""
    stats = real_time_monitor.get_stats()
    emit('stats_update', stats)


# 用于从其他地方触发日志广播的函数
def broadcast_new_log(log_data):
    """广播新的日志条目"""
    real_time_monitor.broadcast_log(log_data)