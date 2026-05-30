# WebSocket 实时日志监控路由
"""Socket.IO 实时日志推送事件处理。"""
from flask import Blueprint, request, session
from flask_socketio import emit
from app import socketio
from app.services.realtime_monitor import real_time_monitor
from functools import wraps

bp = Blueprint('websocket', __name__)


def login_required_ws(f):
    """WebSocket 事件登录校验，未登录时直接向客户端发送 error 事件。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            emit('error', {'message': '请先登录'})
            return
        return f(*args, **kwargs)
    return decorated_function


@socketio.on('connect')
def handle_connect():
    """处理客户端连接，并回放最近日志。"""
    if 'user_id' not in session:
        return False
    
    client_id = request.sid
    real_time_monitor.add_client(client_id)
    
    # 发送最近的日志给新连接的客户端，使刷新页面后仍能看到近期动态。
    recent_logs = real_time_monitor.get_recent_logs(20)
    for log_entry in recent_logs:
        emit('new_log', log_entry['data'])
    
    emit('connected', {'client_id': client_id, 'message': '已连接到实时监控系统'})
    return True


@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开，释放连接记录。"""
    real_time_monitor.remove_client(request.sid)


@socketio.on('subscribe_logs')
@login_required_ws
def handle_subscribe_logs(data):
    """订阅日志流，当前实现只返回确认消息。"""
    emit('subscribed', {'message': '已订阅日志流'})


@socketio.on('unsubscribe_logs')
@login_required_ws
def handle_unsubscribe_logs():
    """取消订阅日志流"""
    emit('unsubscribed', {'message': '已取消订阅日志流'})


@socketio.on('get_stats')
@login_required_ws
def handle_get_stats():
    """向当前客户端推送实时监控统计信息。"""
    stats = real_time_monitor.get_stats()
    emit('stats_update', stats)


# 用于从其他地方触发日志广播的函数，例如日志上传完成后推送新条目。
def broadcast_new_log(log_data):
    """广播新的日志条目"""
    real_time_monitor.record_log(log_data)
    socketio.emit('new_log', log_data)
