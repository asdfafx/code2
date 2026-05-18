# 实时日志监控服务
import time
import threading
from collections import deque
from datetime import datetime


class RealTimeMonitor:
    """实时日志监控服务"""
    
    def __init__(self):
        self.clients = {}  # 存储连接的客户端
        self.log_buffer = deque(maxlen=1000)  # 日志缓冲区
        self.is_running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        
    def add_client(self, client_id, emit_func=None):
        """添加客户端连接"""
        with self.lock:
            self.clients[client_id] = {
                'emit': emit_func,
                'connected_at': datetime.now(),
                'last_activity': datetime.now()
            }
        print(f"客户端 {client_id} 已连接")
        
    def remove_client(self, client_id):
        """移除客户端连接"""
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"客户端 {client_id} 已断开")
                
    def record_log(self, log_entry):
        """记录日志条目到最近日志缓冲区"""
        with self.lock:
            self.log_buffer.append({
                'timestamp': datetime.now().isoformat(),
                'data': log_entry
            })

    def broadcast_log(self, log_entry):
        """向所有保存了 emit 函数的客户端广播日志条目"""
        self.record_log(log_entry)

        disconnected = []
        with self.lock:
            for client_id, client_info in self.clients.items():
                try:
                    emit_func = client_info.get('emit')
                    if emit_func:
                        emit_func('new_log', log_entry)
                    client_info['last_activity'] = datetime.now()
                except Exception as e:
                    print(f"发送消息到客户端 {client_id} 失败: {e}")
                    disconnected.append(client_id)

        # 清理断开的客户端，避免在同一把锁内重复加锁。
        for client_id in disconnected:
            self.remove_client(client_id)
                
    def get_recent_logs(self, count=50):
        """获取最近的日志"""
        with self.lock:
            return list(self.log_buffer)[-count:]
            
    def start_monitoring(self):
        """开始监控（模拟）"""
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join()
            
    def _monitor_loop(self):
        """监控循环（模拟实时日志流）"""
        while self.is_running:
            # 这里可以集成真实的日志流来源
            # 例如：监听日志文件、接收网络日志等
            time.sleep(1)  # 每秒检查一次
            
    def get_stats(self):
        """获取监控统计信息"""
        with self.lock:
            return {
                'connected_clients': len(self.clients),
                'buffer_size': len(self.log_buffer),
                'is_running': self.is_running or len(self.clients) > 0
            }


# 全局实例
real_time_monitor = RealTimeMonitor()
