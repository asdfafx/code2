# 安全中间件 - 限流和登录保护
"""简单的内存级安全控制。

当前实现适合单进程开发/演示环境：登录失败记录和限流计数都存在内存中。
如果部署到多进程或多机器环境，应迁移到 Redis 等共享存储。
"""
import time
from functools import wraps
from flask import request, jsonify, session
from app.models import User


class SecurityMiddleware:
    """提供登录态校验、登录失败锁定和接口限流能力。"""
    
    def __init__(self):
        # 登录尝试记录 {ip: [(timestamp, success), ...]}
        self.login_attempts = {}
        # IP 访问记录 {ip: {endpoint: [timestamps]}}
        self.rate_limits = {}
        
        # 配置
        self.max_login_attempts = 5  # 最大登录尝试次数
        self.lockout_time = 300  # 锁定时间（秒）
        self.rate_limit_window = 60  # 限流窗口（秒）
        self.rate_limit_max_requests = 100  # 窗口内最大请求数
    
    def login_required_with_rate_limit(self, f):
        """带限流的登录验证装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': '请先登录'}), 401
            
            # 每次请求都重新检查用户状态，防止已禁用账号继续使用旧 Session。
            user = User.query.get(session['user_id'])
            if not user or not user.is_active:
                session.clear()
                return jsonify({'error': '账号无效，请重新登录'}), 401
            
            return f(*args, **kwargs)
        return decorated_function
    
    def rate_limit(self, max_requests=None, window=None):
        """基于客户端 IP 和 endpoint 的滑动窗口限流装饰器。"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                client_ip = request.remote_addr
                endpoint = request.endpoint
                now = time.time()
                
                # 使用配置的默认值或传入的参数
                limit = max_requests or self.rate_limit_max_requests
                win = window or self.rate_limit_window
                
                # 初始化记录
                if client_ip not in self.rate_limits:
                    self.rate_limits[client_ip] = {}
                if endpoint not in self.rate_limits[client_ip]:
                    self.rate_limits[client_ip][endpoint] = []
                
                # 只保留当前窗口内的访问时间戳，窗口外的记录不参与限流判断。
                self.rate_limits[client_ip][endpoint] = [
                    t for t in self.rate_limits[client_ip][endpoint]
                    if now - t < win
                ]
                
                # 检查是否超过限制
                if len(self.rate_limits[client_ip][endpoint]) >= limit:
                    return jsonify({
                        'error': '请求过于频繁，请稍后再试',
                        'retry_after': win
                    }), 429
                
                # 记录本次请求
                self.rate_limits[client_ip][endpoint].append(now)
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def check_login_attempt(self, username, success):
        """记录一次登录尝试，并返回当前 IP 是否仍允许继续登录。"""
        client_ip = request.remote_addr
        now = time.time()
        
        if client_ip not in self.login_attempts:
            self.login_attempts[client_ip] = []
        
        # 添加尝试记录
        self.login_attempts[client_ip].append((now, success))
        
        # 清理过期记录（超过锁定时间的记录）
        self.login_attempts[client_ip] = [
            (t, s) for t, s in self.login_attempts[client_ip]
            if now - t < self.lockout_time
        ]
        
        # 检查是否被锁定
        recent_failures = sum(
            1 for t, s in self.login_attempts[client_ip]
            if not s and now - t < self.lockout_time
        )
        
        if recent_failures >= self.max_login_attempts:
            return False, f"登录失败次数过多，请 {self.lockout_time} 秒后再试"
        
        return True, None
    
    def is_ip_locked(self, ip):
        """检查 IP 是否被锁定"""
        if ip not in self.login_attempts:
            return False
        
        now = time.time()
        recent_failures = sum(
            1 for t, s in self.login_attempts[ip]
            if not s and now - t < self.lockout_time
        )
        
        return recent_failures >= self.max_login_attempts
    
    def cleanup_old_records(self):
        """清理过期的记录（定期调用）"""
        now = time.time()
        
        # 清理登录尝试记录
        expired_ips = [
            ip for ip, attempts in self.login_attempts.items()
            if all(now - t >= self.lockout_time for t, _ in attempts)
        ]
        for ip in expired_ips:
            del self.login_attempts[ip]
        
        # 清理已经没有有效窗口记录的限流 IP，避免内存长期增长。
        expired_ips = [
            ip for ip, endpoints in self.rate_limits.items()
            if all(
                all(now - t >= self.rate_limit_window for t in timestamps)
                for timestamps in endpoints.values()
            )
        ]
        for ip in expired_ips:
            del self.rate_limits[ip]


# 创建全局安全中间件实例
security = SecurityMiddleware()
