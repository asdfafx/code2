# 用户认证路由
"""用户注册、登录、登出和个人资料接口。"""
from flask import Blueprint, request, jsonify, session
from datetime import datetime
from app import db, csrf
from app.models import User
from app.security import security
from functools import wraps

bp = Blueprint('auth', __name__)

# 为 API 蓝图禁用 CSRF 保护
csrf.exempt(bp)


def login_required(f):
    """要求请求已经建立用户 Session。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """要求当前登录用户是管理员。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': '权限不足'}), 403
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/register', methods=['POST'])
def register():
    """创建普通用户账号。"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        
        # 验证输入，避免空用户名、弱密码和重复账号进入数据库。
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
        
        if len(password) < 6:
            return jsonify({'error': '密码长度至少为 6 位'}), 400
        
        # 检查用户名是否存在
        if User.query.filter_by(username=username).first():
            return jsonify({'error': '用户名已存在'}), 400
        
        # 检查邮箱是否存在
        if email and User.query.filter_by(email=email).first():
            return jsonify({'error': '邮箱已被注册'}), 400
        
        # 创建新用户时只保存密码哈希，不保存明文密码。
        user = User(
            username=username,
            email=email,
            role='user'
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': '注册成功',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/login', methods=['POST'])
@security.rate_limit(max_requests=10, window=60)  # 每分钟最多 10 次登录尝试
def login():
    """校验用户名密码，写入 Session 并更新最后登录时间。"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
        
        # 检查 IP 是否被锁定
        client_ip = request.remote_addr
        if security.is_ip_locked(client_ip):
            return jsonify({'error': f'登录失败次数过多，请 {security.lockout_time} 秒后再试'}), 429
        
        # 查找用户
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            # 记录失败尝试
            security.check_login_attempt(username, False)
            return jsonify({'error': '用户名或密码错误'}), 401
        
        if not user.is_active:
            return jsonify({'error': '账号已被禁用'}), 403
        
        # 记录成功登录
        security.check_login_attempt(username, True)
        
        # 更新最后登录时间
        user.last_login = datetime.now()
        db.session.commit()
        
        # 设置会话，后续 API 通过 session['user_id'] 判断登录状态。
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        
        return jsonify({
            'message': '登录成功',
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """用户登出"""
    session.clear()
    return jsonify({'message': '退出成功'})


@bp.route('/check', methods=['GET'])
def check_auth():
    """检查当前请求是否仍处于登录状态。"""
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({
        'user_id': user.user_id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    })


@bp.route('/current', methods=['GET'])
@login_required
def get_current_user():
    """获取当前用户信息"""
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({'user': user.to_dict()})


@bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """获取个人信息（用于个人中心页面）"""
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'error': '用户不存在'}), 404
        
        return jsonify({
            'success': True,
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email or '',
            'role': user.role,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """修改当前用户个人资料。"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        email = data.get('email', '').strip()
        
        # 检查邮箱是否已被其他用户使用，避免唯一索引冲突。
        if email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and existing_user.user_id != user.user_id:
                return jsonify({'error': '邮箱已被使用'}), 400
            user.email = email
        
        db.session.commit()
        
        return jsonify({
            'message': '修改成功',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/password', methods=['PUT'])
@login_required
def change_password():
    """验证旧密码后更新当前用户密码。"""
    try:
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')
        
        if not user.check_password(old_password):
            return jsonify({'error': '原密码错误'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': '新密码长度至少为 6 位'}), 400
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': '密码修改成功'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
