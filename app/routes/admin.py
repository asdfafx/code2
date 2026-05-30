# 管理员路由
"""管理员后台接口：用户管理、模型配置和系统统计。"""
from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.models import User, LogImport, LLMModel, AnalysisResult
from functools import wraps

bp = Blueprint('admin', __name__)

# 为 API 蓝图禁用 CSRF 保护
csrf.exempt(bp)


def admin_required(f):
    """要求请求来自已登录管理员。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': '权限不足'}), 403
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    """分页获取用户列表，并附带每个用户的日志导入数量。"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        pagination = User.query.order_by(User.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        users = [{
            **user.to_dict(),
            'log_count': user.log_imports.count()
        } for user in pagination.items]
        
        return jsonify({
            'users': users,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """修改指定用户的邮箱、角色或启用状态。"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # 只允许更新白名单字段，避免请求体中的其他字段被误写入模型。
        if 'email' in data:
            user.email = data['email']
        if 'role' in data and data['role'] in ['admin', 'user']:
            user.role = data['role']
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify({
            'message': '修改成功',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """删除指定用户及其级联数据。"""
    try:
        user = User.query.get_or_404(user_id)
        
        # 不允许删除自己
        if user.user_id == session['user_id']:
            return jsonify({'error': '不能删除自己的账号'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': '删除成功'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    """启用或禁用指定用户。"""
    try:
        user = User.query.get_or_404(user_id)
        
        # 记录切换前的状态
        old_status = user.is_active
        print(f"[DEBUG] 切换用户状态 - 用户ID: {user_id}, 用户名: {user.username}")
        print(f"[DEBUG] 切换前 is_active: {old_status}")
        
        # 不允许禁用自己，避免管理员把自己锁在系统外。
        if user.user_id == session['user_id']:
            return jsonify({'error': '不能禁用自己'}), 400
        
        # 切换状态
        user.is_active = not user.is_active
        db.session.commit()
        
        # 记录切换后的状态
        new_status = user.is_active
        print(f"[DEBUG] 切换后 is_active: {new_status}")
        
        status_text = '已启用' if user.is_active else '已禁用'
        print(f"[DEBUG] 返回消息: 用户{status_text}")
        
        return jsonify({
            'message': f'用户{status_text}',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/models', methods=['GET'])
@admin_required
def get_models():
    """获取模型配置列表"""
    try:
        models = LLMModel.query.all()
        return jsonify({
            'models': [model.to_dict() for model in models]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/models', methods=['POST'])
@admin_required
def create_model():
    """创建一条 LLM 模型调用配置。"""
    try:
        data = request.get_json()
        
        model = LLMModel(
            model_name=data.get('model_name', ''),
            model_path=data.get('model_path', ''),
            api_endpoint=data.get('api_endpoint', ''),
            api_key=data.get('api_key', ''),
            max_tokens=data.get('max_tokens', 512),
            temperature=data.get('temperature', 0.7)
        )
        
        db.session.add(model)
        db.session.commit()
        
        return jsonify({
            'message': '创建成功',
            'model': model.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/models/<int:model_id>', methods=['PUT'])
@admin_required
def update_model(model_id):
    """更新指定模型配置的可编辑字段。"""
    try:
        model = LLMModel.query.get_or_404(model_id)
        data = request.get_json()
        
        if 'model_name' in data:
            model.model_name = data['model_name']
        if 'api_endpoint' in data:
            model.api_endpoint = data['api_endpoint']
        if 'max_tokens' in data:
            model.max_tokens = data['max_tokens']
        if 'temperature' in data:
            model.temperature = data['temperature']
        if 'is_active' in data:
            model.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify({
            'message': '更新成功',
            'model': model.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """获取后台首页展示的全局统计信息。"""
    try:
        # 用户统计
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        
        # 日志统计
        total_imports = LogImport.query.count()
        total_entries = db.session.query(db.func.sum(LogImport.total_lines)).scalar() or 0
        
        # 分析统计
        total_analyses = db.session.query(db.func.count(AnalysisResult.result_id)).scalar() or 0
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'total_imports': total_imports,
            'total_log_entries': int(total_entries),
            'total_analyses': total_analyses
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
