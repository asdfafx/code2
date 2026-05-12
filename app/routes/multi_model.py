# 多模型对比分析路由
from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.services.multi_model_llm import multi_model_service
from app.models import LLMModel
from app import db
from functools import wraps

bp = Blueprint('multi_model', __name__)

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
def analyze_with_model():
    """使用指定模型分析日志"""
    try:
        data = request.get_json()
        
        # 验证必要字段
        if 'log_entry' not in data:
            return jsonify({'error': '缺少日志条目'}), 400
        
        if 'model_id' not in data:
            return jsonify({'error': '缺少模型ID'}), 400
        
        log_entry = data['log_entry']
        model_id = data['model_id']
        
        # 获取模型配置
        model = LLMModel.query.get(model_id)
        if not model:
            return jsonify({'error': '模型不存在'}), 404
        
        if not model.is_active:
            return jsonify({'error': '模型未启用'}), 400
        
        # 构建模型配置
        model_config = {
            'model_type': model.model_name.split('-')[0] if '-' in model.model_name else 'ollama',
            'model_name': model.model_name,
            'api_endpoint': model.api_endpoint,
            'api_key': model.api_key,
            'secret_key': getattr(model, 'secret_key', None),
            'max_tokens': model.max_tokens,
            'temperature': model.temperature
        }
        
        # 执行分析
        result = multi_model_service.analyze_log(log_entry, model_config)
        
        return jsonify({
            'message': '分析完成',
            'model_name': model.model_name,
            'analysis': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/compare', methods=['POST'])
@login_required
def compare_models():
    """多模型对比分析"""
    try:
        data = request.get_json()
        
        if 'log_entry' not in data:
            return jsonify({'error': '缺少日志条目'}), 400
        
        log_entry = data['log_entry']
        model_ids = data.get('model_ids', [])
        
        # 如果没有指定模型，使用所有启用的模型
        if not model_ids:
            models = LLMModel.query.filter_by(is_active=True).all()
        else:
            models = LLMModel.query.filter(LLMModel.model_id.in_(model_ids)).all()
        
        if not models:
            return jsonify({'error': '没有可用的模型'}), 400
        
        # 构建模型配置列表
        model_configs = []
        for model in models:
            model_type = model.model_name.split('-')[0] if '-' in model.model_name else 'ollama'
            
            config = {
                'model_type': model_type,
                'model_name': model.model_name,
                'api_endpoint': model.api_endpoint,
                'api_key': model.api_key,
                'secret_key': getattr(model, 'secret_key', None),
                'max_tokens': model.max_tokens,
                'temperature': model.temperature
            }
            
            model_configs.append({
                'name': model.model_name,
                'config': config
            })
        
        # 执行对比分析
        results = multi_model_service.compare_models(log_entry, model_configs)
        
        return jsonify({
            'message': '对比分析完成',
            'results': results,
            'total_models': len(results)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/models', methods=['GET'])
@login_required
def get_available_models():
    """获取可用的多模型列表"""
    try:
        models = LLMModel.query.all()
        
        model_list = []
        for model in models:
            model_type = model.model_name.split('-')[0] if '-' in model.model_name else 'ollama'
            
            model_list.append({
                'model_id': model.model_id,
                'model_name': model.model_name,
                'model_type': model_type,
                'api_endpoint': model.api_endpoint,
                'is_active': model.is_active,
                'max_tokens': model.max_tokens,
                'temperature': model.temperature,
                'created_at': model.created_at.isoformat() if model.created_at else None
            })
        
        return jsonify({
            'models': model_list,
            'total': len(model_list)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/add-model', methods=['POST'])
@login_required
def add_custom_model():
    """添加自定义模型配置"""
    try:
        data = request.get_json()
        
        # 验证必要字段
        required_fields = ['model_name', 'api_endpoint']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'缺少必要字段: {field}'}), 400
        
        # 检查模型名称是否已存在
        existing = LLMModel.query.filter_by(model_name=data['model_name']).first()
        if existing:
            return jsonify({'error': '模型名称已存在'}), 400
        
        # 创建新模型
        new_model = LLMModel(
            model_name=data['model_name'],
            model_path='',
            api_endpoint=data['api_endpoint'],
            api_key=data.get('api_key', ''),
            max_tokens=data.get('max_tokens', 512),
            temperature=data.get('temperature', 0.7),
            is_active=data.get('is_active', True)
        )
        
        # 保存额外字段（如文心一言的secret_key）
        if 'secret_key' in data:
            setattr(new_model, 'secret_key', data['secret_key'])
        
        db.session.add(new_model)
        db.session.commit()
        
        return jsonify({
            'message': '模型添加成功',
            'model_id': new_model.model_id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/test-model', methods=['POST'])
@login_required
def test_model():
    """测试模型连接"""
    try:
        data = request.get_json()
        
        if 'model_id' not in data:
            return jsonify({'error': '缺少模型ID'}), 400
        
        model = LLMModel.query.get(data['model_id'])
        if not model:
            return jsonify({'error': '模型不存在'}), 404
        
        # 构建简单的测试提示词
        test_prompt = "请回复OK"
        
        model_type = model.model_name.split('-')[0] if '-' in model.model_name else 'ollama'
        model_config = {
            'model_type': model_type,
            'model_name': model.model_name,
            'api_endpoint': model.api_endpoint,
            'api_key': model.api_key,
            'secret_key': getattr(model, 'secret_key', None),
            'max_tokens': 10,
            'temperature': 0.1
        }
        
        # 尝试调用模型
        result = multi_model_service.analyze_log({
            'ip_address': '127.0.0.1',
            'url': '/test',
            'method': 'GET',
            'status_code': 200,
            'parameters': ''
        }, model_config)
        
        return jsonify({
            'message': '模型连接成功',
            'response_preview': result.get('reason', '')[:100]
        })
        
    except Exception as e:
        return jsonify({
            'message': '模型连接失败',
            'error': str(e)
        }), 500
