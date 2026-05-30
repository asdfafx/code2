# 日志管理路由
"""日志上传、粘贴导入、规则初筛和 LLM 分析接口。"""
import os
from flask import Blueprint, request, jsonify, current_app, session
from werkzeug.utils import secure_filename
from datetime import datetime
from app import db, socketio, csrf
from app.models import LogImport, LogEntry
from app.services.log_parser import LogParser
from app.services.realtime_monitor import real_time_monitor
from app.services.rule_filter import RuleFilter
from app.security import security
from functools import wraps

bp = Blueprint('logs', __name__)

# 为 API 蓝图禁用 CSRF 保护
csrf.exempt(bp)


def login_required(f):
    """要求请求已登录后才能访问日志数据。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    """检查上传文件扩展名是否在允许列表内。"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'log'}


@bp.route('/upload', methods=['POST'])
@login_required
@security.rate_limit(max_requests=20, window=300)  # 5分钟最多20次上传
def upload_log():
    """上传日志文件，解析后写入数据库并广播最新日志。"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到上传文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '未选择文件'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件格式，请上传.txt 或.log 文件'}), 400
        
        # 保存文件到上传目录，文件名前加时间戳避免重名覆盖。
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(upload_folder, saved_filename)
        file.save(file_path)
        
        # 创建导入记录，先标记为 processing，解析完成后再更新状态。
        log_format = request.form.get('format', 'apache')
        import_record = LogImport(
            user_id=session['user_id'],
            filename=filename,
            log_format=log_format,
            file_path=file_path,
            status='processing'
        )
        db.session.add(import_record)
        db.session.commit()
        
        # 解析日志并将结构化条目批量写入数据库。
        parser = LogParser()
        entries_data = parser.parse_file(file_path, log_format)
        
        # 批量创建条目
        if entries_data:
            parser.create_entries(import_record, entries_data)
            
            # 更新导入记录
            import_record.total_lines = len(entries_data)
            import_record.parsed_lines = len(entries_data)
            import_record.status = 'completed'
        else:
            import_record.status = 'failed'
        
        db.session.commit()
        
        # 如果有新条目，通过 WebSocket 广播最近几条，驱动实时看板更新。
        if entries_data and len(entries_data) > 0:
            # 获取最新的几个条目进行广播
            recent_entries = LogEntry.query.filter_by(import_id=import_record.import_id)\
                .order_by(LogEntry.created_at.desc()).limit(5).all()
            
            for entry in recent_entries:
                log_payload = entry.to_dict()
                real_time_monitor.record_log(log_payload)
                socketio.emit('new_log', log_payload)
        
        return jsonify({
            'success': True,
            'message': '上传成功',
            'import': import_record.to_dict(),
            'parsed_count': len(entries_data)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/paste', methods=['POST'])
@login_required
def paste_log():
    """导入用户粘贴的日志文本。"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        log_format = data.get('format', 'apache')
        
        if not text.strip():
            return jsonify({'error': '日志内容不能为空'}), 400
        
        # 粘贴文本没有真实文件名，统一使用 pasted_text.txt 作为导入来源。
        import_record = LogImport(
            user_id=session['user_id'],
            filename='pasted_text.txt',
            log_format=log_format,
            status='processing'
        )
        db.session.add(import_record)
        db.session.commit()
        
        # 使用与文件上传相同的解析流程，保证数据结构一致。
        parser = LogParser()
        entries_data = parser.parse_text(text, log_format)
        
        # 批量创建条目
        if entries_data:
            parser.create_entries(import_record, entries_data)
            
            import_record.total_lines = len(entries_data)
            import_record.parsed_lines = len(entries_data)
            import_record.status = 'completed'
        else:
            import_record.status = 'failed'
        
        db.session.commit()
        
        # 如果有新条目，通过 WebSocket 广播
        if entries_data and len(entries_data) > 0:
            # 获取最新的几个条目进行广播
            recent_entries = LogEntry.query.filter_by(import_id=import_record.import_id)\
                .order_by(LogEntry.created_at.desc()).limit(5).all()
            
            for entry in recent_entries:
                log_payload = entry.to_dict()
                real_time_monitor.record_log(log_payload)
                socketio.emit('new_log', log_payload)
        
        return jsonify({
            'success': True,
            'message': '导入成功',
            'import': import_record.to_dict(),
            'parsed_count': len(entries_data)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/list', methods=['GET'])
@login_required
def list_logs():
    """分页获取当前用户的日志导入记录。"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # 查询用户的导入记录（按 import_id 降序，最新的在前面）
        query = LogImport.query.filter_by(user_id=session['user_id'])\
            .order_by(LogImport.import_id.desc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        imports = [{
            **imp.to_dict(),
            'entry_count': imp.entries.count()
        } for imp in pagination.items]
        
        return jsonify({
            'imports': imports,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:import_id>', methods=['GET'])
@login_required
def get_log_detail(import_id):
    """获取指定导入批次的日志条目详情。"""
    try:
        import_record = LogImport.query.filter_by(
            import_id=import_id,
            user_id=session['user_id']
        ).first_or_404()
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # 查询日志条目
        query = LogEntry.query.filter_by(import_id=import_id)\
            .order_by(LogEntry.created_at.desc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        entries = [entry.to_dict() for entry in pagination.items]
        
        return jsonify({
            'import': import_record.to_dict(),
            'entries': entries,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _log_entry_to_rule_data(entry):
    """将 LogEntry 模型转换为规则初筛服务需要的字典。"""
    return {
        'ip_address': entry.ip_address,
        'request_time': entry.request_time,
        'method': entry.method,
        'url': entry.url,
        'parameters': entry.parameters,
        'status_code': entry.status_code,
        'response_size': entry.response_size,
        'user_agent': entry.user_agent,
        'referer': entry.referer,
        'raw_log': entry.raw_log
    }


def _summarize_pre_screen(entries):
    """基于已保存的初筛字段汇总统计，不重复执行规则。"""
    stats = {'total_scanned': len(entries), 'flagged': 0, 'top_keywords': {}, 'attack_types': {}}
    rule_filter = RuleFilter()
    template_labels = getattr(rule_filter, 'PROMPT_TEMPLATE_LABELS', {})

    for entry in entries:
        risk_score = entry.initial_risk_score or 0
        if risk_score >= 20:
            stats['flagged'] += 1

        # risk_keywords 保存的是逗号分隔字符串，这里拆回列表用于统计。
        keywords = [kw for kw in (entry.risk_keywords or '').split(',') if kw]
        for kw in keywords:
            stats['top_keywords'][kw] = stats['top_keywords'].get(kw, 0) + 1
            label = template_labels.get(rule_filter.classify_keyword(kw), kw)
            stats['attack_types'][label] = stats['attack_types'].get(label, 0) + 1

    sorted_keywords = sorted(stats['top_keywords'].items(), key=lambda x: x[1], reverse=True)
    stats['top_keywords'] = dict(sorted_keywords[:10])
    return stats


def _choose_prompt_template(default_analysis_type, pre_screen_keywords):
    """根据初筛命中结果选择单条日志的 LLM 提示词模板。"""
    valid_templates = set(getattr(RuleFilter, 'PROMPT_TEMPLATE_LABELS', {}).keys())
    rule_filter = RuleFilter()

    # 初筛命中的攻击类型优先级高于前端默认分析类型。
    for keyword in pre_screen_keywords:
        template_name = rule_filter.classify_keyword(keyword)
        if template_name in valid_templates:
            return template_name

    if default_analysis_type == 'auto':
        return 'general'

    return default_analysis_type if default_analysis_type in valid_templates else 'general'


def _run_pre_screen_for_import(import_id):
    """对一个导入批次执行规则初筛，并把风险分和关键词写回日志条目。"""
    import_record = LogImport.query.filter_by(
        import_id=import_id,
        user_id=session['user_id']
    ).first_or_404()

    entries = LogEntry.query.filter_by(import_id=import_record.import_id)\
        .order_by(LogEntry.entry_id.asc()).all()
    rule_filter = RuleFilter()
    suspicious_entries = []
    stats = {'total_scanned': len(entries), 'flagged': 0, 'top_keywords': {}, 'attack_types': {}}

    for entry in entries:
        # 规则初筛只使用结构化日志字段，不依赖 LLM。
        analysis = rule_filter.analyze_entry(_log_entry_to_rule_data(entry))
        risk_score = analysis.get('risk_score', 0)
        matched_keywords = analysis.get('matched_keywords', [])
        prompt_templates = analysis.get('prompt_templates', [])

        entry.initial_risk_score = risk_score
        entry.risk_keywords = ','.join(matched_keywords)

        # 风险分达到阈值后加入可疑列表，前端可直接展示前 100 条。
        if risk_score >= 20:
            stats['flagged'] += 1
            suspicious_entries.append({
                'entry': entry.to_dict(),
                'analysis': analysis
            })

        for kw in matched_keywords:
            stats['top_keywords'][kw] = stats['top_keywords'].get(kw, 0) + 1
        for template_name in prompt_templates:
            label = RuleFilter.PROMPT_TEMPLATE_LABELS.get(template_name, template_name)
            stats['attack_types'][label] = stats['attack_types'].get(label, 0) + 1

    sorted_keywords = sorted(stats['top_keywords'].items(), key=lambda x: x[1], reverse=True)
    stats['top_keywords'] = dict(sorted_keywords[:10])
    db.session.commit()

    return {
        'success': True,
        'total_logs': len(entries),
        'suspicious_count': len(suspicious_entries),
        'safe_count': len(entries) - len(suspicious_entries),
        'suspicious_entries': suspicious_entries[:100],
        'pre_screen_stats': stats,
        'message': '初筛完成'
    }


@bp.route('/<int:import_id>/filter', methods=['POST'])
@login_required
def filter_logs(import_id):
    """兼容旧接口：对指定导入批次筛选可疑日志。"""
    try:
        result = _run_pre_screen_for_import(import_id)
        result['total'] = result['suspicious_count']
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/pre-screen', methods=['POST'])
@login_required
def pre_screen_logs():
    """独立触发规则初筛，不调用 LLM。"""
    try:
        data = request.get_json() or {}
        import_id = data.get('import_id')
        if not import_id:
            return jsonify({'success': False, 'error': '请提供 import_id'}), 400

        return jsonify(_run_pre_screen_for_import(import_id))
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:import_id>', methods=['DELETE'])
@login_required
def delete_log(import_id):
    """删除指定日志导入记录及其本地上传文件。"""
    try:
        import_record = LogImport.query.filter_by(
            import_id=import_id,
            user_id=session['user_id']
        ).first_or_404()
        
        # 删除文件
        if import_record.file_path and os.path.exists(import_record.file_path):
            os.remove(import_record.file_path)
        
        db.session.delete(import_record)
        db.session.commit()
        
        return jsonify({'message': '删除成功'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/analyze-with-config', methods=['POST'])
@login_required
def analyze_with_custom_config():
    """使用请求中传入的模型配置直接分析日志。

    这是一个较早的兼容接口：它在路由内组装请求体并直接调用模型服务。
    新流程优先使用 /llm-analyze 和 LLMService。
    """
    try:
        import requests
        import json
        from app.services.llm_service import PromptTemplateManager
        from app.services.rule_filter import RuleFilter
        
        data = request.get_json()
        
        # 获取配置参数
        model_type = data.get('model_type', 'ollama')
        api_key = data.get('api_key', '')
        api_endpoint = data.get('api_endpoint', 'http://localhost:11434')
        model_name = data.get('model_name', 'qwen:7b')
        prompt_template = data.get('prompt_template', 'general')
        import_id = data.get('import_id')
        log_content = data.get('log_content', '')
        
        # DeepSeek 思考模式配置
        thinking_enabled = data.get('thinking_enabled', True)  # 默认启用思考模式
        reasoning_effort = data.get('reasoning_effort', 'high')  # 思考强度: low/medium/high/max
        
        # 获取日志条目：优先从数据库读取，也支持直接传入日志文本。
        entries = []
        if import_id:
            # 从数据库获取
            log_entries = LogEntry.query.filter_by(import_id=import_id)\
                .order_by(LogEntry.entry_id.asc()).all()
            for entry in log_entries:
                entries.append({
                    'ip_address': entry.ip_address,
                    'request_time': entry.request_time,
                    'method': entry.method,
                    'url': entry.url,
                    'parameters': entry.parameters,
                    'status_code': entry.status_code,
                    'response_size': entry.response_size,
                    'user_agent': entry.user_agent,
                    'raw_log': entry.raw_log
                })
        elif log_content:
            # 直接解析传入的日志内容
            parser = LogParser()
            parsed_entries = parser.parse_text(log_content, 'apache')
            for entry_data in parsed_entries:
                entries.append(entry_data)
        else:
            return jsonify({'error': '没有可分析的日志内容'}), 400
        
        if not entries:
            return jsonify({
                'success': True,
                'total_logs': 0,
                'suspicious_count': 0,
                'safe_count': 0,
                'message': '没有解析到有效日志'
            })
        
        # 初始化模板管理器
        template_manager = PromptTemplateManager()
        rule_filter = RuleFilter()
        
        # 分析结果汇总
        total_logs = len(entries)
        suspicious_logs = []
        risk_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # 构建 LLM 请求头；如果用户提供 API Key，则按 Bearer Token 传递。
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        # 根据模型类型确定 API URL 和请求格式。
        if model_type == 'deepseek':
            api_url = f"{api_endpoint}/chat/completions" if '/v1' not in api_endpoint else api_endpoint
            llm_payload_template = {
                'model': model_name,
                'messages': [{'role': 'user', 'content': '{prompt}'}],
                'max_tokens': 2048,
                'temperature': 0.1  # 严谨模式
            }
            # DeepSeek 思考模式配置
            if thinking_enabled:
                llm_payload_template['reasoning_effort'] = reasoning_effort
                llm_payload_template['extra_body'] = {"thinking": {"type": "enabled"}}
        elif model_type == 'dashscope':
            api_url = f"{api_endpoint}/services/aigc/text-generation/generation"
            llm_payload_template = {
                'model': model_name,
                'input': {'messages': [{'role': 'user', 'content': '{prompt}'}]},
                'parameters': {'max_tokens': 512, 'temperature': 0.1}  # 严谨模式
            }
        
        # 初筛统计
        pre_screen_stats = {'total_scanned': 0, 'flagged': 0, 'top_keywords': {}, 'attack_types': {}}

        # 遍历分析每条日志；限制最多 50 条，避免一次请求占用过长时间。
        for entry in entries[:50]:  # 限制最多分析50条
            try:
                # 规则初筛
                pre_screen = rule_filter.analyze_entry(entry)
                risk_keywords = pre_screen.get('matched_keywords', [])
                risk_score = pre_screen.get('risk_score', 0)
                attack_types = pre_screen.get('attack_types', [])

                # 汇总初筛统计
                pre_screen_stats['total_scanned'] += 1
                if risk_score >= 20:
                    pre_screen_stats['flagged'] += 1
                for kw in risk_keywords:
                    pre_screen_stats['top_keywords'][kw] = pre_screen_stats['top_keywords'].get(kw, 0) + 1
                for at in attack_types:
                    pre_screen_stats['attack_types'][at] = pre_screen_stats['attack_types'].get(at, 0) + 1
                
                # 构建提示词
                template = template_manager.get_template(prompt_template)
                
                prompt = template.format(
                    ip_address=entry.get('ip_address', ''),
                    request_time=entry.get('request_time', ''),
                    method=entry.get('method', ''),
                    url=entry.get('url', ''),
                    parameters=entry.get('parameters', ''),
                    status_code=entry.get('status_code', 0),
                    user_agent=entry.get('user_agent', ''),
                    raw_log=entry.get('raw_log', ''),
                    risk_keywords=', '.join(risk_keywords) if risk_keywords else '无',
                    initial_risk_score=risk_score,
                    referer=entry.get('referer', ''),
                    raw_request=f"{entry.get('method', '')} {entry.get('url', '')}?{entry.get('parameters', '')}",
                    risk_level='高风险' if risk_score >= 60 else '中风险' if risk_score >= 40 else '正常',
                    analysis_reason='',
                    confidence_score=0.8
                )
                
                # 调用 LLM。这里先把模板中的 {prompt} 替换为真实提示词，再还原成 JSON。
                llm_payload = json.dumps(llm_payload_template).replace('"{prompt}"', json.dumps(prompt))
                llm_payload = json.loads(llm_payload)
                
                response = requests.post(api_url, headers=headers, json=llm_payload, timeout=10)  # 10秒超时
                response.raise_for_status()
                
                # 解析响应
                result = response.json()
                
                if model_type == 'deepseek':
                    message = result['choices'][0]['message']
                    llm_response = message.get('content', '')
                    reasoning_content = message.get('reasoning_content', '')  # 获取思考链内容
                elif model_type == 'dashscope':
                    llm_response = result.get('output', {}).get('text', '')
                    reasoning_content = ''
                
                # 解析 LLM 响应并补充初筛上下文，便于前端展示。
                parsed_result = _parse_llm_analysis(llm_response)
                parsed_result['raw_log'] = entry.get('raw_log', '')
                parsed_result['url'] = entry.get('url', '')
                parsed_result['initial_risk_score'] = risk_score
                parsed_result['risk_keywords'] = list(risk_keywords)
                parsed_result['pre_attack_types'] = attack_types

                # 添加思考链内容（如果有）
                if reasoning_content:
                    parsed_result['reasoning_content'] = reasoning_content

                # 统计风险
                risk_level = parsed_result.get('risk_level', '正常')
                if risk_level in risk_stats:
                    risk_stats[risk_level] += 1
                
                # 可疑日志加入结果
                if risk_level in ['高风险', '严重风险'] or parsed_result.get('attack_type') not in ['无攻击', '正常访问', '正常']:
                    suspicious_logs.append(parsed_result)
                    
            except Exception as e:
                print(f"分析日志失败: {e}")
                continue
        
        # 初筛关键词排序，取 Top 10
        sorted_keywords = sorted(pre_screen_stats['top_keywords'].items(), key=lambda x: x[1], reverse=True)
        pre_screen_stats['top_keywords'] = dict(sorted_keywords[:10])

        return jsonify({
            'success': True,
            'total_logs': total_logs,
            'suspicious_count': len(suspicious_logs),
            'safe_count': total_logs - len(suspicious_logs),
            'suspicious_logs': suspicious_logs,
            'risk_stats': risk_stats,
            'pre_screen_stats': pre_screen_stats,
            'thinking_mode': {
                'enabled': thinking_enabled,
                'effort': reasoning_effort if model_type == 'deepseek' else None
            },
            'message': '分析完成'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/last', methods=['GET'])
@login_required
def get_last_import():
    """获取当前用户最后一次日志导入记录。"""
    try:
        last_import = LogImport.query.filter_by(
            user_id=session['user_id']
        ).order_by(LogImport.import_time.desc()).first()
        
        if not last_import:
            return jsonify({'error': '没有找到导入记录'}), 404
        
        return jsonify(last_import.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _parse_llm_analysis(text):
    """解析 LLM 文本响应，优先提取 JSON，失败时做简单文本兜底分类。"""
    try:
        import json
        import re

        # 尝试从文本中提取 JSON，兼容 Markdown 代码块和裸 JSON。
        json_patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*\{[^}]+\}\s*```',
            r'\{[^{}]*"[^"]+"\s*:\s*[^{}]+\}'
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    result = json.loads(match.group(0))
                    # 标准化字段名
                    return {
                        'attack_type': result.get('attack_type', '未知'),
                        'risk_level': result.get('risk_level', '正常'),
                        'reason': result.get('reason', result.get('conclusion', '')),
                        'conclusion': result.get('conclusion', result.get('reason', '')),
                        'confidence': result.get('confidence', 0.5),
                        'suggestions': result.get('suggestions', [])
                    }
                except:
                    pass
        
        # 无法解析 JSON 时，根据关键词做保守兜底分类。
        text_lower = text.lower()
        
        # 简单文本分析
        if any(word in text_lower for word in ['sql注入', 'sql injection', '注入']):
            attack_type = 'SQL注入'
            risk_level = '高风险'
        elif any(word in text_lower for word in ['xss', '跨站', '脚本', 'script']):
            attack_type = 'XSS攻击'
            risk_level = '高风险'
        elif any(word in text_lower for word in ['目录遍历', '文件包含', 'path traversal']):
            attack_type = '目录遍历'
            risk_level = '中风险'
        elif any(word in text_lower for word in ['正常', '安全', 'no attack', '无攻击']):
            attack_type = '正常访问'
            risk_level = '正常'
        else:
            attack_type = '未知'
            risk_level = '中风险'
        
        return {
            'attack_type': attack_type,
            'risk_level': risk_level,
            'reason': text[:200] if len(text) > 200 else text,
            'conclusion': text[:100] if len(text) > 100 else text,
            'confidence': 0.6,
            'suggestions': ['建议人工审核']
        }
        
    except Exception as e:
        return {
            'attack_type': '解析错误',
            'risk_level': '正常',
            'reason': f'解析失败: {str(e)}',
            'conclusion': '无法确定',
            'confidence': 0,
            'suggestions': []
        }


@bp.route('/test-llm', methods=['POST'])
@login_required
def test_llm_connection():
    """使用短提示词测试指定 LLM 连接是否可用。"""
    try:
        import requests
        
        data = request.get_json()
        model_type = data.get('model_type', 'ollama')
        api_key = data.get('api_key', '')
        api_endpoint = data.get('api_endpoint', 'http://localhost:11434')
        model_name = data.get('model_name', 'qwen:7b')
        
        test_prompt = "请回复OK"
        
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        # 构建请求
        if model_type == 'deepseek':
            api_url = f"{api_endpoint}/chat/completions" if '/v1' not in api_endpoint else api_endpoint
            payload = {
                'model': model_name,
                'messages': [{'role': 'user', 'content': test_prompt}],
                'max_tokens': 10
            }
        elif model_type == 'dashscope':
            api_url = f"{api_endpoint}/services/aigc/text-generation/generation"
            payload = {
                'model': model_name,
                'input': {'messages': [{'role': 'user', 'content': test_prompt}]},
                'parameters': {'max_tokens': 10}
            }
        
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        # 验证响应
        if model_type == 'deepseek':
            reply = result['choices'][0]['message']['content']
        elif model_type == 'dashscope':
            reply = result.get('output', {}).get('text', '')
        
        if 'ok' in reply.lower():
            return jsonify({'success': True, 'message': f'连接成功！模型响应: {reply[:50]}'})
        else:
            return jsonify({'success': True, 'message': f'连接成功，但响应异常: {reply[:50]}'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/llm-analyze', methods=['POST'])
@login_required
def llm_analyze():
    """
    统一的 LLM 分析接口
    
    支持：
    - 阿里云 Qwen (dashscope)
    - DeepSeek (支持思考模式)
    
    分析类型通过 prompt_template 指定：
    - general: 通用安全分析
    - sql_injection: SQL 注入检测
    - xss: XSS 攻击检测
    - directory_traversal: 目录遍历检测
    """
    try:
        from app.services.llm_service import LLMService
        
        data = request.get_json()
        
        # 获取配置参数
        model_type = data.get('model_type', 'dashscope')  # 默认使用阿里云百炼
        
        # ⚠️ 强制要求前端传入 API Key，禁止使用配置文件中的备用 Key
        api_key_from_frontend = data.get('api_key', '').strip()
        if not api_key_from_frontend:
            return jsonify({
                'success': False,
                'error': '❌ 必须提供 API Key！请在前端输入框中输入您的 API Key'
            }), 400
        
        api_key = api_key_from_frontend
        
        api_endpoint = data.get('api_endpoint', '')
        model_name = data.get('model_name', '')
        analysis_type = data.get('analysis_type', 'general')
        import_id = data.get('import_id')
        max_logs = data.get('max_logs', 50)
        try:
            max_logs = int(max_logs)
        except (TypeError, ValueError):
            max_logs = 50
        
        # DeepSeek 思考模式
        thinking_enabled = data.get('thinking_enabled', False)
        reasoning_effort = data.get('reasoning_effort', 'high')
        
        # 设置默认端点和模型
        if model_type == 'dashscope':
            if not api_endpoint:
                api_endpoint = 'https://dashscope.aliyuncs.com/api/v1'
            if not model_name:
                model_name = 'qwen-plus'
        elif model_type == 'deepseek':
            if not api_endpoint:
                api_endpoint = 'https://api.deepseek.com/v1'
            if not model_name:
                model_name = 'deepseek-chat'
        
        # 获取日志条目，只允许按 import_id 分析已导入的数据。
        entries = []
        filename = 'unknown'  # 默认文件名
        if import_id:
            # 通过 import_id 查询 log_imports 表获取 filename
            log_import = LogImport.query.get(import_id)
            if log_import:
                filename = log_import.filename or 'unknown'
            
            log_entries = LogEntry.query.filter_by(import_id=import_id).all()
            for entry in log_entries:
                entries.append({
                    'entry_id': entry.entry_id,
                    'ip_address': entry.ip_address or '',
                    'request_time': entry.request_time,
                    'method': entry.method or '',
                    'url': entry.url or '',
                    'parameters': entry.parameters or '',
                    'status_code': entry.status_code or 0,
                    'user_agent': entry.user_agent or '',
                    'referer': entry.referer or '',
                    'raw_log': entry.raw_log or '',
                    'initial_risk_score': entry.initial_risk_score or 0,
                    'risk_keywords': [kw for kw in (entry.risk_keywords or '').split(',') if kw]
                })

        else:
            return jsonify({'error': '请提供 import_id'}), 400
        
        # 调试日志：确认收到正确的 analysis_type
        print(f"\n{'='*80}")
        print(f"[DEBUG] ==================== 开始分析 ====================")
        print(f"[DEBUG] 收到分析请求 - analysis_type: {analysis_type}, model_type: {model_type}")
        print(f"[DEBUG] import_id: {import_id}, max_logs: {max_logs}")
        print(f"[DEBUG] api_endpoint: {api_endpoint}")
        print(f"[DEBUG] 日志条目数量: {len(entries)}")
        
        # API Key 来源说明
        if api_key_from_frontend:
            print(f"[DEBUG] ✅ API Key 来源: 前端输入 (用户自定义)")
            print(f"[DEBUG] API Key 前缀: {api_key[:10]}...")
        else:
            # 理论上不会到这里，因为前面已经验证了
            print(f"[DEBUG] ❌ API Key 未提供！")
            return jsonify({
                'success': False,
                'error': '❌ 必须提供 API Key！请在前端输入框中输入您的 API Key'
            }), 400
        
        if entries:
            print(f"[DEBUG] 第一条日志URL: {entries[0].get('url', 'N/A')}")
        print(f"[DEBUG] =====================================================\n")
        
        if not entries:
            return jsonify({
                'success': True,
                'total_logs': 0,
                'suspicious_count': 0,
                'safe_count': 0,
                'risk_stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'message': '没有可分析的日志'
            })
        
        # 初始化 LLM 服务（传递思考模式配置）
        llm_service = LLMService(
            api_endpoint, 
            model_name, 
            api_key,
            thinking_enabled=(thinking_enabled and model_type == 'deepseek'),
            reasoning_effort=reasoning_effort
        )
        
        # 风险统计
        total_logs = len(entries)
        suspicious_logs = []
        risk_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        # 使用已经保存的初筛结果作为 LLM 上下文，不在此接口重新执行规则初筛。
        pre_screen_stats = _summarize_pre_screen(
            LogEntry.query.filter_by(import_id=import_id)
                .order_by(LogEntry.entry_id.asc())
                .limit(max_logs)
                .all()
        )

        # 遍历分析每条日志，根据初筛命中的攻击类型动态选择提示词。
        for i, entry in enumerate(entries[:max_logs]):
            try:
                risk_score = entry.get('initial_risk_score', 0) or 0
                risk_keywords = entry.get('risk_keywords', [])
                entry['initial_risk_score'] = risk_score
                entry_analysis_type = _choose_prompt_template(analysis_type, risk_keywords)

                entry['pre_screen_analysis_type'] = entry_analysis_type

                print(
                    f"[DEBUG] 第 {i+1} 条日志初筛命中: "
                    f"{', '.join(risk_keywords) if risk_keywords else '无'} -> "
                    f"使用提示词: {entry_analysis_type}"
                )

                # 根据本条日志的初筛结果调用对应的 LLM 提示词模板
                result = llm_service.analyze(entry, risk_keywords, entry_analysis_type, filename)
                
                # 添加日志信息
                result['raw_log'] = entry.get('raw_log', '')
                result['url'] = entry.get('url', '')
                result['ip_address'] = entry.get('ip_address', '')
                result['method'] = entry.get('method', '')
                result['status_code'] = entry.get('status_code', 0)
                result['initial_risk_score'] = risk_score
                result['risk_keywords'] = risk_keywords
                result['analysis_type'] = entry_analysis_type
                
                # DeepSeek 思考模式获取 reasoning_content
                if model_type == 'deepseek' and thinking_enabled:
                    # reasoning_content 已在 LLMService 中处理
                    pass
                
                # 统计风险等级，供前端摘要展示。
                risk_level = result.get('risk_level', '正常')
                if risk_level in risk_stats:
                    risk_stats[risk_level] += 1
                
                # 可疑日志加入结果（风险等级不为正常或低风险，或有攻击类型）。
                attack_type = result.get('attack_type', '')
                is_safe = risk_level in ['正常', '低风险'] and attack_type in ['无攻击', '正常访问', '分析异常']
                
                if not is_safe:
                    suspicious_logs.append(result)

                entry_model = LogEntry.query.get(entry.get('entry_id'))
                if entry_model:
                    entry_model.is_analyzed = True
                    
            except Exception as e:
                error_msg = str(e)
                print(f"\n{'='*80}")
                print(f"[ERROR] 分析第 {i+1} 条日志失败")
                print(f"{'='*80}")
                print(f"错误信息: {error_msg}")
                print(f"{'='*80}\n")
                
                # ⚠️ 如果是 LLM API 调用失败，立即终止并返回错误
                if 'LLM API 调用失败' in error_msg or 'API Key' in error_msg:
                    return jsonify({
                        'success': False,
                        'error': f'❌ LLM API 调用失败（第 {i+1} 条日志）：{error_msg}'
                    }), 500
                
                # 其他错误继续处理下一条
                continue

        db.session.commit()
        
        # 计算安全日志数。
        analyzed_count = total_logs
        safe_count = max(analyzed_count - len(suspicious_logs), 0)

        # 打印返回结果统计
        print(f"[DEBUG] 分析完成 - analysis_type: {analysis_type}")
        print(f"[DEBUG] 总日志: {total_logs}, 已分析: {analyzed_count}, 可疑: {len(suspicious_logs)}, 安全: {safe_count}")
        if suspicious_logs:
            print(f"[DEBUG] 攻击类型示例: {suspicious_logs[0].get('attack_type', 'N/A')}")
        print(f"[DEBUG] ==================== 分析结束 ====================")

        return jsonify({
            'success': True,
            'total_logs': total_logs,
            'analyzed_count': analyzed_count,
            'suspicious_count': len(suspicious_logs),
            'safe_count': safe_count,
            'suspicious_logs': suspicious_logs,
            'risk_stats': risk_stats,
            'pre_screen_stats': pre_screen_stats,
            'thinking_mode': {
                'enabled': thinking_enabled if model_type == 'deepseek' else False,
                'effort': reasoning_effort if model_type == 'deepseek' else None
            },
            'analysis_type': analysis_type,
            'model_type': model_type,
            'message': '分析完成'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
