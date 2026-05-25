# 分析结果路由
from flask import Blueprint, request, jsonify, session, current_app
from app import db, csrf
from app.models import LogEntry, AnalysisResult, LogImport
from app.services.llm_service import LLMService
from app.security import security
from functools import wraps

bp = Blueprint('analysis', __name__)

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


@bp.route('/start', methods=['POST'])
@login_required
@security.rate_limit(max_requests=10, window=600)  # 10分钟最多10次分析任务
def start_analysis():
    """开始分析任务"""
    try:
        data = request.get_json()
        import_id = data.get('import_id')
        
        # 构建查询 - 获取当前用户的所有日志
        query = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        )
        
        # 如果指定了 import_id，只分析该导入的日志
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        
        # 只分析未分析的或高风险的条目
        entries = query.filter(
            (LogEntry.is_analyzed == False) | (LogEntry.initial_risk_score >= 20)
        ).all()
        
        if not entries:
            return jsonify({
                'message': '没有需要分析的日志',
                'analyzed_count': 0
            })
        
        # 初始化 LLM 服务
        llm_service = LLMService(
            api_endpoint=current_app.config['LLM_API_ENDPOINT'],
            model_name=current_app.config['LLM_MODEL_NAME'],
            max_tokens=current_app.config['LLM_MAX_TOKENS'],
            temperature=float(current_app.config['LLM_TEMPERATURE']),
            timeout=current_app.config['LLM_TIMEOUT'],
            api_key=current_app.config.get('DEEPSEEK_API_KEY') or current_app.config.get('DASHSCOPE_API_KEY')
        )
        
        analyzed_count = 0
        results = []
        
        for entry in entries:
            try:
                # 准备日志数据
                log_data = {
                    'entry_id': entry.entry_id,  # 添加 entry_id
                    'import_id': entry.import_id,  # 添加 import_id
                    'ip_address': entry.ip_address,
                    'request_time': entry.request_time,
                    'method': entry.method,
                    'url': entry.url,
                    'parameters': entry.parameters,
                    'status_code': entry.status_code,
                    'response_size': entry.response_size,
                    'user_agent': entry.user_agent,
                    'raw_log': entry.raw_log,
                    'initial_risk_score': entry.initial_risk_score
                }
                
                # 获取风险关键词
                risk_keywords = entry.risk_keywords.split(',') if entry.risk_keywords else []
                
                # 获取文件名
                filename = entry.import_record.filename if entry.import_record else '未知文件'
                
                # 调用 LLM 分析（会在内部保存结果到数据库）
                analysis_result = llm_service.analyze(
                    log_data, 
                    risk_keywords,
                    'general',  # analysis_type
                    filename
                )
                
                # 分析结果已通过 llm_service.analyze() 保存到数据库
                # 标记为已分析
                entry.is_analyzed = True
                
                analyzed_count += 1
                
                results.append({
                    'risk_level': analysis_result.get('risk_level', '中风险'),
                    'attack_type': analysis_result.get('attack_type', '未知')
                })
                
            except Exception as e:
                # 单个条目分析失败，记录错误并继续处理下一个
                import traceback
                current_app.logger.error(f'分析失败: {str(e)}')
                current_app.logger.error(traceback.format_exc())
                print(f"\n❌ 分析失败: {str(e)}")
                print(traceback.format_exc())
                continue
        
        # 提交标记为已分析
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        
        return jsonify({
            'message': '分析完成',
            'analyzed_count': analyzed_count,
            'results': results[:20]  # 限制返回数量
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/results', methods=['GET'])
@login_required
def get_results():
    """获取分析结果"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 15, type=int)
        risk_level = request.args.get('risk_level', None)
        attack_type = request.args.get('attack_type', None)
        import_id = request.args.get('import_id', None)
        search = request.args.get('search', None)
        
        # 构建查询 - 通过 LogEntry 关联
        query = db.session.query(AnalysisResult, LogEntry).join(
            LogEntry,
            AnalysisResult.entry_id == LogEntry.entry_id
        ).join(
            LogImport,
            LogEntry.import_id == LogImport.import_id
        ).filter(
            LogImport.user_id == session['user_id']
        )
        
        # 筛选条件
        if risk_level:
            query = query.filter(AnalysisResult.risk_level == risk_level)
        if attack_type:
            query = query.filter(AnalysisResult.attack_type.like(f'%{attack_type}%'))
        if import_id:
            query = query.filter(LogEntry.import_id == import_id)
        if search:
            query = query.filter(
                db.or_(
                    LogEntry.ip_address.like(f'%{search}%'),
                    LogEntry.url.like(f'%{search}%')
                )
            )
        
        # 分页
        pagination = query.order_by(AnalysisResult.analysis_time.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        results = []
        for result, entry in pagination.items:
            result_dict = result.to_dict()
            result_dict['log_entry'] = entry.to_dict()
            results.append(result_dict)
        
        return jsonify({
            'results': results,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
        
    except Exception as e:
        current_app.logger.error(f'获取分析结果失败: {str(e)}')
        import traceback
        current_app.logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@bp.route('/stats', methods=['GET'])
@login_required
def get_statistics():
    """获取统计信息"""
    try:
        # 总日志数
        total_logs = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == session['user_id']
        ).count()
        
        # 已分析数（通过 AnalysisResult 表统计）
        analyzed_logs = db.session.query(db.func.count(AnalysisResult.result_id)).join(
            LogEntry
        ).join(
            LogImport
        ).filter(
            LogImport.user_id == session['user_id']
        ).scalar() or 0
        
        # 待分析数
        pending_analysis = total_logs - analyzed_logs
        
        # 按风险等级统计（包含所有等级：高风险、中风险、正常）
        risk_stats = db.session.query(
            AnalysisResult.risk_level,
            db.func.count(AnalysisResult.result_id)
        ).join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id']
        ).group_by(AnalysisResult.risk_level).all()
        
        # 按攻击类型统计（过滤掉 "none", "None", "无" 等无效值）
        attack_stats = db.session.query(
            AnalysisResult.attack_type,
            db.func.count(AnalysisResult.result_id)
        ).join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            AnalysisResult.attack_type.notin_(['none', 'None', '无', ''])
        ).group_by(AnalysisResult.attack_type).all()
        
        # 最近分析趋势（最近 7 天）
        from datetime import datetime, timedelta
        from datetime import timezone as dt_timezone
        seven_days_ago = datetime.now(dt_timezone.utc) - timedelta(days=7)
        trend_stats = db.session.query(
            db.func.date(AnalysisResult.analysis_time),
            db.func.count(AnalysisResult.result_id)
        ).join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            AnalysisResult.analysis_time >= seven_days_ago
        ).group_by(db.func.date(AnalysisResult.analysis_time)).all()
        
        # 转换为字典
        trend_dict = {str(date): count for date, count in trend_stats}
        
        # 生成完整的 7 天数据（包括没有数据的日期）
        trend = []
        for i in range(7):
            date = (datetime.now(dt_timezone.utc) - timedelta(days=6-i)).date()
            date_str = str(date)
            trend.append({
                'date': date_str,
                'count': trend_dict.get(date_str, 0)
            })
        
        return jsonify({
            'total_logs': total_logs,
            'analyzed_logs': analyzed_logs,
            'pending_analysis': pending_analysis,
            'risk_distribution': dict(risk_stats),
            'attack_distribution': dict(attack_stats),
            'trend': trend
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:result_id>', methods=['GET'])
@login_required
def get_result_detail(result_id):
    """获取分析结果详情"""
    try:
        result = AnalysisResult.query.join(LogEntry).join(LogImport).filter(
            AnalysisResult.result_id == result_id,
            LogImport.user_id == session['user_id']
        ).first_or_404()
        
        result_dict = result.to_dict()
        result_dict['log_entry'] = result.log_entry.to_dict()
        result_dict['log_entry']['raw_log'] = result.log_entry.raw_log
        
        return jsonify({'result': result_dict})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
