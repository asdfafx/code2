# Celery 异步任务配置
from celery import Celery
from flask import current_app


def make_celery(app=None):
    """创建 Celery 实例"""
    celery = Celery('log_analysis')
    
    if app:
        celery.conf.update({
            'task_serializer': 'json',
            'accept_content': ['json'],
            'result_serializer': 'json',
            'timezone': 'Asia/Shanghai',
            'enable_utc': True,
            'task_track_started': True,
            'task_time_limit': 30 * 60,  # 30分钟超时
            'worker_prefetch_multiplier': 1,
        })
        
        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)
        
        celery.Task = ContextTask
    
    return celery


# 创建全局 Celery 实例
celery = make_celery()


@celery.task(bind=True)
def analyze_log_entry(self, log_data, risk_keywords, config, filename=None):
    """异步分析单个日志条目"""
    from app.services.llm_service import LLMService
    from app import db
    from app.models import AnalysisResult
    
    try:
        # 打印初始数据库状态
        print(f"\n{'#'*80}")
        print(f"[tasks.py] 开始分析")
        print(f"{'#'*80}")
        before_count = AnalysisResult.query.count()
        print(f"  分析前 analysis_results 表记录数: {before_count}")
        print(f"{'#'*80}\n")
        
        # 初始化 LLM 服务
        llm_service = LLMService(
            api_endpoint=config['api_endpoint'],
            model_name=config['model_name'],
            max_tokens=config['max_tokens'],
            temperature=config['temperature'],
            timeout=config['timeout'],
            api_key=config.get('api_key')
        )
        
        # 调用 LLM 分析（会在内部保存结果到数据库）
        analysis_result = llm_service.analyze(log_data, risk_keywords, 'general', filename)
        
        # 打印 LLM 返回的原始结果
        print(f"\n{'*'*80}")
        print(f"[tasks.py] LLM返回结果")
        print(f"{'*'*80}")
        print(f"  LLM返回的原始结果: {analysis_result}")
        print(f"  所有字段: {list(analysis_result.keys()) if isinstance(analysis_result, dict) else 'Not a dict'}")
        print(f"{'*'*80}\n")
        
        # 获取刚插入的结果ID
        result = AnalysisResult.query.order_by(AnalysisResult.result_id.desc()).first()
        result_id = result.result_id if result else None
        
        return {
            'status': 'success',
            'result_id': result_id
        }
        
    except Exception as e:
        db.session.rollback()
        import traceback
        print(f'分析失败: {str(e)}')
        print(traceback.format_exc())
        return {
            'status': 'failed',
            'error': str(e)
        }


@celery.task(bind=True)
def batch_analyze_logs(self, log_entries, config):
    """批量异步分析日志"""
    from app.services.llm_service import LLMService
    from app import db
    from app.models import AnalysisResult
    
    total = len(log_entries)
    completed = 0
    failed = 0
    results = []
    
    for log_entry in log_entries:
        try:
            # 准备日志数据和文件名
            log_data = {
                'ip_address': log_entry.get('ip_address'),
                'request_time': log_entry.get('request_time'),
                'method': log_entry.get('method'),
                'url': log_entry.get('url'),
                'parameters': log_entry.get('parameters'),
                'status_code': log_entry.get('status_code'),
                'response_size': log_entry.get('response_size'),
                'user_agent': log_entry.get('user_agent'),
                'raw_log': log_entry.get('raw_log'),
                'initial_risk_score': log_entry.get('initial_risk_score', 0)
            }
            
            filename = log_entry.get('filename', '未知文件')
            risk_keywords = log_entry.get('risk_keywords', [])
            
            # 调用单个分析任务
            result = analyze_log_entry.apply_async(
                args=[log_data, risk_keywords, config, filename]
            )
            results.append(result.id)
            
            completed += 1
            
            # 更新进度
            self.update_state(
                state='PROGRESS',
                meta={'current': completed, 'total': total}
            )
            
        except Exception as e:
            failed += 1
            continue
    
    return {
        'status': 'completed',
        'total': total,
        'completed': completed,
        'failed': failed,
        'results': results
    }
