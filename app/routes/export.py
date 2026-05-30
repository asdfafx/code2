# 导出服务路由
"""分析结果导出接口，支持 CSV、HTML 和 JSON。"""
import io
import csv
import json
from flask import Blueprint, request, jsonify, session, send_file
from app import csrf
from app.models import AnalysisResult, LogEntry, LogImport
from functools import wraps
from datetime import datetime

bp = Blueprint('export', __name__)

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


@bp.route('/csv', methods=['POST'])
@login_required
def export_csv():
    """导出指定导入批次的分析结果为 CSV 文件。"""
    try:
        data = request.get_json() or {}
        import_id = data.get('import_id')
        
        # 如果没有提供 import_id，则默认导出当前用户最后一次导入的检测记录。
        if not import_id:
            last_import = LogImport.query.filter_by(
                user_id=session['user_id']
            ).order_by(LogImport.import_time.desc()).first()
            
            if not last_import:
                return jsonify({'error': '没有找到检测记录'}), 404
            
            import_id = last_import.import_id
        
        # 构建查询
        query = AnalysisResult.query.join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            LogEntry.import_id == import_id
        )
        
        results = query.all()
        
        # 创建 CSV，使用 utf-8-sig 方便 Excel 正确识别中文。
        output = io.StringIO()
        writer = csv.writer(output)
        
        # 写入表头
        writer.writerow([
            'IP 地址',
            '请求时间',
            '请求方法',
            'URL',
            '参数',
            '攻击类型',
            '风险等级',
            '分析结论',
            '分析理由',
            '置信度',
            '分析时间'
        ])
        
        # 写入数据
        for result in results:
            entry = result.log_entry
            writer.writerow([
                entry.ip_address,
                entry.request_time.strftime('%Y-%m-%d %H:%M:%S') if entry.request_time else '',
                entry.method or '',
                entry.url or '',
                entry.parameters or '',
                result.attack_type or '',
                result.risk_level or '',
                result.llm_conclusion or '',
                result.analysis_reason or '',
                float(result.confidence_score) if result.confidence_score else '',
                result.analysis_time.strftime('%Y-%m-%d %H:%M:%S') if result.analysis_time else ''
            ])
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'analysis_report_{timestamp}.csv'
        
        # 创建 BytesIO 用于发送
        bytes_output = io.BytesIO()
        bytes_output.write(output.getvalue().encode('utf-8-sig'))
        bytes_output.seek(0)
        
        return send_file(
            bytes_output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/html', methods=['POST'])
@login_required
def export_html():
    """导出带统计摘要和明细表格的 HTML 报告。"""
    try:
        data = request.get_json() or {}
        import_id = data.get('import_id')
        
        # 如果没有提供 import_id，则获取最后一次导入的记录
        if not import_id:
            last_import = LogImport.query.filter_by(
                user_id=session['user_id']
            ).order_by(LogImport.import_time.desc()).first()
            
            if not last_import:
                return jsonify({'error': '没有找到检测记录'}), 404
            
            import_id = last_import.import_id
        
        # 获取统计数据
        query = AnalysisResult.query.join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            LogEntry.import_id == import_id
        )
        
        results = query.all()
        
        # 统计信息用于报告顶部的摘要卡片。
        total = len(results)
        high_risk = sum(1 for r in results if r.risk_level in ['高风险', '严重风险'])
        medium_risk = sum(1 for r in results if r.risk_level == '中风险')
        low_risk = sum(1 for r in results if r.risk_level == '正常')
        
        attack_types = {}
        for result in results:
            attack_type = result.attack_type or '未知'
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        # 生成 HTML 字符串并以附件形式返回给浏览器下载。
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>日志安全分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .stat-box {{ display: inline-block; margin: 10px; padding: 15px; background: white; border: 1px solid #ddd; border-radius: 5px; min-width: 150px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #2196F3; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #2196F3; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .risk-high {{ color: #f44336; font-weight: bold; }}
        .risk-medium {{ color: #ff9800; }}
        .risk-low {{ color: #4caf50; }}
        .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>📊 日志安全分析报告</h1>
    <p>生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>总体统计</h2>
        <div class="stat-box">
            <div class="stat-number">{total}</div>
            <div class="stat-label">总记录数</div>
        </div>
        <div class="stat-box">
            <div class="stat-number" style="color: #f44336;">{high_risk}</div>
            <div class="stat-label">高风险</div>
        </div>
        <div class="stat-box">
            <div class="stat-number" style="color: #ff9800;">{medium_risk}</div>
            <div class="stat-label">中风险</div>
        </div>
        <div class="stat-box">
            <div class="stat-number" style="color: #4caf50;">{low_risk}</div>
            <div class="stat-label">正常</div>
        </div>
    </div>
    
    <h2>攻击类型分布</h2>
    <table>
        <tr>
            <th>攻击类型</th>
            <th>数量</th>
            <th>占比</th>
        </tr>
"""
        
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            html_content += f"""        <tr>
            <td>{attack_type}</td>
            <td>{count}</td>
            <td>{percentage:.1f}%</td>
        </tr>
"""
        
        html_content += """    </table>
    
    <h2>详细分析结果</h2>
    <table>
        <tr>
            <th>IP 地址</th>
            <th>时间</th>
            <th>请求</th>
            <th>攻击类型</th>
            <th>风险等级</th>
            <th>结论</th>
        </tr>
"""
        
        for result in results[:100]:  # 限制显示 100 条
            entry = result.log_entry
            risk_class = f"risk-{result.risk_level}" if result.risk_level else ""
            html_content += f"""        <tr>
            <td>{entry.ip_address}</td>
            <td>{entry.request_time.strftime('%Y-%m-%d %H:%M') if entry.request_time else ''}</td>
            <td>{entry.method} {entry.url[:50]}{'...' if len(entry.url or '') > 50 else ''}</td>
            <td>{result.attack_type or '未知'}</td>
            <td class="{risk_class}">{result.risk_level or 'unknown'}</td>
            <td>{result.llm_conclusion[:50] if result.llm_conclusion else ''}{'...' if len(result.llm_conclusion or '') > 50 else ''}</td>
        </tr>
"""
        
        html_content += f"""    </table>
    
    <div class="footer">
        <p>本报告由日志可疑行为分析系统自动生成 | 共 {total} 条记录</p>
    </div>
</body>
</html>
"""
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'analysis_report_{timestamp}.html'
        
        return send_file(
            io.BytesIO(html_content.encode('utf-8')),
            mimetype='text/html',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/json', methods=['POST'])
@login_required
def export_json():
    """导出结构化 JSON，便于二次处理或对接其他系统。"""
    try:
        data = request.get_json() or {}
        import_id = data.get('import_id')
        
        # 如果没有提供 import_id，则获取最后一次导入的记录
        if not import_id:
            last_import = LogImport.query.filter_by(
                user_id=session['user_id']
            ).order_by(LogImport.import_time.desc()).first()
            
            if not last_import:
                return jsonify({'error': '没有找到检测记录'}), 404
            
            import_id = last_import.import_id
        
        # 构建查询
        query = AnalysisResult.query.join(LogEntry).join(LogImport).filter(
            LogImport.user_id == session['user_id'],
            LogEntry.import_id == import_id
        )
        
        results = query.all()
        
        # 构建 JSON 数据，包含导入批次信息和所有分析结果。
        export_data = {
            'export_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'import_info': None,
            'total_records': len(results),
            'results': []
        }
        
        # 获取导入信息
        log_import = LogImport.query.get(import_id)
        if log_import:
            export_data['import_info'] = {
                'filename': log_import.filename,
                'import_time': log_import.import_time.strftime('%Y-%m-%d %H:%M:%S') if log_import.import_time else None,
                'total_lines': log_import.total_lines,
                'parsed_lines': log_import.parsed_lines
            }
        
        # 添加分析结果
        for result in results:
            entry = result.log_entry
            export_data['results'].append({
                'ip_address': entry.ip_address,
                'request_time': entry.request_time.strftime('%Y-%m-%d %H:%M:%S') if entry.request_time else None,
                'method': entry.method,
                'url': entry.url,
                'parameters': entry.parameters,
                'attack_type': result.attack_type,
                'risk_level': result.risk_level,
                'llm_conclusion': result.llm_conclusion,
                'analysis_reason': result.analysis_reason,
                'confidence_score': float(result.confidence_score) if result.confidence_score else None,
                'analysis_time': result.analysis_time.strftime('%Y-%m-%d %H:%M:%S') if result.analysis_time else None
            })
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'analysis_report_{timestamp}.json'
        
        # 创建 JSON 文件
        json_content = json.dumps(export_data, ensure_ascii=False, indent=2)
        
        return send_file(
            io.BytesIO(json_content.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
