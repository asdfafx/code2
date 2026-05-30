# 数据库初始化脚本
"""手动初始化数据库测试数据。

该脚本用于开发或演示环境，向数据库写入一个普通用户、一次日志导入、
多条可疑/正常日志以及对应的模拟分析结果。生产环境不要直接运行。
"""
import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User, LogImport, LogEntry, AnalysisResult
from datetime import datetime


def create_test_data():
    """创建一组覆盖常见攻击类型的测试数据。"""
    print("正在创建测试数据...")
    
    # 创建测试用户
    test_user = User.query.filter_by(username='testuser').first()
    if not test_user:
        test_user = User(
            username='testuser',
            email='test@example.com',
            role='user'
        )
        test_user.set_password('test123')
        db.session.add(test_user)
        db.session.commit()
        print("✓ 测试用户已创建 (用户名：testuser, 密码：test123)")
    
    # 创建测试日志导入
    test_import = LogImport(
        user_id=test_user.user_id,
        filename='test_apache.log',
        log_format='apache',
        total_lines=5,
        parsed_lines=5,
        status='completed'
    )
    db.session.add(test_import)
    db.session.commit()
    
    # 创建测试日志条目：既包含 SQL 注入、XSS、目录遍历等攻击样例，也保留一条正常访问作对照。
    test_logs = [
        {
            'ip_address': '192.168.1.100',
            'request_time': datetime.now(),
            'method': 'GET',
            'url': '/news.php',
            'parameters': "id=1 UNION SELECT username,password FROM users--",
            'status_code': 200,
            'response_size': 1234,
            'raw_log': '192.168.1.100 - - [10/Oct/2023:13:55:36 +0800] "GET /news.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200 1234'
        },
        {
            'ip_address': '192.168.1.101',
            'request_time': datetime.now(),
            'method': 'GET',
            'url': '/search.php',
            'parameters': "q=<script>alert('XSS')</script>",
            'status_code': 200,
            'response_size': 567,
            'raw_log': '192.168.1.101 - - [10/Oct/2023:14:00:00 +0800] "GET /search.php?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 567'
        },
        {
            'ip_address': '192.168.1.102',
            'request_time': datetime.now(),
            'method': 'GET',
            'url': '/files.php',
            'parameters': "path=../../../etc/passwd",
            'status_code': 403,
            'response_size': 234,
            'raw_log': '192.168.1.102 - - [10/Oct/2023:14:05:00 +0800] "GET /files.php?path=../../../etc/passwd HTTP/1.1" 403 234'
        },
        {
            'ip_address': '192.168.1.103',
            'request_time': datetime.now(),
            'method': 'POST',
            'url': '/login.php',
            'parameters': "username=admin&password=' OR '1'='1",
            'status_code': 200,
            'response_size': 890,
            'raw_log': '192.168.1.103 - - [10/Oct/2023:14:10:00 +0800] "POST /login.php?username=admin&password=\' OR \'1\'=\'1 HTTP/1.1" 200 890'
        },
        {
            'ip_address': '192.168.1.104',
            'request_time': datetime.now(),
            'method': 'GET',
            'url': '/index.html',
            'parameters': '',
            'status_code': 200,
            'response_size': 2048,
            'raw_log': '192.168.1.104 - - [10/Oct/2023:14:15:00 +0800] "GET /index.html HTTP/1.1" 200 2048'
        }
    ]
    
    for log_data in test_logs:
        entry = LogEntry(
            import_id=test_import.import_id,
            **log_data
        )
        db.session.add(entry)
    
    db.session.commit()
    print(f"✓ 已创建 {len(test_logs)} 条测试日志记录")
    
    # 创建模拟分析结果，使前端统计、导出和详情页面无需真实调用 LLM 也能展示数据。
    analysis_results = [
        {
            'entry_id': 1,
            'attack_type': 'SQL 注入',
            'risk_level': '高风险',
            'llm_conclusion': '检测到联合查询 SQL 注入攻击',
            'analysis_reason': '请求参数中包含 UNION SELECT 语句，试图从 users 表窃取用户名和密码字段，属于典型的 SQL 注入攻击手法。',
            'confidence_score': 0.95
        },
        {
            'entry_id': 2,
            'attack_type': 'XSS',
            'risk_level': '高风险',
            'llm_conclusion': '检测到反射型 XSS 攻击',
            'analysis_reason': '搜索参数中包含<script>标签和 alert 函数调用，试图在用户浏览器中执行恶意 JavaScript 代码。',
            'confidence_score': 0.92
        },
        {
            'entry_id': 3,
            'attack_type': '目录遍历',
            'risk_level': '中风险',
            'llm_conclusion': '检测到目录遍历攻击尝试',
            'analysis_reason': '路径参数中使用多个../试图访问 Web 根目录之外的系统文件/etc/passwd。',
            'confidence_score': 0.88
        },
        {
            'entry_id': 4,
            'attack_type': 'SQL 注入',
            'risk_level': '高风险',
            'llm_conclusion': '检测到认证绕过 SQL 注入',
            'analysis_reason': '密码字段包含 OR \'1\'=\'1 永真条件，试图绕过登录验证，属于布尔盲注类型。',
            'confidence_score': 0.90
        },
        {
            'entry_id': 5,
            'attack_type': '无攻击',
            'risk_level': '低风险',
            'llm_conclusion': '正常请求',
            'analysis_reason': '请求为普通的 HTML 页面访问，不包含任何恶意 payload 或异常特征。',
            'confidence_score': 0.98
        }
    ]
    
    for result_data in analysis_results:
        result = AnalysisResult(
            **result_data,
            analysis_time=datetime.now()
        )
        db.session.add(result)
    
    db.session.commit()
    print(f"✓ 已创建 {len(analysis_results)} 条测试分析结果")
    
    print("\n✓ 测试数据创建完成！")
    print("\n测试账号:")
    print("  - 管理员：admin / admin123")
    print("  - 普通用户：testuser / test123")


if __name__ == '__main__':
    # 脚本直接执行时创建 Flask 应用上下文，保证 SQLAlchemy 会话可用。
    app = create_app()
    
    with app.app_context():
        create_test_data()
