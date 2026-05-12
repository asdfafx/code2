#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
为地理分析生成测试数据
包含真实地理位置的IP地址
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, LogImport, LogEntry
from datetime import datetime, timedelta
import random

def generate_geo_test_data():
    """生成带地理位置的测试数据"""
    app = create_app()
    
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        if not user:
            print("❌ 找不到 admin 用户")
            return
        
        # 检查是否已有足够数据
        existing_count = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == user.user_id
        ).count()
        
        if existing_count > 200:
            print(f"✅ 已有 {existing_count} 条日志")
        
        print(f"📊 当前日志数: {existing_count}，开始生成地理测试数据...")
        
        # 创建导入记录
        log_import = LogImport(
            user_id=user.user_id,
            filename='geo_test.log',
            log_format='apache',
            total_lines=150,
            parsed_lines=150,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(log_import)
        db.session.flush()
        
        # 真实的IP地址及其大概位置
        geo_ips = [
            ('203.0.113.42', '美国', '加利福尼亚', '洛杉矶'),
            ('198.51.100.23', '中国', '北京', '北京'),
            ('192.0.2.100', '日本', '东京', '东京'),
            ('198.51.100.50', '德国', '柏林', '柏林'),
            ('203.0.113.75', '英国', '伦敦', '伦敦'),
            ('192.0.2.150', '法国', '巴黎', '巴黎'),
            ('198.51.100.80', '澳大利亚', '悉尼', '悉尼'),
            ('203.0.113.120', '加拿大', '多伦多', '多伦多'),
            ('192.0.2.200', '巴西', '圣保罗', '圣保罗'),
            ('198.51.100.120', '印度', '孟买', '孟买'),
        ]
        
        urls_normal = ['/index.html', '/api/users', '/login', '/dashboard']
        urls_attack = [
            "/search?q=1' OR '1'='1",
            "/page?content=<script>alert('xss')</script>",
            "/files/../../../etc/passwd",
        ]
        
        for i in range(150):
            ip_info = random.choice(geo_ips)
            ip = ip_info[0]
            
            # 60% 正常，40% 攻击
            if random.random() < 0.6:
                url = random.choice(urls_normal)
                risk_score = random.randint(0, 15)
                keywords = ''
            else:
                url = random.choice(urls_attack)
                risk_score = random.randint(25, 85)
                keywords = random.choice(['sqli', 'xss', 'traversal'])
            
            entry = LogEntry(
                import_id=log_import.import_id,
                ip_address=ip,
                request_time=datetime.now() - timedelta(hours=random.randint(0, 168)),
                method=random.choice(['GET', 'POST']),
                url=url,
                parameters='',
                status_code=random.choice([200, 200, 404, 500]),
                response_size=random.randint(100, 50000),
                user_agent='Mozilla/5.0',
                raw_log=f'{ip} - - [{datetime.now()}] "GET {url} HTTP/1.1"',
                initial_risk_score=risk_score,
                risk_keywords=keywords,
                is_analyzed=False
            )
            db.session.add(entry)
        
        db.session.commit()
        print(f"✅ 成功生成 150 条带地理位置的测试日志")
        
        total = LogEntry.query.join(LogImport).filter(
            LogImport.user_id == user.user_id
        ).count()
        print(f"📊 总日志数: {total}")
        print(f"\n💡 现在刷新页面，点击「地理分析」查看地图分布")

if __name__ == '__main__':
    generate_geo_test_data()
