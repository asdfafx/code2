# -*- coding: utf-8 -*-
"""
为各个分析模块生成测试日志数据
包含: SQL注入、XSS攻击、流式分析、地理分析、行为时间线
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, LogImport, LogEntry
from datetime import datetime, timedelta
import random

def generate_all_test_data():
    """生成所有模块的测试数据"""
    app = create_app()
    
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        if not user:
            user = User.query.filter_by(username='testuser').first()
        if not user:
            print("❌ 找不到用户，请先创建用户")
            return
        
        print(f"✅ 找到用户: {user.username}\n")
        
        # ========== 1. SQL注入攻击日志 ==========
        print("📊 生成 SQL 注入攻击日志...")
        sql_import = LogImport(
            user_id=user.user_id,
            filename='sql_injection_test.log',
            log_format='nginx',
            total_lines=30,
            parsed_lines=30,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(sql_import)
        db.session.flush()
        
        sql_payloads = [
            ("id=1 UNION SELECT username,password FROM users--", "高危联合查询注入"),
            ("id=1' OR '1'='1", "中危布尔注入"),
            ("id=1; DROP TABLE users--", "高危堆叠注入"),
            ("username=admin'--&password=anything", "高危认证绕过"),
            ("id=1 AND 1=2 UNION SELECT NULL--", "中危盲注测试"),
            ("search=1' WAITFOR DELAY '00:00:05'--", "中危时间盲注"),
            ("id=1' AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>64--", "高危报错注入"),
            ("q=1' UNION SELECT NULL,NULL,NULL--", "中危联合注入探测"),
            ("id=9999999 UNION SELECT version()--", "中危信息收集"),
            ("id=1' OR EXISTS(SELECT * FROM users)--", "中危布尔盲注"),
        ]
        
        for i, (payload, desc) in enumerate(sql_payloads):
            base_time = datetime.now() - timedelta(hours=random.randint(1, 24))
            entry = LogEntry(
                import_id=sql_import.import_id,
                ip_address=f"192.168.1.{100 + i}",
                request_time=base_time,
                method='POST',
                url='/login.php',
                parameters=f"username=admin&password={payload}",
                status_code=200 if i % 3 == 0 else 403,
                response_size=random.randint(500, 5000),
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.7',
                referer='https://google.com',
                raw_log=f'192.168.1.{100+i} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "POST /login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
                initial_risk_score=random.randint(70, 95),
                risk_keywords='sqli,' + desc,
                is_analyzed=False
            )
            db.session.add(entry)
        db.session.commit()
        print(f"✅ SQL注入日志: 30条")
        
        # ========== 2. XSS攻击日志 ==========
        print("📊 生成 XSS 攻击日志...")
        xss_import = LogImport(
            user_id=user.user_id,
            filename='xss_attack_test.log',
            log_format='nginx',
            total_lines=25,
            parsed_lines=25,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(xss_import)
        db.session.flush()
        
        xss_payloads = [
            ("<script>alert('XSS')</script>", "高危存储型XSS"),
            ("<img src=x onerror=alert(1)>", "高危事件型XSS"),
            ("<svg/onload=alert('XSS')>", "高危SVG XSS"),
            ("javascript:alert('XSS')", "中危协议型XSS"),
            ("<iframe src='javascript:alert(1)'>", "高危iframe注入"),
            ("<body onload=alert('XSS')>", "高危事件触发XSS"),
            ("'><script>alert(String.fromCharCode(88,83,83))</script>", "高危绕过型XSS"),
            ("<script>eval(atob('YWxlcnQoMSk='))</script>", "高危编码混淆XSS"),
            ("<a href='javascript:alert(1)'>click</a>", "中危链接XSS"),
            ("<div onmouseover='alert(1)'>hover</div>", "中危事件XSS"),
        ]
        
        user_agents = [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ]
        
        for i, (payload, desc) in enumerate(xss_payloads):
            base_time = datetime.now() - timedelta(hours=random.randint(1, 12))
            entry = LogEntry(
                import_id=xss_import.import_id,
                ip_address=f"10.0.0.{50 + i}",
                request_time=base_time,
                method='GET',
                url='/search.php',
                parameters=f"q={payload}",
                status_code=200,
                response_size=random.randint(1000, 8000),
                user_agent=random.choice(user_agents),
                referer='/index.html',
                raw_log=f'10.0.0.{50+i} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "GET /search.php?q={payload} HTTP/1.1" 200 2345 "-" "Chrome/90"',
                initial_risk_score=random.randint(60, 90),
                risk_keywords='xss,' + desc,
                is_analyzed=False
            )
            db.session.add(entry)
        db.session.commit()
        print(f"✅ XSS攻击日志: 25条")
        
        # ========== 3. 流式分析日志 ==========
        print("📊 生成 流式分析 日志...")
        stream_import = LogImport(
            user_id=user.user_id,
            filename='streaming_test.log',
            log_format='nginx',
            total_lines=50,
            parsed_lines=50,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(stream_import)
        db.session.flush()
        
        attack_patterns = [
            'sql_injection_pattern',
            'xss_pattern', 
            'brute_force_pattern',
            'normal_pattern',
            'directory_traversal_pattern'
        ]
        
        for i in range(50):
            base_time = datetime.now() - timedelta(minutes=random.randint(1, 60))
            pattern = random.choice(attack_patterns)
            
            if pattern == 'sql_injection_pattern':
                url = '/api/user'
                params = f"id=1' UNION SELECT NULL--"
                risk_score = random.randint(70, 95)
            elif pattern == 'xss_pattern':
                url = '/comment'
                params = f"text=<script>alert(1)</script>"
                risk_score = random.randint(65, 88)
            elif pattern == 'brute_force_pattern':
                url = '/login'
                params = f"pwd={random.choice(['admin', '123456', 'password', 'letmein'])}"
                risk_score = random.randint(50, 75)
            elif pattern == 'directory_traversal_pattern':
                url = '/download'
                params = "file=../../../etc/passwd"
                risk_score = random.randint(75, 90)
            else:
                url = f'/page/{random.randint(1, 20)}'
                params = ""
                risk_score = random.randint(0, 20)
            
            entry = LogEntry(
                import_id=stream_import.import_id,
                ip_address=f"172.16.0.{random.randint(1, 50)}",
                request_time=base_time,
                method='POST' if 'login' in url else 'GET',
                url=url,
                parameters=params,
                status_code=random.choice([200, 200, 403, 404]),
                response_size=random.randint(200, 10000),
                user_agent='Mozilla/5.0 (compatible; Googlebot/2.1)',
                referer='https://www.google.com',
                raw_log=f'172.16.0.{random.randint(1,50)} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "GET {url} HTTP/1.1" 200 1234',
                initial_risk_score=risk_score,
                risk_keywords=pattern,
                is_analyzed=False
            )
            db.session.add(entry)
        db.session.commit()
        print(f"✅ 流式分析日志: 50条")
        
        # ========== 4. 地理分析日志 ==========
        print("📊 生成 地理分析 日志...")
        geo_import = LogImport(
            user_id=user.user_id,
            filename='geo_analysis_test.log',
            log_format='nginx',
            total_lines=100,
            parsed_lines=100,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(geo_import)
        db.session.flush()
        
        geo_ips = [
            ('203.0.113.42', '美国', '加利福尼亚', '洛杉矶'),
            ('198.51.100.23', '中国', '北京', '北京'),
            ('192.0.2.100', '日本', '东京', '东京'),
            ('198.51.100.50', '德国', '柏林', '柏林'),
            ('203.0.113.75', '英国', '伦敦', '伦敦'),
            ('192.0.2.150', '法国', '巴黎', '巴黎'),
            ('198.51.100.80', '澳大利亚', '悉尼', '悉尼'),
            ('203.0.113.120', '俄罗斯', '莫斯科', '莫斯科'),
            ('192.0.2.200', '巴西', '圣保罗', '圣保罗'),
            ('198.51.100.120', '印度', '孟买', '孟买'),
            ('203.0.113.200', '韩国', '首尔', '首尔'),
            ('192.0.2.180', '加拿大', '多伦多', '多伦多'),
        ]
        
        for i in range(100):
            ip_info = random.choice(geo_ips)
            base_time = datetime.now() - timedelta(hours=random.randint(0, 72))
            
            is_attack = random.random() < 0.35
            if is_attack:
                attack_type = random.choice(['sql_injection', 'xss', 'traversal'])
                risk_score = random.randint(60, 95)
            else:
                attack_type = 'normal'
                risk_score = random.randint(0, 25)
            
            entry = LogEntry(
                import_id=geo_import.import_id,
                ip_address=ip_info[0],
                request_time=base_time,
                method=random.choice(['GET', 'POST']),
                url=random.choice(['/index.html', '/api/users', '/login', '/search']),
                parameters='',
                status_code=200 if not is_attack else random.choice([200, 403, 404]),
                response_size=random.randint(100, 50000),
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                referer='https://google.com',
                raw_log=f'{ip_info[0]} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "GET /index.html HTTP/1.1" 200 2048',
                initial_risk_score=risk_score,
                risk_keywords=attack_type,
                is_analyzed=False
            )
            db.session.add(entry)
        db.session.commit()
        print(f"✅ 地理分析日志: 100条")
        
        # ========== 5. 行为时间线日志 ==========
        print("📊 生成 行为时间线 日志...")
        timeline_import = LogImport(
            user_id=user.user_id,
            filename='timeline_behavior_test.log',
            log_format='nginx',
            total_lines=80,
            parsed_lines=80,
            import_time=datetime.now(),
            status='completed'
        )
        db.session.add(timeline_import)
        db.session.flush()
        
        # 模拟一个攻击者的完整攻击过程
        attacker_ip = '45.33.32.156'  # 模拟攻击者IP
        base_time = datetime.now() - timedelta(days=2)
        
        behavior_sequence = [
            (0, 'GET', '/', 200, 0, 'normal', '初始探测'),
            (1, 'GET', '/robots.txt', 404, 5, 'normal', '信息收集'),
            (2, 'GET', '/admin', 403, 10, 'normal', '后台探测'),
            (3, 'GET', '/login.php', 200, 15, 'normal', '访问登录页'),
            (4, 'POST', '/login.php', 200, 20, 'brute_force', '暴力破解开始'),
            (5, 'POST', '/login.php', 403, 25, 'brute_force', '暴力破解尝试'),
            (6, 'POST', '/login.php', 403, 30, 'brute_force', '暴力破解尝试'),
            (7, 'POST', '/login.php', 403, 35, 'brute_force', '暴力破解尝试'),
            (8, 'GET', '/search?q=1%27%20OR%20%271%27%3D%271', 200, 40, 'sql_injection', 'SQL注入尝试'),
            (9, 'GET', '/search?q=1%27%20UNION%20SELECT%20NULL--', 200, 45, 'sql_injection', '联合注入探测'),
            (10, 'GET', '/page?id=<script>alert(1)</script>', 200, 50, 'xss', 'XSS尝试'),
            (11, 'GET', '/download?file=../../../etc/passwd', 403, 55, 'directory_traversal', '目录遍历'),
            (12, 'GET', '/wp-admin', 302, 60, 'normal', 'CMS后台探测'),
            (13, 'GET', '/phpmyadmin', 404, 65, 'normal', '管理后台探测'),
            (14, 'POST', '/upload.php', 403, 70, 'normal', '上传尝试'),
        ]
        
        for (offset_min, method, url, status, risk, attack_type, desc) in behavior_sequence:
            entry_time = base_time + timedelta(minutes=offset_min)
            entry = LogEntry(
                import_id=timeline_import.import_id,
                ip_address=attacker_ip,
                request_time=entry_time,
                method=method,
                url=url,
                parameters='',
                status_code=status,
                response_size=random.randint(500, 5000),
                user_agent='Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101',
                referer='https://www.google.com',
                raw_log=f'{attacker_ip} - - [{entry_time.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "{method} {url} HTTP/1.1" {status} 1234',
                initial_risk_score=risk,
                risk_keywords=attack_type,
                is_analyzed=False
            )
            db.session.add(entry)
        
        # 添加更多正常用户行为
        for i in range(65):
            base = datetime.now() - timedelta(hours=random.randint(0, 48))
            entry = LogEntry(
                import_id=timeline_import.import_id,
                ip_address=f"{random.randint(10, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                request_time=base,
                method=random.choice(['GET', 'POST']),
                url=random.choice(['/index.html', '/about', '/contact', '/products']),
                parameters='',
                status_code=200,
                response_size=random.randint(1000, 10000),
                user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                referer=random.choice(['https://google.com', 'https://baidu.com', '']),
                raw_log=f'192.168.1.{i} - - [{base.strftime("%d/%b/%Y:%H:%M:%S +0800")}] "GET /index.html HTTP/1.1" 200 2048',
                initial_risk_score=random.randint(0, 15),
                risk_keywords='normal',
                is_analyzed=False
            )
            db.session.add(entry)
        
        db.session.commit()
        print(f"✅ 行为时间线日志: 80条")
        
        # ========== 统计 ==========
        total = LogEntry.query.count()
        print(f"\n{'='*50}")
        print(f"✅ 测试数据生成完成!")
        print(f"📊 总日志数: {total}")
        print(f"{'='*50}")
        print(f"\n💡 可用分析模块:")
        print(f"   1. SQL注入分析 (30条)")
        print(f"   2. XSS攻击分析 (25条)")
        print(f"   3. 流式分析 (50条)")
        print(f"   4. 地理分析 (100条)")
        print(f"   5. 行为时间线 (80条)")

if __name__ == '__main__':
    generate_all_test_data()
