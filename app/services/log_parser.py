# 日志解析服务
import re
from datetime import datetime
from app.models import LogEntry, LogImport


class LogParser:
    """日志解析器"""
    
    # Apache Common Log Format
    APACHE_PATTERN = re.compile(
        r'^(\S+)\s+'           # IP 地址
        r'(\S+)\s+'            # 标识符
        r'(\S+)\s+'            # 用户
        r'\[([^\]]+)\]\s+'     # 时间
        r'"(\S+)\s+'           # 请求方法
        r'([^"]*)\s+'          # URL
        r'([^"]*)"\s+'         # 协议
        r'(\d{3})\s+'          # 状态码
        r'(\d+|-)'             # 响应大小
    )
    
    # Nginx Combined Log Format
    NGINX_PATTERN = re.compile(
        r'^(\S+)\s+-\s+'       # IP 地址
        r'(\S+)\s+'            # 用户
        r'\[([^\]]+)\]\s+'     # 时间
        r'"(\S+)\s+'           # 请求方法
        r'([^"]*)\s+'          # URL
        r'([^"]*)"\s+'         # 协议
        r'(\d{3})\s+'          # 状态码
        r'(\d+)\s+'            # 响应大小
        r'"([^"]*)"\s+'        # Referer
        r'"([^"]*)"'           # User-Agent
    )
    
    def __init__(self):
        self.parsed_count = 0
        self.failed_count = 0
    
    def parse_line(self, line, log_format='apache'):
        """解析单行日志"""
        line = line.strip()
        if not line:
            return None
        
        try:
            if log_format == 'apache':
                return self._parse_apache(line)
            elif log_format == 'nginx':
                return self._parse_nginx(line)
            else:
                return self._parse_custom(line)
        except Exception as e:
            self.failed_count += 1
            return None
    
    def _parse_apache(self, line):
        """解析 Apache 格式日志"""
        match = self.APACHE_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groups()
        
        # 解析时间
        try:
            request_time = datetime.strptime(groups[3], '%d/%b/%Y:%H:%M:%S %z')
        except:
            request_time = datetime.now()
        
        # 解析 URL 和参数
        url_parts = groups[5].split('?', 1)
        url = url_parts[0]
        parameters = url_parts[1] if len(url_parts) > 1 else ''
        
        return {
            'ip_address': groups[0],
            'request_time': request_time,
            'method': groups[4],
            'url': url,
            'parameters': parameters,
            'protocol': groups[6],
            'status_code': int(groups[7]),
            'response_size': int(groups[8]) if groups[8] != '-' else 0,
            'raw_log': line
        }
    
    def _parse_nginx(self, line):
        """解析 Nginx 格式日志"""
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groups()
        
        # 解析时间
        try:
            request_time = datetime.strptime(groups[2], '%d/%b/%Y:%H:%M:%S %z')
        except:
            request_time = datetime.now()
        
        # 解析 URL 和参数
        url_parts = groups[5].split('?', 1)
        url = url_parts[0]
        parameters = url_parts[1] if len(url_parts) > 1 else ''
        
        return {
            'ip_address': groups[0],
            'user': groups[1],
            'request_time': request_time,
            'method': groups[3],
            'url': url,
            'parameters': parameters,
            'protocol': groups[6],
            'status_code': int(groups[7]),
            'response_size': int(groups[8]),
            'referer': groups[9],
            'user_agent': groups[10],
            'raw_log': line
        }
    
    def _parse_custom(self, line):
        """解析自定义格式日志（简单分割）"""
        parts = line.split()
        if len(parts) < 7:
            return None
        
        return {
            'ip_address': parts[0],
            'request_time': datetime.now(),
            'method': parts[1] if len(parts) > 1 else '',
            'url': parts[2] if len(parts) > 2 else '',
            'parameters': '',
            'status_code': int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
            'response_size': int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
            'user_agent': ' '.join(parts[5:]) if len(parts) > 5 else '',
            'raw_log': line
        }
    
    def parse_file(self, file_path, log_format='apache'):
        """解析日志文件"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed_data = self.parse_line(line, log_format)
                    if parsed_data:
                        entries.append(parsed_data)
                        self.parsed_count += 1
            
            return entries
        except Exception as e:
            raise Exception(f"读取文件失败：{str(e)}")
    
    def parse_text(self, text, log_format='apache'):
        """解析日志文本"""
        entries = []
        lines = text.split('\n')
        
        for line in lines:
            parsed_data = self.parse_line(line, log_format)
            if parsed_data:
                entries.append(parsed_data)
                self.parsed_count += 1
        
        return entries
    
    def create_entries(self, import_record, entries_data):
        """批量创建日志条目"""
        batch_entries = []
        
        for data in entries_data:
            entry = LogEntry(
                import_id=import_record.import_id,
                ip_address=data.get('ip_address', ''),
                request_time=data.get('request_time'),
                method=data.get('method', ''),
                url=data.get('url', ''),
                parameters=data.get('parameters', ''),
                status_code=data.get('status_code', 0),
                response_size=data.get('response_size', 0),
                user_agent=data.get('user_agent', ''),
                raw_log=data.get('raw_log', '')
            )
            batch_entries.append(entry)
        
        # 批量插入
        if batch_entries:
            from app import db
            db.session.bulk_save_objects(batch_entries)
            db.session.commit()
        
        return len(batch_entries)
