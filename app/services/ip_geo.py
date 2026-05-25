# IP 地理位置服务
import requests
from functools import lru_cache


class IPGeoService:
    """IP 地理位置查询服务"""
    
    def __init__(self):
        # 使用免费的 IP 地理位置 API
        self.api_urls = [
            'https://ipapi.co/{ip}/json/',
            'http://ip-api.com/json/{ip}',
        ]
        
        # 中国地区特殊处理（使用国内 API）
        self.cn_api_url = 'https://sp0.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query={ip}&co=&resource_id=6006&ie=utf8&oe=gbk&cb=op_aladdin_callback&format=json&tn=baidu&cb=jQuery11020123456789_1234567890&_=1234567890'
        
        # 缓存查询结果
        self.cache = {}
    
    @lru_cache(maxsize=1000)
    def query_ip_location(self, ip_address):
        """
        查询 IP 地址的地理位置
        
        Args:
            ip_address: IP 地址字符串
            
        Returns:
            dict: 包含地理位置信息的字典
        """
        # 检查缓存
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        # 本地地址
        if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
            result = {
                'ip': ip_address,
                'country': '本地网络',
                'region': '内网',
                'city': '局域网',
                'latitude': 0,
                'longitude': 0,
                'is_private': True
            }
            self.cache[ip_address] = result
            return result
        
        try:
            # 尝试使用百度 API（对中国 IP 更准确）
            result = self._query_baidu_api(ip_address)
            if result:
                self.cache[ip_address] = result
                return result
            
            # 降级到国际 API
            result = self._query_international_api(ip_address)
            if result:
                self.cache[ip_address] = result
                return result
            
        except Exception as e:
            print(f"IP 地理位置查询失败 {ip_address}: {str(e)}")
        
        # 返回默认值
        result = {
            'ip': ip_address,
            'country': '未知',
            'region': '未知',
            'city': '未知',
            'latitude': None,
            'longitude': None,
            'is_private': False
        }
        
        self.cache[ip_address] = result
        return result
    
    def _query_baidu_api(self, ip_address):
        """使用百度 API 查询（对中国 IP 更准确）"""
        try:
            url = f'https://sp0.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query={ip_address}&co=&resource_id=6006&ie=utf8&oe=gbk&format=json'
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '0' and data.get('data'):
                    location_data = data['data'][0]
                    location = location_data.get('location', '')
                    
                    # 解析位置信息
                    parts = location.split()
                    country = parts[0] if len(parts) > 0 else '中国'
                    province = parts[1] if len(parts) > 1 else ''
                    city = parts[2] if len(parts) > 2 else ''
                    
                    return {
                        'ip': ip_address,
                        'country': country,
                        'region': province,
                        'city': city,
                        'latitude': None,  # 百度 API 不提供经纬度
                        'longitude': None,
                        'is_private': False,
                        'source': 'baidu'
                    }
        except:
            pass
        
        return None
    
    def _query_international_api(self, ip_address):
        """使用国际 API 查询"""
        try:
            # 尝试 ipapi.co
            url = f'https://ipapi.co/{ip_address}/json/'
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip_address,
                    'country': data.get('country_name', '未知'),
                    'region': data.get('region', '未知'),
                    'city': data.get('city', '未知'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'is_private': False,
                    'source': 'ipapi'
                }
        except:
            pass
        
        try:
            # 尝试 ip-api.com
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip_address,
                        'country': data.get('country', '未知'),
                        'region': data.get('regionName', '未知'),
                        'city': data.get('city', '未知'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'is_private': False,
                        'source': 'ip-api'
                    }
        except:
            pass
        
        return None
    
    def get_ip_stats(self, entries):
        """
        统计多个 IP 的地理位置分布
        
        Args:
            entries: 日志条目列表
            
        Returns:
            dict: 地理位置统计信息
        """
        location_stats = {}
        
        for entry in entries:
            ip = entry.ip_address if hasattr(entry, 'ip_address') else entry.get('ip_address')
            if not ip:
                continue
            
            location = self.query_ip_location(ip)
            country = location['country']
            
            if country not in location_stats:
                location_stats[country] = {
                    'count': 0,
                    'ips': set(),
                    'cities': set(),
                    'attacks': 0
                }
            
            location_stats[country]['count'] += 1
            location_stats[country]['ips'].add(ip)
            
            if location['city'] and location['city'] != '未知':
                location_stats[country]['cities'].add(location['city'])
            
            # 统计攻击次数
            if hasattr(entry, 'initial_risk_score') and entry.initial_risk_score > 20:
                location_stats[country]['attacks'] += 1
            elif isinstance(entry, dict) and entry.get('initial_risk_score', 0) > 20:
                location_stats[country]['attacks'] += 1
        
        # 转换 set 为 list 以便 JSON 序列化
        result = {}
        for country, stats in location_stats.items():
            result[country] = {
                'count': stats['count'],
                'unique_ips': len(stats['ips']),
                'cities': list(stats['cities'])[:10],  # 最多 10 个城市
                'attacks': stats['attacks'],
                'attack_rate': round(stats['attacks'] / stats['count'] * 100, 2) if stats['count'] > 0 else 0
            }
        
        return result
    
    def detect_anonymous_regions(self, entries, threshold=30):
        """
        检测异常地区访问
        
        Args:
            entries: 日志条目列表
            threshold: 异常阈值（攻击率百分比）
            
        Returns:
            list: 异常地区列表
        """
        stats = self.get_ip_stats(entries)
        anomalies = []
        
        for country, data in stats.items():
            if data['attack_rate'] > threshold and data['attacks'] > 5:
                anomalies.append({
                    'country': country,
                    'attack_rate': data['attack_rate'],
                    'total_requests': data['count'],
                    'attacks': data['attacks'],
                    'unique_ips': data['unique_ips'],
                    'severity': 'high' if data['attack_rate'] > 50 else 'medium'
                })
        
        # 按攻击率排序
        anomalies.sort(key=lambda x: x['attack_rate'], reverse=True)
        
        return anomalies


# 创建全局实例
ip_geo_service = IPGeoService()
