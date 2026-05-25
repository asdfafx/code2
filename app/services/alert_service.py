# 告警通知服务
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class AlertService:
    """告警通知服务"""
    
    def __init__(self, config=None):
        self.config = config or {}
        
    def send_email_alert(self, subject, message, recipients):
        """发送电子邮件告警"""
        try:
            smtp_server = self.config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = self.config.get('smtp_port', 587)
            sender_email = self.config.get('sender_email', '')
            sender_password = self.config.get('sender_password', '')
            
            if not sender_email or not sender_password:
                print("警告: 未配置邮件发送者信息")
                return False
            
            # 创建邮件
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[日志分析系统告警] {subject}"
            
            body = f"""
            <html>
            <body>
                <h2>日志分析系统告警通知</h2>
                <p><strong>时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>主题:</strong> {subject}</p>
                <hr>
                <p>{message}</p>
                <hr>
                <p style="color: #999; font-size: 12px;">
                    此邮件由日志分析系统自动发送，请勿回复。
                </p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # 发送邮件
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipients, text)
            server.quit()
            
            print(f"邮件告警已发送至: {recipients}")
            return True
            
        except Exception as e:
            print(f"发送邮件告警失败: {e}")
            return False
    
    def send_sms_alert(self, message, phone_numbers):
        """发送短信告警（使用阿里云短信服务作为示例）"""
        try:
            # 这里以阿里云短信服务为例，实际使用时需要替换为真实的API
            access_key_id = self.config.get('aliyun_access_key_id', '')
            access_key_secret = self.config.get('aliyun_access_key_secret', '')
            sign_name = self.config.get('aliyun_sign_name', '')
            template_code = self.config.get('aliyun_template_code', '')
            
            if not access_key_id or not access_key_secret:
                print("警告: 未配置阿里云短信服务信息")
                return False
            
            # 实际的阿里云短信API调用代码
            # 这里只是示例，需要根据实际情况调整
            for phone in phone_numbers:
                # 调用阿里云短信API
                response = self._send_aliyun_sms(
                    access_key_id, 
                    access_key_secret, 
                    phone, 
                    sign_name, 
                    template_code, 
                    {'message': message}
                )
                
                if response:
                    print(f"短信告警已发送至: {phone}")
                else:
                    print(f"短信告警发送失败: {phone}")
            
            return True
            
        except Exception as e:
            print(f"发送短信告警失败: {e}")
            return False
    
    def _send_aliyun_sms(self, access_key_id, access_key_secret, phone, sign_name, template_code, template_param):
        """发送阿里云短信（示例实现）"""
        # 这里需要使用阿里云SDK
        # 由于这是一个示例，我们只返回True表示成功
        # 在实际部署时，需要安装 aliyun-python-sdk-core 和 aliyun-python-sdk-dysmsapi
        message = template_param.get('message', '')
        print(f"模拟发送短信到 {phone}: {message}")
        return True
    
    def send_webhook_alert(self, webhook_url, payload):
        """发送Webhook告警"""
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"Webhook告警已发送至: {webhook_url}")
                return True
            else:
                print(f"Webhook告警发送失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"发送Webhook告警失败: {e}")
            return False
    
    def send_high_risk_alert(self, log_entry, analysis_result, notification_config):
        """发送高风险告警"""
        try:
            risk_level = analysis_result.get('risk_level', 'unknown')
            attack_type = analysis_result.get('attack_type', 'unknown')
            ip_address = log_entry.get('ip_address', 'unknown')
            url = log_entry.get('url', 'unknown')
            
            subject = f"检测到{risk_level}风险 - {attack_type}"
            message = f"""
            <h3>高风险行为检测告警</h3>
            <ul>
                <li><strong>风险等级:</strong> {risk_level}</li>
                <li><strong>攻击类型:</strong> {attack_type}</li>
                <li><strong>IP地址:</strong> {ip_address}</li>
                <li><strong>请求URL:</strong> {url}</li>
                <li><strong>检测时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
            </ul>
            <p>请立即检查相关日志并采取适当的安全措施。</p>
            """
            
            # 发送邮件告警
            if notification_config.get('email_enabled', False):
                email_recipients = notification_config.get('email_recipients', [])
                if email_recipients:
                    self.send_email_alert(subject, message, email_recipients)
            
            # 发送短信告警
            if notification_config.get('sms_enabled', False):
                phone_numbers = notification_config.get('phone_numbers', [])
                if phone_numbers:
                    sms_message = f"日志分析系统告警: 检测到{risk_level}风险 - {attack_type}，来自IP: {ip_address}"
                    self.send_sms_alert(sms_message, phone_numbers)
            
            # 发送Webhook告警
            if notification_config.get('webhook_enabled', False):
                webhook_url = notification_config.get('webhook_url', '')
                if webhook_url:
                    payload = {
                        'alert_type': 'high_risk_detection',
                        'risk_level': risk_level,
                        'attack_type': attack_type,
                        'ip_address': ip_address,
                        'url': url,
                        'timestamp': datetime.now().isoformat(),
                        'message': f"检测到{risk_level}风险 - {attack_type}"
                    }
                    self.send_webhook_alert(webhook_url, payload)
            
            return True
            
        except Exception as e:
            print(f"发送高风险告警失败: {e}")
            return False


# 全局实例
alert_service = AlertService()
