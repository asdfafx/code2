# 项目配置文件
"""集中管理 Flask 应用的运行配置。

本文件只放环境、数据库、会话、上传、LLM 和安全阈值等配置项，
业务逻辑应放在 routes 或 services 中，避免配置层产生副作用。
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """所有环境共享的基础配置。"""

    # 密钥配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    
    # 数据库配置（使用 SQLite 简化部署）
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'log_analysis.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # 会话配置
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(basedir, 'flask_session')  # Session 文件存储目录
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # 生产环境设为 True
    SESSION_COOKIE_SAMESITE = 'Lax'  # 添加 SameSite 配置，允许同站请求携带 cookie
    
    # 文件上传配置
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'txt', 'log'}
    
    # LLM 服务配置（默认使用阿里云百炼）
    LLM_API_ENDPOINT = os.environ.get('LLM_API_URL') or 'https://dashscope.aliyuncs.com/api/v1'
    LLM_MODEL_NAME = os.environ.get('LLM_MODEL') or 'qwen-plus'
    LLM_MAX_TOKENS = 512
    LLM_TEMPERATURE = 0.5
    LLM_TIMEOUT = 180
    
    # DeepSeek API Key
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY') or ''
    
    # 阿里云百炼 API Key（备用）
    DASHSCOPE_API_KEY = os.environ.get('DASHSCOPE_API_KEY') or ''
    
    # 分页配置
    LOGS_PER_PAGE = 20
    RESULTS_PER_PAGE = 15
    
    # 安全配置
    PASSWORD_MIN_LENGTH = 6
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300  # 5 分钟
    
    # 初筛规则配置
    RISK_THRESHOLD_LOW = 20
    RISK_THRESHOLD_MEDIUM = 40
    RISK_THRESHOLD_HIGH = 60
    
    @staticmethod
    def init_app(app):
        """预留环境初始化钩子，子类可在这里挂载日志或监控配置。"""
        pass


class DevelopmentConfig(Config):
    """开发环境配置：打开调试和 SQL 输出，方便本地排查问题。"""

    DEBUG = True
    SQLALCHEMY_ECHO = True


class TestingConfig(Config):
    """测试配置"""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False  # 禁用 CSRF 保护用于测试
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    """生产环境配置：关闭调试，并要求 Session Cookie 走 HTTPS。"""

    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_ECHO = False


# 根据 FLASK_CONFIG 名称选择配置类；default 指向开发配置，便于本地直接运行。
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
