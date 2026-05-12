# 数据库模型定义
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from flask_login import UserMixin


class User(UserMixin, db.Model):
    """用户模型"""
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, index=True)
    role = db.Column(db.Enum('admin', 'user'), default='user')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # 关联关系
    log_imports = db.relationship('LogImport', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        """设置密码"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """转换为字典"""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,  # 添加 is_active 字段
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
        }


class LogImport(db.Model):
    """日志导入记录模型"""
    __tablename__ = 'log_imports'

    import_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    log_format = db.Column(db.Enum('apache', 'nginx', 'custom'), default='apache')
    total_lines = db.Column(db.Integer, default=0)
    parsed_lines = db.Column(db.Integer, default=0)
    import_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    file_path = db.Column(db.String(500))
    status = db.Column(db.Enum('processing', 'completed', 'failed'), default='processing')

    # 关联关系
    entries = db.relationship('LogEntry', backref='import_record', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        """转换为字典"""
        return {
            'import_id': self.import_id,
            'filename': self.filename,
            'log_format': self.log_format,
            'total_lines': self.total_lines,
            'parsed_lines': self.parsed_lines,
            'import_time': self.import_time.strftime('%Y-%m-%d %H:%M:%S') if self.import_time else None,
            'status': self.status
        }


class LogEntry(db.Model):
    """日志条目模型"""
    __tablename__ = 'log_entries'

    entry_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    import_id = db.Column(db.Integer, db.ForeignKey('log_imports.import_id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    request_time = db.Column(db.DateTime, index=True)
    method = db.Column(db.String(10))
    url = db.Column(db.Text)
    parameters = db.Column(db.Text)
    status_code = db.Column(db.Integer)
    response_size = db.Column(db.Integer)
    user_agent = db.Column(db.Text)
    referer = db.Column(db.Text)
    raw_log = db.Column(db.Text)
    initial_risk_score = db.Column(db.Integer, default=0, index=True)
    risk_keywords = db.Column(db.Text)
    is_analyzed = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # 关联关系
    analysis_result = db.relationship('AnalysisResult', backref='log_entry', uselist=False, cascade='all, delete-orphan')

    def to_dict(self):
        """转换为字典"""
        return {
            'entry_id': self.entry_id,
            'ip_address': self.ip_address,
            'request_time': self.request_time.strftime('%Y-%m-%d %H:%M:%S') if self.request_time else None,
            'method': self.method,
            'url': self.url,
            'parameters': self.parameters,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'initial_risk_score': self.initial_risk_score,
            'is_analyzed': self.is_analyzed
        }


class AnalysisResult(db.Model):
    """分析结果模型"""
    __tablename__ = 'analysis_results'

    result_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    entry_id = db.Column(db.Integer, db.ForeignKey('log_entries.entry_id'), nullable=False, index=True)  # 添加外键约束
    filename = db.Column(db.String(255), index=True)  # 文件名
    attack_type = db.Column(db.String(50), index=True)
    risk_level = db.Column(db.String(20), default='正常', index=True)  # 存储中文：正常/低风险/中风险/高风险/严重风险
    llm_conclusion = db.Column(db.Text)
    analysis_reason = db.Column(db.Text)
    confidence_score = db.Column(db.Numeric(3, 2))
    analysis_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    prompt_template = db.Column(db.Text)
    llm_response_raw = db.Column(db.Text)
    model_id = db.Column(db.Integer)

    def to_dict(self):
        """转换为字典"""
        return {
            'result_id': self.result_id,
            'entry_id': self.entry_id,  # 使用 result_id 填充
            'filename': self.filename,
            'attack_type': self.attack_type,
            'risk_level': self.risk_level,
            'llm_conclusion': self.llm_conclusion,
            'analysis_reason': self.analysis_reason,
            'confidence_score': float(self.confidence_score) if self.confidence_score else None,
            'analysis_time': self.analysis_time.strftime('%Y-%m-%d %H:%M:%S') if self.analysis_time else None,
            'llm_response_raw': self.llm_response_raw,  # LLM 原始响应
            'prompt_template': self.prompt_template  # 提示词模板
        }


class LLMModel(db.Model):
    """LLM 模型配置模型"""
    __tablename__ = 'llm_models'

    model_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    model_name = db.Column(db.String(100), nullable=False)
    model_path = db.Column(db.String(500))
    api_endpoint = db.Column(db.String(255))
    api_key = db.Column(db.String(255))
    secret_key = db.Column(db.String(255))
    max_tokens = db.Column(db.Integer, default=512)
    temperature = db.Column(db.Numeric(3, 2), default=0.70)
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """转换为字典"""
        return {
            'model_id': self.model_id,
            'model_name': self.model_name,
            'api_endpoint': self.api_endpoint,
            'max_tokens': self.max_tokens,
            'temperature': float(self.temperature) if self.temperature else None,
            'is_active': self.is_active
        }


@login_manager.user_loader
def load_user(user_id):
    """加载用户"""
    return User.query.get(int(user_id))
