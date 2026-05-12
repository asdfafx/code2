# 项目初始化文件
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO

# 初始化扩展
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
socketio = SocketIO(cors_allowed_origins="*")

# 设置登录视图
login_manager.login_view = 'auth.login'
login_manager.login_message = '请先登录以访问该页面'


def create_app(config_name='default'):
    """应用工厂函数"""
    app = Flask(__name__)
    
    # 加载配置
    from config import config
    app.config.from_object(config[config_name])
    
    # 初始化扩展
    db.init_app(app)
    login_manager.init_app(app)
    
    # 根据配置决定是否启用 CSRF（开发环境也禁用以简化测试）
    if app.config.get('ENABLE_CSRF', False):
        csrf.init_app(app)
    
    socketio.init_app(app)
    
    # 初始化 Session
    Session(app)
    
    # 确保 session 目录存在
    session_dir = app.config.get('SESSION_FILE_DIR')
    if session_dir and not os.path.exists(session_dir):
        os.makedirs(session_dir, exist_ok=True)
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
    
    # 注册蓝图
    from .routes import auth, logs, analysis, export, admin, geo, timeline, ml, websocket, alerts, stream, multi_model
    app.register_blueprint(auth.bp, url_prefix='/api/auth')
    app.register_blueprint(logs.bp, url_prefix='/api/logs')
    app.register_blueprint(analysis.bp, url_prefix='/api/analysis')
    app.register_blueprint(export.bp, url_prefix='/api/export')
    app.register_blueprint(admin.bp, url_prefix='/api/admin')
    app.register_blueprint(geo.bp, url_prefix='/api/geo')
    app.register_blueprint(timeline.bp, url_prefix='/api/timeline')
    app.register_blueprint(ml.bp, url_prefix='/api/ml')
    app.register_blueprint(websocket.bp)
    app.register_blueprint(alerts.bp, url_prefix='/api/alerts')
    app.register_blueprint(stream.bp, url_prefix='/api/stream')
    app.register_blueprint(multi_model.bp, url_prefix='/api/multi-model')
    
    # 注册主页面路由
    @app.route('/')
    def index():
        from flask import redirect
        return redirect('/login')
    
    @app.route('/login')
    def login_page():
        from flask import render_template
        return render_template('login.html')
    
    @app.route('/dashboard')
    def dashboard():
        from flask import render_template
        return render_template('dashboard.html')
    
    # 独立功能页面路由
    @app.route('/import')
    def import_page():
        from flask import render_template
        return render_template('import.html')
    
    @app.route('/analyze')
    def analyze_page():
        from flask import render_template
        return render_template('analyze.html')
    
    @app.route('/stream')
    def stream_page():
        from flask import render_template
        return render_template('stream.html')
    
    @app.route('/geo')
    def geo_page():
        from flask import render_template
        return render_template('geo.html')
    
    @app.route('/timeline')
    def timeline_page():
        from flask import render_template
        return render_template('timeline.html')
    
    @app.route('/realtime')
    def realtime_page():
        from flask import render_template
        return render_template('realtime.html')
    
    @app.route('/export')
    def export_page():
        from flask import render_template
        return render_template('export.html')
    
    @app.route('/profile')
    def profile_page():
        from flask import render_template
        return render_template('profile.html')
    
    @app.route('/admin')
    def admin_page():
        from flask import render_template
        return render_template('admin.html')
    
    @app.route('/favicon.ico')
    def favicon():
        from flask import send_from_directory
        try:
            return send_from_directory(
                app.static_folder,
                'favicon.ico',
                mimetype='image/x-icon'
            )
        except:
            # 如果没有favicon文件，返回空响应
            from flask import Response
            return Response('', status=204)
    
    return app
