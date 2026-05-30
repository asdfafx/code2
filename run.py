#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志可疑行为分析系统 - 启动脚本

职责：
1. 加载本地环境变量；
2. 创建 Flask/SocketIO 应用；
3. 初始化数据库、默认管理员和默认模型配置；
4. 启动开发服务器。
"""
import os
import sys

# 加载 .env 文件中的环境变量
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
        print(f"✅ 已加载环境变量文件: {env_path}")
    else:
        print(f"⚠️  未找到 .env 文件: {env_path}")
except ImportError:
    print("⚠️  未安装 python-dotenv，跳过 .env 文件加载")

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db, socketio
from app.models import User, LLMModel


def create_admin_user():
    """确保系统存在默认管理员账号，便于首次启动后登录后台。"""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✓ 管理员账号已创建 (用户名：admin, 密码：admin123)")
    else:
        print("✓ 管理员账号已存在")


def create_default_model():
    """确保数据库中存在一条默认 LLM 模型配置。"""
    model = LLMModel.query.first()
    if not model:
        model = LLMModel(
            model_name='qwen:7b',
            api_endpoint='http://localhost:11434',
            max_tokens=512,
            temperature=0.7,
            is_active=True
        )
        db.session.add(model)
        db.session.commit()
        print("✓ 默认 LLM 模型配置已创建")
    else:
        print("✓ LLM 模型配置已存在")


if __name__ == '__main__':
    # 从环境变量获取配置，默认为 development
    config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    # 创建 Flask 应用
    app = create_app(config_name)
    
    # 初始化数据库必须放在应用上下文中，否则 Flask-SQLAlchemy 无法定位当前应用。
    with app.app_context():
        print("正在初始化数据库...")
        db.create_all()
        create_admin_user()
        create_default_model()
        print("✓ 数据库初始化完成")
    
    # 确保上传目录存在
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    
    # 确保 session 目录存在
    session_dir = app.config.get('SESSION_FILE_DIR')
    if session_dir:
        os.makedirs(session_dir, exist_ok=True)
    
    print("\n" + "="*50)
    print("🚀 日志可疑行为分析系统启动成功！")
    print("="*50)
    print(f"\n访问地址：http://localhost:8081")
    print(f"管理员账号：admin / admin123")
    print(f"上传目录：{upload_folder}")
    print("\n按 Ctrl+C 停止服务\n")
    
    # 使用 SocketIO 启动服务，兼容普通 HTTP 路由和 WebSocket 实时推送。
    socketio.run(
        app,
        host='0.0.0.0',
        port=8081,
        debug=app.config['DEBUG'],
        allow_unsafe_werkzeug=True
    )
