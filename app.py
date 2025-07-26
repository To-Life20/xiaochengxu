"""
基于Flask的轻量级用户管理系统
功能：
1. 用户登录/登出
2. 管理员账号管理
3. 权限控制（仅管理员可创建账号）
4. 命令行数据库操作
5. 显示当前登录状态
6. 显示用户密码明文（仅在创建时显示）
"""

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

# 初始化Flask应用
app = Flask(__name__)
# 生成随机密钥用于会话安全
app.config['SECRET_KEY'] = os.urandom(24)
# 配置SQLite数据库路径
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# 禁用SQLAlchemy事件系统，减少开销
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化SQLAlchemy数据库对象
db = SQLAlchemy(app)

# 定义初始管理员信息
INITIAL_ADMIN_USERNAME = "左左子"
INITIAL_ADMIN_PASSWORD = "1234abcd"

# 用户数据模型
class User(db.Model):
    # 用户ID（主键）
    id = db.Column(db.Integer, primary_key=True)
    # 用户名（唯一）
    username = db.Column(db.String(80), unique=True, nullable=False)
    # 密码哈希值
    password_hash = db.Column(db.String(120), nullable=False)
    # 管理员标志
    is_admin = db.Column(db.Boolean, default=False)
    # 账户激活状态
    is_active = db.Column(db.Boolean, default=True)
    # 是否为初始管理员
    is_initial_admin = db.Column(db.Boolean, default=False)

    # 设置密码（生成哈希值）
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 验证密码
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 将用户对象转换为字典（不包含密码信息）
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'is_active': self.is_active
        }

# 全局变量：当前登录的用户
current_cli_user = None

# 装饰器：确保函数在应用上下文中执行
def with_app_context(func):
    """确保函数在Flask应用上下文中执行的装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        with app.app_context():
            return func(*args, **kwargs)
    return wrapper

# 命令行工具函数 - 全部添加应用上下文
@with_app_context
def create_admin_cli():
    """创建管理员账号"""
    global current_cli_user

    # 检查当前用户是否为管理员
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    username = input("输入管理员用户名: ")
    password = input("输入管理员密码: ")

    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=username).first():
        print("错误：用户名已存在")
        return

    # 创建新管理员账号
    admin = User(username=username, is_admin=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"管理员账号 {username} 创建成功")
    print(f"密码: {password} (请妥善保存)")  # 显示明文密码

@with_app_context
def list_users_cli():
    """列出所有用户信息"""
    users = db.session.query(User).all()
    print("\n用户列表:")
    print("ID | 用户名 | 管理员 | 状态 | 初始管理员")
    print("-" * 70)
    for user in users:
        status = "激活" if user.is_active else "禁用"
        admin = "是" if user.is_admin else "否"
        initial_admin = "是" if user.is_initial_admin else "否"
        print(f"{user.id} | {user.username} | {admin} | {status} | {initial_admin}")
    print()

@with_app_context
def create_user_cli():
    """创建普通用户账号"""
    global current_cli_user

    # 检查当前用户是否为管理员
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    username = input("输入用户名: ")
    password = input("输入密码: ")
    is_admin = input("是否为管理员? (y/n): ").lower() == 'y'

    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=username).first():
        print("错误：用户名已存在")
        return

    # 创建新用户
    new_user = User(username=username, is_admin=is_admin)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    print(f"用户 {username} 创建成功")
    print(f"密码: {password} (请妥善保存)")  # 显示明文密码

@with_app_context
def cli_login():
    """命令行登录功能"""
    global current_cli_user

    username = input("用户名: ")
    password = input("密码: ")

    # 查询用户
    user = db.session.query(User).filter_by(username=username).first()

    if user and user.check_password(password) and user.is_active:
        current_cli_user = user
        print(f"登录成功！欢迎 {user.username}{' (管理员)' if user.is_admin else ''}")
    else:
        print("登录失败：用户名或密码错误，或账户已禁用")

def cli_logout():
    """命令行登出功能"""
    global current_cli_user
    if current_cli_user:
        print(f"用户 {current_cli_user.username} 已登出")
        current_cli_user = None
    else:
        print("当前没有登录的用户")

@with_app_context
def clear_database():
    """清空数据库（危险操作）"""
    global current_cli_user

    # 检查管理员权限
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    # 确认操作
    confirm = input("警告：这将删除所有用户数据（初始管理员除外）！确认操作?(y/n): ").lower()
    if confirm != 'y':
        print("操作已取消")
        return

    # 删除所有非初始管理员用户
    try:
        num_deleted = db.session.query(User).filter(User.is_initial_admin == False).delete()
        db.session.commit()
        print(f"数据库已清空，删除了 {num_deleted} 个用户（初始管理员保留）")
    except Exception as e:
        db.session.rollback()
        print(f"清空数据库失败: {str(e)}")

@with_app_context
def delete_user_cli():
    """删除用户"""
    global current_cli_user

    # 检查管理员权限
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    list_users_cli()
    user_id = input("输入要删除的用户ID: ")

    if not user_id.isdigit():
        print("无效的用户ID")
        return

    # 使用新的 Session.get() 方法替代弃用的 Query.get()
    user = db.session.get(User, int(user_id))

    if not user:
        print("未找到用户")
        return

    # 防止删除初始管理员
    if user.is_initial_admin:
        print("错误：不能删除初始管理员账户")
        return

    confirm = input(f"确认删除用户 {user.username}? (y/n): ").lower()
    if confirm != 'y':
        print("操作已取消")
        return

    db.session.delete(user)
    db.session.commit()
    print(f"用户 {user.username} 已删除")

# API权限检查装饰器
def admin_required(fn):
    """检查API请求是否具有管理员权限"""
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        # 获取HTTP Basic Auth认证信息
        auth = request.authorization
        if not auth:
            return jsonify({"error": "需要认证"}), 401

        # 验证用户名和密码
        user = db.session.query(User).filter_by(username=auth.username).first()
        if not user or not user.check_password(auth.password):
            return jsonify({"error": "无效的凭证"}), 401

        # 检查管理员权限
        if not user.is_admin:
            return jsonify({"error": "需要管理员权限"}), 403

        # 执行被装饰的函数
        return fn(*args, **kwargs)
    return decorated_function

# API端点
@app.route('/api/login', methods=['POST'], endpoint='api_login')
def login():
    """用户登录API"""
    data = request.get_json()
    # 查询用户
    user = db.session.query(User).filter_by(username=data.get('username')).first()

    # 验证用户凭据
    if user and user.check_password(data.get('password')):
        return jsonify({
            "message": "登录成功",
            "user": user.to_dict()
        })
    return jsonify({"error": "无效的用户名或密码"}), 401

@app.route('/api/users', methods=['POST'], endpoint='api_create_user')
@admin_required
def create_user():
    """创建新用户API（仅管理员）"""
    data = request.get_json()
    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=data['username']).first():
        return jsonify({"error": "用户名已存在"}), 400

    # 创建新用户
    new_user = User(
        username=data['username'],
        is_admin=data.get('is_admin', False)
    )
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()

    # 在响应中包含明文密码（仅创建时显示）
    return jsonify({
        "message": "用户创建成功",
        "user": new_user.to_dict(),
        "password": data['password']  # 仅创建时显示明文密码
    }), 201

@app.route('/api/users', methods=['GET'], endpoint='api_list_users')
@admin_required
def list_users():
    """列出所有用户API（仅管理员）"""
    users = db.session.query(User).all()
    return jsonify({
        "users": [user.to_dict() for user in users]
    })


# 初始化数据库
@with_app_context
def init_db():
    """初始化数据库（创建表结构）并添加初始管理员"""
    # 检查表是否已存在
    inspector = db.inspect(db.engine)
    table_exists = inspector.has_table("user")

    # 如果表不存在，则创建
    if not table_exists:
        db.create_all()
        print("已创建数据库表")
    else:
        print("数据库表已存在，跳过创建")

    # 检查初始管理员是否存在
    admin_user = db.session.query(User).filter_by(username=INITIAL_ADMIN_USERNAME).first()

    if not admin_user:
        # 创建初始管理员
        admin_user = User(
            username=INITIAL_ADMIN_USERNAME,
            is_admin=True,
            is_active=True,
            is_initial_admin=True
        )
        admin_user.set_password(INITIAL_ADMIN_PASSWORD)
        db.session.add(admin_user)
        db.session.commit()
        print(f"初始管理员 '{INITIAL_ADMIN_USERNAME}' 已创建")
        print(f"密码: {INITIAL_ADMIN_PASSWORD} (请妥善保存)")
    else:
        print(f"初始管理员 '{INITIAL_ADMIN_USERNAME}' 已存在")

    print("数据库初始化完成")

# 命令行界面
def cli_interface():
    """主命令行界面"""
    global current_cli_user

    # 自动初始化数据库
    init_db()

    while True:
        print("\n" + "=" * 50)
        # 显示当前登录状态
        if current_cli_user:
            user_info = f"当前用户: {current_cli_user.username}{' (管理员)' if current_cli_user.is_admin else ''}"
            print(user_info)
            print("-" * len(user_info))

        print("用户管理系统命令行工具")
        print("1. 登录账号")

        # 根据登录状态显示不同选项
        if current_cli_user:
            print("2. 登出账号")
            if current_cli_user.is_admin:
                print("3. 创建管理员账号")
                print("4. 创建普通用户")
                print("5. 删除用户")
            print("6. 列出所有用户")
            if current_cli_user.is_admin:
                print("7. 清空数据库")
            print("8. 退出")
        else:
            print("2. 退出")

        choice = input("请选择操作: ")

        # 处理用户选择
        if choice == '1':
            cli_login()
        elif choice == '2':
            if current_cli_user:
                cli_logout()
            else:
                break  # 退出程序
        elif choice == '3' and current_cli_user and current_cli_user.is_admin:
            create_admin_cli()
        elif choice == '4' and current_cli_user and current_cli_user.is_admin:
            create_user_cli()
        elif choice == '5' and current_cli_user and current_cli_user.is_admin:
            delete_user_cli()
        elif choice == '6' and current_cli_user:
            list_users_cli()
        elif choice == '7' and current_cli_user and current_cli_user.is_admin:
            clear_database()
        elif choice == '8' and current_cli_user:
            break
        else:
            print("无效选择或权限不足")

if __name__ == '__main__':
    cli_interface()