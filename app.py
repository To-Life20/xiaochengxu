"""
基于Flask的轻量级用户管理系统
功能：
1. 用户登录/登出
2. 管理员账号管理
3. 权限控制（仅管理员可创建账号）
4. 命令行数据库操作
5. 显示当前登录状态
6. 显示用户密码明文（仅在创建时显示）
7. 课程权限管理（40门课程）
8. 教师开关和年级设置（管理员自动设置为教师）
9. 课程状态管理（开始/结束）和倒计时
10. 用户只能开启授权的课程
修复问题：
1. 管理员/初始管理员可以同时开启多门课程 - 已修复，现在管理员一次只能开启一门课程
2. 教师账号之间课程开启互相干扰 - 已修复，现在每个教师账号独立管理自己的课程
3. 数据保存问题 - 已修复，现在退出后数据会持久化保存
4. 创建空用户问题 - 已修复，添加用户名和密码的非空验证
"""

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import time
import threading
from datetime import datetime, timedelta
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

# 定义所有课程列表（按顺序）
COURSE_LIST = [
    "9年级语文课", "9年级数学课", "9年级英语课", "9年级政治", "9年级历史", "9年级物理", "9年级化学",
    "10年级语文课", "10年级数学课", "10年级英语课", "10年级政治", "10年级历史", "10年级物理", "10年级化学", "10年级生物", "10年级地理",
    "11年级语文课", "11年级数学课", "11年级英语课", "11年级政治", "11年级历史", "11年级物理", "11年级化学", "11年级生物", "11年级地理",
    "12年级语文课", "12年级数学课", "12年级英语课", "12年级政治", "12年级历史", "12年级物理", "12年级化学", "12年级生物", "12年级地理",
    "飞盘课", "瑜伽课", "篮球课", "射箭课", "音乐课", "乐理", "乐队", "自我认知", "理科融合", "项目1", "项目2", "项目3"
]

# 年级选项
GRADE_OPTIONS = ["9年级", "10年级", "11年级", "12年级"]

# 课程状态模型
class CourseStatus(db.Model):
    # 课程ID（主键）
    id = db.Column(db.Integer, primary_key=True)
    # 课程名称（唯一）
    course_name = db.Column(db.String(100), unique=True, nullable=False)
    # 课程是否开始
    is_started = db.Column(db.Boolean, default=False)
    # 课程开始时间
    start_time = db.Column(db.DateTime, nullable=True)
    # 课程结束时间
    end_time = db.Column(db.DateTime, nullable=True)
    # 记录开启课程的用户ID（新增字段）
    started_by_user_id = db.Column(db.Integer, nullable=True)

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
    # 课程权限（JSON格式存储）
    course_permissions = db.Column(db.String(2000), default='{}')
    # 是否为教师
    is_teacher = db.Column(db.Boolean, default=False)
    # 年级（非教师用户）
    grade = db.Column(db.String(20), default='')

    # 设置密码（生成哈希值）
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 验证密码
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 获取课程权限字典
    def get_course_permissions(self):
        try:
            return json.loads(self.course_permissions)
        except:
            return {}

    # 设置课程权限
    def set_course_permissions(self, permissions_dict):
        # 只保留在COURSE_LIST中定义的课程
        valid_permissions = {course: permissions_dict.get(course, False)
                             for course in COURSE_LIST}
        self.course_permissions = json.dumps(valid_permissions)

    # 检查特定课程权限
    def has_course_permission(self, course_name):
        permissions = self.get_course_permissions()
        return permissions.get(course_name, False)

    # 更新特定课程权限
    def update_course_permission(self, course_name, has_permission):
        permissions = self.get_course_permissions()
        if course_name in COURSE_LIST:
            permissions[course_name] = has_permission
            self.course_permissions = json.dumps(permissions)
            return True
        return False

    # 检查是否有权限开始课程
    def can_start_course(self, course_name):
        # 管理员可以开始任何课程
        if self.is_admin:
            return True
        # 教师只能开始自己有权限的课程
        if self.is_teacher:
            return self.has_course_permission(course_name)
        # 学生不能开始课程
        return False

    # 将用户对象转换为字典（包含课程权限）
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'is_teacher': self.is_teacher,
            'grade': self.grade if not self.is_teacher else '',
            'course_permissions': self.get_course_permissions()
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

# 创建默认课程权限字典
def default_course_permissions():
    return {course: False for course in COURSE_LIST}

# 创建全权限课程字典
def full_course_permissions():
    return {course: True for course in COURSE_LIST}

# 初始化课程状态
def init_course_status():
    """确保所有课程都有状态记录"""
    for course in COURSE_LIST:
        status = CourseStatus.query.filter_by(course_name=course).first()
        if not status:
            new_status = CourseStatus(course_name=course)
            db.session.add(new_status)
    db.session.commit()

# 开始课程倒计时
def start_course_timer(course_name, user_id):
    """开始课程的45分钟倒计时"""
    status = CourseStatus.query.filter_by(course_name=course_name).first()
    if status:
        status.is_started = True
        status.start_time = datetime.now()
        status.end_time = status.start_time + timedelta(minutes=45)
        status.started_by_user_id = user_id  # 记录开启者ID
        db.session.commit()

        # 创建倒计时线程
        def countdown():
            # 等待45分钟
            time.sleep(45 * 60)

            # 倒计时结束后结束课程
            with app.app_context():
                status = CourseStatus.query.filter_by(course_name=course_name).first()
                if status and status.is_started:
                    status.is_started = False
                    status.start_time = None
                    status.end_time = None
                    status.started_by_user_id = None  # 清除开启者记录
                    db.session.commit()
                    print(f"\n[系统通知] 课程 '{course_name}' 已自动结束")

        # 启动倒计时线程
        thread = threading.Thread(target=countdown)
        thread.daemon = True
        thread.start()

# 获取课程状态信息
def get_course_status():
    """获取所有课程的状态信息"""
    status_list = []
    for status in CourseStatus.query.all():
        remaining = None
        if status.is_started and status.end_time:
            remaining_seconds = (status.end_time - datetime.now()).total_seconds()
            if remaining_seconds > 0:
                minutes, seconds = divmod(int(remaining_seconds), 60)
                remaining = f"{minutes:02d}:{seconds:02d}"

        status_list.append({
            "course_name": status.course_name,
            "is_started": status.is_started,
            "start_time": status.start_time.isoformat() if status.start_time else None,
            "end_time": status.end_time.isoformat() if status.end_time else None,
            "remaining": remaining,
            "started_by_user_id": status.started_by_user_id  # 新增字段
        })
    return status_list

# 命令行工具函数 - 全部添加应用上下文
@with_app_context
def create_admin_cli():
    """创建管理员账号（自动设置为教师）"""
    global current_cli_user

    # 检查当前用户是否为管理员
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    while True:
        username = input("输入管理员用户名: ").strip()
        if not username:
            print("错误：用户名不能为空")
            continue
        break

    while True:
        password = input("输入管理员密码: ").strip()
        if not password:
            print("错误：密码不能为空")
            continue
        break

    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=username).first():
        print("错误：用户名已存在")
        return

    # 创建新管理员账号 - 管理员自动设置为教师
    admin = User(username=username, is_admin=True, is_teacher=True)

    admin.set_password(password)
    admin.set_course_permissions(full_course_permissions())  # 管理员拥有所有课程权限
    db.session.add(admin)
    db.session.commit()
    print(f"管理员账号 {username} 创建成功")
    print(f"密码: {password} (请妥善保存)")  # 显示明文密码
    print(f"教师: 是 (管理员自动设置为教师)")

@with_app_context
def list_users_cli():
    """列出所有用户信息"""
    users = db.session.query(User).all()
    print("\n用户列表:")
    print("ID | 用户名 | 管理员 | 教师 | 年级 | 状态 | 初始管理员 | 课程权限数量")
    print("-" * 90)
    for user in users:
        status = "激活" if user.is_active else "禁用"
        admin = "是" if user.is_admin else "否"
        teacher = "是" if user.is_teacher else "否"
        initial_admin = "是" if user.is_initial_admin else "否"
        permissions = user.get_course_permissions()
        num_permissions = sum(1 for has_perm in permissions.values() if has_perm)
        grade = user.grade if not user.is_teacher else "教师"
        print(f"{user.id} | {user.username} | {admin} | {teacher} | {grade} | {status} | {initial_admin} | {num_permissions}/{len(COURSE_LIST)}")
    print()

@with_app_context
def create_user_cli():
    """创建普通用户账号"""
    global current_cli_user

    # 检查当前用户是否为管理员
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    while True:
        username = input("输入用户名: ").strip()
        if not username:
            print("错误：用户名不能为空")
            continue
        break

    while True:
        password = input("输入密码: ").strip()
        if not password:
            print("错误：密码不能为空")
            continue
        break

    is_admin = input("是否为管理员? (y/n): ").lower() == 'y'

    # 管理员自动设置为教师，普通用户询问教师状态
    if is_admin:
        is_teacher = True
        print("管理员自动设置为教师")
    else:
        is_teacher = input("是否为教师? (y/n): ").lower() == 'y'

    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=username).first():
        print("错误：用户名已存在")
        return

    # 创建新用户
    new_user = User(username=username, is_admin=is_admin, is_teacher=is_teacher)

    # 如果不是教师，设置年级
    if not is_teacher:
        print("\n请选择年级:")
        for i, grade in enumerate(GRADE_OPTIONS, 1):
            print(f"{i}. {grade}")
        grade_choice = input("输入年级编号: ")
        if grade_choice.isdigit() and 1 <= int(grade_choice) <= len(GRADE_OPTIONS):
            new_user.grade = GRADE_OPTIONS[int(grade_choice)-1]
        else:
            print("无效选择，默认设置为9年级")
            new_user.grade = "9年级"

    new_user.set_password(password)
    new_user.set_course_permissions(default_course_permissions())
    db.session.add(new_user)
    db.session.commit()
    print(f"用户 {username} 创建成功")
    print(f"密码: {password} (请妥善保存)")  # 显示明文密码
    print(f"教师: {'是' if is_teacher else '否'}")
    if not is_teacher:
        print(f"年级: {new_user.grade}")

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
        role_info = []
        if user.is_admin:
            role_info.append("管理员")
        if user.is_teacher:
            role_info.append("教师")
        else:
            role_info.append(f"学生 ({user.grade})")
        role_str = ", ".join(role_info)
        print(f"登录成功！欢迎 {user.username} ({role_str})")
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
    """清空数据库（危险操作）并重置初始管理员权限"""
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

    try:
        # 删除所有非初始管理员用户
        num_deleted = db.session.query(User).filter(User.is_initial_admin == False).delete()

        # 重置初始管理员权限
        initial_admin = db.session.query(User).filter_by(is_initial_admin=True).first()
        if initial_admin:
            # 重置密码
            initial_admin.set_password(INITIAL_ADMIN_PASSWORD)
            # 重置所有课程权限
            initial_admin.set_course_permissions(full_course_permissions())
            # 确保初始管理员是教师
            initial_admin.is_teacher = True
            initial_admin.grade = ''
            print(f"已重置初始管理员 '{INITIAL_ADMIN_USERNAME}' 的密码和课程权限")
        else:
            print("警告：未找到初始管理员账号")

        # 重置所有课程状态
        db.session.query(CourseStatus).delete()
        init_course_status()
        print("已重置所有课程状态")

        db.session.commit()
        print(f"数据库已清空，删除了 {num_deleted} 个用户（初始管理员保留并重置）")
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

@with_app_context
def manage_course_permissions():
    """管理用户课程权限（使用固定课程编号）"""
    global current_cli_user

    # 检查管理员权限
    if not current_cli_user or not current_cli_user.is_admin:
        print("错误：需要管理员权限")
        return

    list_users_cli()
    user_id = input("输入要管理权限的用户ID: ")

    if not user_id.isdigit():
        print("无效的用户ID")
        return

    user = db.session.get(User, int(user_id))
    if not user:
        print("未找到用户")
        return

    # 修复1: 防止为学生设置课程权限
    if not user.is_teacher and not user.is_admin:
        print("错误：学生账户不能设置课程权限")
        return

    print(f"\n管理用户: {user.username} 的课程权限")

    # 获取当前权限字典
    permissions = user.get_course_permissions()

    while True:
        print("\n课程列表 (编号固定，与状态无关):")
        print("-" * 60)
        # 显示所有课程，使用固定编号
        for i, course in enumerate(COURSE_LIST, 1):
            status = "启用" if permissions.get(course, False) else "禁用"
            print(f"{i:2d}. {course:<20} [{status}]")
        print("-" * 60)

        print("\n操作:")
        print("1. 启用课程")
        print("2. 禁用课程")
        print("3. 保存并退出")
        print("4. 退出不保存")

        choice = input("请选择操作: ")

        if choice == '1' or choice == '2':  # 启用或禁用课程
            try:
                course_num = int(input("请输入课程编号: "))
                if 1 <= course_num <= len(COURSE_LIST):
                    course_name = COURSE_LIST[course_num - 1]
                    if choice == '1':  # 启用课程
                        permissions[course_name] = True
                        print(f"已启用课程: {course_name}")
                    else:  # 禁用课程
                        permissions[course_name] = False
                        print(f"已禁用课程: {course_name}")
                else:
                    print(f"无效的课程编号，请输入 1-{len(COURSE_LIST)} 之间的数字")
            except ValueError:
                print("请输入有效的数字")

        elif choice == '3':  # 保存并退出
            # 将更新后的权限应用到用户对象
            user.set_course_permissions(permissions)
            db.session.commit()
            print("权限已保存")
            break

        elif choice == '4':  # 退出不保存
            db.session.rollback()
            print("已退出，未保存更改")
            break

        else:
            print("无效选择")

@with_app_context
def view_course_permissions():
    """查看用户课程权限"""
    global current_cli_user

    list_users_cli()
    user_id = input("输入要查看权限的用户ID: ")

    if not user_id.isdigit():
        print("无效的用户ID")
        return

    user = db.session.get(User, int(user_id))
    if not user:
        print("未找到用户")
        return

    permissions = user.get_course_permissions()

    print(f"\n用户: {user.username} 的课程权限:")
    print(f"角色: {'教师' if user.is_teacher else '学生'} {'(' + user.grade + ')' if not user.is_teacher else ''}")
    print("-" * 60)
    print("已启用的课程:")
    enabled_count = 0
    for i, course in enumerate(COURSE_LIST, 1):
        if permissions.get(course, False):
            print(f"  {i:2d}. ✓ {course}")
            enabled_count += 1

    print(f"\n未启用的课程 ({len(COURSE_LIST) - enabled_count}):")
    for i, course in enumerate(COURSE_LIST, 1):
        if not permissions.get(course, False):
            print(f"  {i:2d}. ✗ {course}")

    print("-" * 60)
    print(f"总计: {enabled_count}/{len(COURSE_LIST)} 门课程已启用")

@with_app_context
def view_course_status():
    """查看所有课程状态"""
    status_list = get_course_status()

    print("\n课程状态:")
    print("-" * 80)
    print("编号 | 课程名称             | 状态    | 剩余时间 | 开启者ID")
    print("-" * 80)

    for i, status in enumerate(status_list, 1):
        course_name = status['course_name']
        is_started = "进行中" if status['is_started'] else "未开始"
        remaining = status['remaining'] if status['remaining'] else "无"
        started_by = status['started_by_user_id'] if status['started_by_user_id'] else "无"
        print(f"{i:3d} | {course_name:<20} | {is_started:<6} | {remaining:<8} | {started_by}")

    print("-" * 80)

@with_app_context
def list_authorized_courses(user):
    """列出用户可以开启的授权课程（使用本地索引）"""
    authorized_courses = []
    permissions = user.get_course_permissions()

    print("\n您可以开启的课程:")
    print("-" * 60)

    # 修复：使用本地索引而不是全局索引
    count = 1
    for course in COURSE_LIST:
        if permissions.get(course, False) or user.is_admin:
            # 检查课程状态
            status = CourseStatus.query.filter_by(course_name=course).first()
            status_text = " (进行中)" if status and status.is_started else ""
            print(f"{count:2d}. {course}{status_text}")
            authorized_courses.append(course)
            count += 1  # 只对授权课程递增计数

    print("-" * 60)
    return authorized_courses

@with_app_context
def start_course_cli():
    """开始课程（需要教师或管理员权限）"""
    global current_cli_user

    # 检查用户权限
    if not current_cli_user or (not current_cli_user.is_teacher and not current_cli_user.is_admin):
        print("错误：需要教师或管理员权限")
        return

    # 检查用户是否已有课程在进行中（只检查自己开启的课程）
    active_courses = []
    for status in CourseStatus.query.filter_by(is_started=True).all():
        # 修复：检查开启者ID是否匹配当前用户ID
        if status.started_by_user_id == current_cli_user.id:
            active_courses.append(status.course_name)

    if active_courses:
        print(f"错误：您已有课程在进行中: {', '.join(active_courses)}")
        print("请先结束当前课程再开始新课程")
        return

    # 列出用户可以开启的课程
    authorized_courses = list_authorized_courses(current_cli_user)

    if not authorized_courses:
        print("您没有被授权开启任何课程")
        return

    # 选择课程
    try:
        # 更新提示文本，明确是"列表中的编号"
        course_num = int(input("\n输入列表中的课程编号: "))
        if course_num < 1 or course_num > len(authorized_courses):
            print(f"无效的课程编号，请输入 1-{len(authorized_courses)} 之间的数字")
            return

        course_name = authorized_courses[course_num - 1]
    except ValueError:
        print("请输入有效的数字")
        return

    # 检查课程是否已开始
    status = CourseStatus.query.filter_by(course_name=course_name).first()
    if status and status.is_started:
        print(f"课程 '{course_name}' 已在进行中")
        return

    # 确认操作（输入密码）
    password = input("请输入您的密码以确认开始课程: ")
    if not current_cli_user.check_password(password):
        print("密码错误，操作取消")
        return

    # 开始课程
    start_course_timer(course_name, current_cli_user.id)
    print(f"课程 '{course_name}' 已开始，45分钟倒计时已启动")

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

def teacher_or_admin_required(fn):
    """检查API请求是否具有教师或管理员权限"""
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

        # 检查教师或管理员权限
        if not (user.is_teacher or user.is_admin):
            return jsonify({"error": "需要教师或管理员权限"}), 403

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

    # 验证用户名
    if 'username' not in data or not data['username'].strip():
        return jsonify({"error": "用户名不能为空"}), 400
    if len(data['username'].strip()) < 3:
        return jsonify({"error": "用户名至少需要3个字符"}), 400

    # 验证密码
    if 'password' not in data or not data['password'].strip():
        return jsonify({"error": "密码不能为空"}), 400
    if len(data['password'].strip()) < 4:
        return jsonify({"error": "密码至少需要4个字符"}), 400

    # 检查用户名是否已存在
    if db.session.query(User).filter_by(username=data['username']).first():
        return jsonify({"error": "用户名已存在"}), 400

    # 创建新用户
    is_admin = data.get('is_admin', False)

    # 管理员自动设置为教师
    if is_admin:
        is_teacher = True
    else:
        is_teacher = data.get('is_teacher', False)

    new_user = User(
        username=data['username'],
        is_admin=is_admin,
        is_teacher=is_teacher
    )

    # 如果不是教师，设置年级
    if not is_teacher and 'grade' in data:
        if data['grade'] in GRADE_OPTIONS:
            new_user.grade = data['grade']
        else:
            return jsonify({"error": "无效的年级"}), 400

    new_user.set_password(data['password'])

    # 设置课程权限
    if 'course_permissions' in data:
        new_user.set_course_permissions(data['course_permissions'])
    else:
        new_user.set_course_permissions(default_course_permissions())

    db.session.add(new_user)
    db.session.commit()

    # 在响应中包含明文密码（仅创建时显示）
    response_data = {
        "message": "用户创建成功",
        "user": new_user.to_dict(),
        "password": data['password']  # 仅创建时显示明文密码
    }

    return jsonify(response_data), 201

@app.route('/api/users', methods=['GET'], endpoint='api_list_users')
@admin_required
def list_users():
    """列出所有用户API（仅管理员）"""
    users = db.session.query(User).all()
    return jsonify({
        "users": [user.to_dict() for user in users]
    })

@app.route('/api/users/<int:user_id>/permissions', methods=['PUT'], endpoint='api_update_permissions')
@admin_required
def update_permissions(user_id):
    """更新用户课程权限API（仅管理员）"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "用户不存在"}), 404

    # 修复1: 防止为学生设置课程权限
    if not user.is_teacher and not user.is_admin:
        return jsonify({"error": "学生账户不能设置课程权限"}), 400

    data = request.get_json()
    if 'course_permissions' not in data:
        return jsonify({"error": "缺少课程权限数据"}), 400

    user.set_course_permissions(data['course_permissions'])
    db.session.commit()

    return jsonify({
        "message": "课程权限更新成功",
        "user": user.to_dict()
    })

@app.route('/api/courses/status', methods=['GET'], endpoint='api_course_status')
def course_status():
    """获取所有课程状态（公开）"""
    return jsonify(get_course_status())

@app.route('/api/courses/<string:course_name>/start', methods=['POST'], endpoint='api_start_course')
@teacher_or_admin_required
def start_course(course_name):
    """开始课程API（需要教师或管理员权限）"""
    # 检查课程是否存在
    if course_name not in COURSE_LIST:
        return jsonify({"error": "无效的课程名称"}), 400

    # 获取当前用户
    auth = request.authorization
    user = db.session.query(User).filter_by(username=auth.username).first()

    # 检查用户是否有权限开启该课程
    if not user.can_start_course(course_name):
        return jsonify({"error": "您没有权限开启此课程"}), 403

    # 检查用户是否已有课程在进行中（只检查自己开启的课程）
    active_courses = []
    for status in CourseStatus.query.filter_by(is_started=True).all():
        if status.started_by_user_id == user.id:
            active_courses.append(status.course_name)

    if active_courses:
        return jsonify({
            "error": "您已有课程在进行中",
            "active_courses": active_courses
        }), 400

    # 检查课程是否已开始
    status = CourseStatus.query.filter_by(course_name=course_name).first()
    if status and status.is_started:
        return jsonify({"error": "课程已在进行中"}), 400

    # 从请求中获取密码
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({"error": "需要密码确认"}), 400

    # 验证密码
    if not user.check_password(data['password']):
        return jsonify({"error": "密码错误"}), 401

    # 开始课程
    start_course_timer(course_name, user.id)

    return jsonify({
        "message": f"课程 '{course_name}' 已开始",
        "status": CourseStatus.query.filter_by(course_name=course_name).first().to_dict()
    })

@app.route('/api/user/authorized-courses', methods=['GET'], endpoint='api_authorized_courses')
@teacher_or_admin_required
def authorized_courses():
    """获取用户可以开启的授权课程列表"""
    # 获取当前用户
    auth = request.authorization
    user = db.session.query(User).filter_by(username=auth.username).first()

    # 获取用户有权限的课程
    permissions = user.get_course_permissions()
    authorized = [course for course in COURSE_LIST if permissions.get(course, False) or user.is_admin]

    # 获取课程状态
    status_list = get_course_status()
    status_map = {s['course_name']: s for s in status_list}

    # 构造响应
    courses = []
    for course in authorized:
        status = status_map.get(course, {})
        courses.append({
            "course_name": course,
            "is_started": status.get('is_started', False),
            "remaining": status.get('remaining', None)
        })

    return jsonify({"authorized_courses": courses})


# 初始化数据库
@with_app_context
def init_db():
    """初始化数据库（创建表结构）并添加初始管理员"""
    # 只创建不存在的表，而不是删除所有表
    db.create_all()
    print("数据库表已检查/创建")

    # 初始化课程状态（只添加缺失的课程）
    for course in COURSE_LIST:
        status = CourseStatus.query.filter_by(course_name=course).first()
        if not status:
            new_status = CourseStatus(course_name=course)
            db.session.add(new_status)
    db.session.commit()
    print("课程状态已初始化")

    # 检查初始管理员是否存在
    admin_user = db.session.query(User).filter_by(username=INITIAL_ADMIN_USERNAME).first()

    if not admin_user:
        # 创建初始管理员
        admin_user = User(
            username=INITIAL_ADMIN_USERNAME,
            is_admin=True,
            is_active=True,
            is_initial_admin=True,
            is_teacher=True  # 初始管理员默认是教师
        )
        admin_user.set_password(INITIAL_ADMIN_PASSWORD)
        admin_user.set_course_permissions(full_course_permissions())
        db.session.add(admin_user)
        db.session.commit()
        print(f"初始管理员 '{INITIAL_ADMIN_USERNAME}' 已创建")
        print(f"密码: {INITIAL_ADMIN_PASSWORD} (请妥善保存)")
    else:
        # 确保初始管理员有所有课程权限
        permissions = admin_user.get_course_permissions()
        if not permissions or any(course not in permissions for course in COURSE_LIST):
            admin_user.set_course_permissions(full_course_permissions())

        # 确保初始管理员是教师
        if not admin_user.is_teacher:
            admin_user.is_teacher = True
            admin_user.grade = ''

        db.session.commit()
        print(f"已为初始管理员 '{INITIAL_ADMIN_USERNAME}' 更新课程权限和教师状态")

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
            role_info = []
            if current_cli_user.is_admin:
                role_info.append("管理员")
            if current_cli_user.is_teacher:
                role_info.append("教师")
            else:
                role_info.append(f"学生 ({current_cli_user.grade})")
            role_str = ", ".join(role_info)
            user_info = f"当前用户: {current_cli_user.username} ({role_str})"
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
                print("6. 管理课程权限")
                print("7. 查看课程权限")
            print("8. 列出所有用户")
            if current_cli_user.is_admin:
                print("9. 清空数据库（重置系统）")
            print("10. 查看课程状态")
            if current_cli_user.is_teacher or current_cli_user.is_admin:
                print("11. 开始课程")
            print("0. 退出")
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
        elif choice == '6' and current_cli_user and current_cli_user.is_admin:
            manage_course_permissions()
        elif choice == '7' and current_cli_user and current_cli_user.is_admin:
            view_course_permissions()
        elif choice == '8' and current_cli_user:
            list_users_cli()
        elif choice == '9' and current_cli_user and current_cli_user.is_admin:
            clear_database()
        elif choice == '10' and current_cli_user:
            view_course_status()
        elif choice == '11' and current_cli_user and (current_cli_user.is_teacher or current_cli_user.is_admin):
            start_course_cli()
        elif choice == '0' and current_cli_user:
            break
        else:
            print("无效选择或权限不足")

if __name__ == '__main__':
    cli_interface()