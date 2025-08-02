from flask import Flask, jsonify, request, session, render_template
import json
import os
import uuid
import time
from datetime import datetime, timedelta
from flask_sock import Sock
import threading

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
sock = Sock(app)

# 存储活跃会话 {username: session_id}
active_sessions = {}

# 存储所有 WebSocket 连接
websocket_connections = []
websocket_lock = threading.Lock()

# 存储按用户分组的 WebSocket 连接
user_websockets = {}  # {username: [websocket1, websocket2, ...]}
user_websockets_lock = threading.Lock()

# 用户数据库文件
USER_DB_FILE = 'users.json'

# 课程状态数据库文件
COURSE_STATUS_FILE = 'course_status.json'

# 已完成课程计数数据库文件
COMPLETED_COURSES_FILE = 'completed_courses.json'

# 定义所有课程
COURSES = [
    "9年级语文课", "9年级数学课", "9年级英语课", "9年级政治", "9年级历史", "9年级物理", "9年级化学",
    "10年级语文课", "10年级数学课", "10年级英语课", "10年级政治", "10年级历史", "10年级物理", "10年级化学",
    "10年级生物", "10年级地理",
    "11年级语文课", "11年级数学课", "11年级英语课", "11年级政治", "11年级历史", "11年级物理", "11年级化学",
    "11年级生物", "11年级地理",
    "12年级语文课", "12年级数学课", "12年级英语课", "12年级政治", "12年级历史", "12年级物理", "12年级化学",
    "12年级生物", "12年级地理",
    "飞盘课", "瑜伽课", "篮球课", "射箭课", "音乐课", "乐理", "乐队", "自我认知", "理科融合", "项目1", "项目2", "项目3"
]


# 输出用户列表
def print_users():
    users = get_all_users()
    print("\n当前用户列表:")
    print("用户名\t\t角色\t\t教师状态\t年级\t\t负责课程")
    print("---------------------------------------------------------------")
    for username, info in users.items():
        role = info.get('role', 'user')
        is_teacher = info.get('is_teacher', False)
        teacher_status = "教师" if is_teacher else "非教师"
        grade = info.get('grade', '无') if not is_teacher else 'N/A'
        responsible_courses = info.get('responsible_courses', [])
        courses_str = f"{len(responsible_courses)}门课程" if responsible_courses else "无"
        print(f"{username}\t\t{role}\t\t{teacher_status}\t{grade}\t\t{courses_str}")
    print()


# 初始化用户数据库
def init_user_db():
    if not os.path.exists(USER_DB_FILE):
        users = {
            'admin': {'password': 'admin123', 'role': 'admin', 'is_teacher': True, 'responsible_courses': COURSES},
            'teacher': {'password': 'teacher123', 'role': 'user', 'is_teacher': True, 'responsible_courses': []},
            'student1': {'password': 'pass123', 'role': 'user', 'is_teacher': False, 'grade': '九年级'},
            'student2': {'password': 'pass123', 'role': 'user', 'is_teacher': False, 'grade': '十年级'}
        }
        with open(USER_DB_FILE, 'w') as f:
            json.dump(users, f)
        print("初始用户数据库已创建")
        print_users()


# 获取所有用户
def get_all_users():
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        init_user_db()
        return get_all_users()


# 保存所有用户
def save_all_users(users):
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f)
    print_users()


# 初始化课程状态数据库
def init_course_db():
    if not os.path.exists(COURSE_STATUS_FILE):
        course_status = {course: False for course in COURSES}
        with open(COURSE_STATUS_FILE, 'w') as f:
            json.dump(course_status, f)
        print("初始课程状态数据库已创建")
        print_course_status()
    
    # 初始化课程详细信息数据库
    if not os.path.exists('course_details.json'):
        course_details = {}
        with open('course_details.json', 'w') as f:
            json.dump(course_details, f)
        print("初始课程详细信息数据库已创建")


# 获取所有课程状态
def get_course_status():
    try:
        with open(COURSE_STATUS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        init_course_db()
        return get_course_status()


# 保存所有课程状态
def save_course_status(course_status):
    with open(COURSE_STATUS_FILE, 'w') as f:
        json.dump(course_status, f)
    print_course_status()


# 获取课程详细信息
def get_course_details():
    try:
        with open('course_details.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# 保存课程详细信息
def save_course_details(course_details):
    with open('course_details.json', 'w') as f:
        json.dump(course_details, f)


# 获取已完成课程计数
def get_completed_courses():
    try:
        with open(COMPLETED_COURSES_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {course: 0 for course in COURSES}


# 保存已完成课程计数
def save_completed_courses(completed_courses):
    with open(COMPLETED_COURSES_FILE, 'w') as f:
        json.dump(completed_courses, f)


# 增加课程完成计数
def increment_course_count(course):
    completed_courses = get_completed_courses()
    if course in completed_courses:
        completed_courses[course] += 1
    else:
        completed_courses[course] = 1
    save_completed_courses(completed_courses)


# 打印课程状态
def print_course_status():
    course_status = get_course_status()
    print("\n当前课程状态:")
    print("课程名称\t\t状态")
    print("-----------------------------------------------")
    for course, status in course_status.items():
        status_str = "开启" if status else "关闭"
        print(f"{course}\t\t{status_str}")
    print()


# 初始化数据库
init_user_db()
init_course_db()

print("服务器启动，当前用户信息:")
print_users()
print("当前课程状态:")
print_course_status()


@app.before_request
def log_request_info():
    if request.path != '/':
        timestamp = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        print(f"{timestamp} - {request.remote_addr} - {request.method} {request.path}")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users = get_all_users()
    user = users.get(username)

    if user and user['password'] == password:
        # 检查是否已在其他地方登录
        if username in active_sessions:
            # 踢出前一个会话
            try:
                # 发送强制登出通知给该用户的所有连接
                with user_websockets_lock:
                    if username in user_websockets:
                        for ws in user_websockets[username]:
                            try:
                                ws.send(json.dumps({'type': 'force_logout'}))
                            except:
                                # 连接可能已关闭，忽略错误
                                pass
                        # 清空该用户的WebSocket连接列表
                        user_websockets[username] = []

                # 删除活跃会话
                del active_sessions[username]
            except KeyError:
                pass

        # 创建新会话
        session_id = str(uuid.uuid4())
        active_sessions[username] = session_id

        session['logged_in'] = True
        session['username'] = username
        session['role'] = user.get('role', 'user')
        session['is_teacher'] = user.get('is_teacher', False)
        session['grade'] = user.get('grade', None)
        session['session_id'] = session_id  # 存储会话ID
        session['responsible_courses'] = user.get('responsible_courses', [])  # 存储负责课程信息

        return jsonify({
            'success': True,
            'role': user.get('role', 'user'),
            'is_teacher': user.get('is_teacher', False),
            'grade': user.get('grade', None),
            # 添加负责课程返回
            'responsible_courses': user.get('responsible_courses', [])
        })
    return jsonify({'success': False, 'message': '用户名或密码错误'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username')
    session_id = session.get('session_id')

    # 从活跃会话中移除
    if username in active_sessions and active_sessions[username] == session_id:
        del active_sessions[username]

        # 从用户WebSocket连接中移除
        with user_websockets_lock:
            if username in user_websockets:
                # 清空该用户的WebSocket连接列表
                user_websockets[username] = []

    session.clear()
    return jsonify({'success': True})


@app.route('/api/check_login')
def check_login():
    if session.get('logged_in'):
        username = session.get('username')
        session_id = session.get('session_id')

        # 验证会话是否有效
        if username in active_sessions and active_sessions[username] == session_id:
            return jsonify({
                'logged_in': True,
                'username': session['username'],
                'role': session.get('role', 'user'),
                'is_teacher': session.get('is_teacher', False),
                'grade': session.get('grade', None),
                'responsible_courses': session.get('responsible_courses', [])
            })

    return jsonify({'logged_in': False})


@app.route('/api/users', methods=['GET'])
def get_users():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    users = get_all_users()
    sanitized_users = [{
        'username': uname,
        'role': info.get('role', 'user'),
        'is_teacher': info.get('is_teacher', False),
        'grade': info.get('grade', None),  # 返回年级信息
        'responsible_courses': info.get('responsible_courses', [])  # 返回负责课程信息
    } for uname, info in users.items()]

    return jsonify(sanitized_users)


@app.route('/api/users', methods=['POST'])
def create_user():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    is_teacher = data.get('is_teacher', False)
    grade = data.get('grade', None)
    responsible_courses = data.get('responsible_courses', [])

    # 管理员自动设置为教师
    if is_admin:
        is_teacher = True
        grade = None  # 管理员/教师不需要年级
        responsible_courses = COURSES  # 管理员负责所有课程

    # 验证非教师用户必须选择年级
    if not is_teacher and not grade:
        return jsonify({
            'success': False,
            'message': '非教师用户必须选择年级'
        }), 400

    # 验证年级是否有效（仅当非教师用户）
    valid_grades = ['九年级', '十年级', '十一年级', '十二年级']
    if not is_teacher and grade and grade not in valid_grades:
        return jsonify({
            'success': False,
            'message': f'无效的年级。请选择: {", ".join(valid_grades)}'
        }), 400

    # 验证教师必须选择负责课程
    if is_teacher and not responsible_courses:
        return jsonify({
            'success': False,
            'message': '教师必须选择至少一门负责的课程'
        }), 400

    # 验证负责课程是否有效
    if responsible_courses:
        valid_courses = set(COURSES)
        invalid_courses = [course for course in responsible_courses if course not in valid_courses]
        if invalid_courses:
            return jsonify({
                'success': False,
                'message': f'无效的课程名称: {", ".join(invalid_courses)}'
            }), 400

    if not username or not password:
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400

    users = get_all_users()

    if username in users:
        return jsonify({'success': False, 'message': '用户名已存在'}), 400

    # 创建用户对象
    user_data = {
        'password': password,
        'role': 'admin' if is_admin else 'user',
        'is_teacher': is_teacher
    }

    # 如果不是教师，添加年级信息
    if not is_teacher:
        user_data['grade'] = grade
    else:
        # 如果是教师，添加负责课程信息
        user_data['responsible_courses'] = responsible_courses

    users[username] = user_data

    save_all_users(users)
    broadcast_user_update()  # 通知所有客户端
    return jsonify({'success': True, 'message': '用户创建成功'})


@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username):
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    users = get_all_users()

    if username not in users:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    if username == session.get('username'):
        return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400

    del users[username]
    save_all_users(users)
    broadcast_user_update()  # 通知所有客户端

    # 如果被删除用户已登录，强制登出
    if username in active_sessions:
        with user_websockets_lock:
            if username in user_websockets:
                for ws in user_websockets[username]:
                    try:
                        ws.send(json.dumps({'type': 'force_logout', 'reason': '账号已被删除'}))
                    except:
                        pass
                # 清空该用户的WebSocket连接列表
                user_websockets[username] = []
        del active_sessions[username]

    return jsonify({'success': True, 'message': '用户删除成功'})


@app.route('/api/users/<username>', methods=['PUT'])
def edit_user(username):
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    data = request.get_json()
    new_username = data.get('username')  # 新用户名
    password = data.get('password')
    is_admin = data.get('is_admin', None)
    is_teacher = data.get('is_teacher', None)
    grade = data.get('grade', None)
    responsible_courses = data.get('responsible_courses', None)

    users = get_all_users()

    if username not in users:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    # 检查新用户名是否已存在（且不是自己）
    if new_username and new_username != username and new_username in users:
        return jsonify({'success': False, 'message': '新用户名已存在'}), 400

    user = users[username]

    # 修改用户名
    if new_username and new_username != username:
        users[new_username] = user.copy()
        del users[username]
        username = new_username
        user = users[username]

    # 修改密码
    if password:
        user['password'] = password

    # 修改角色和教师状态
    if is_admin is not None:
        user['role'] = 'admin' if is_admin else 'user'
        if is_admin:
            user['is_teacher'] = True
            user.pop('grade', None)
            user['responsible_courses'] = COURSES  # 管理员负责所有课程
    if is_teacher is not None:
        user['is_teacher'] = is_teacher
        if is_teacher:
            user.pop('grade', None)
            # 如果之前没有负责课程，设置为空列表
            if 'responsible_courses' not in user:
                user['responsible_courses'] = []
        else:
            # 如果不是教师，移除负责课程信息
            user.pop('responsible_courses', None)

    # 修改年级（仅非教师）
    if (is_teacher is False or user.get('is_teacher') is False) and grade:
        user['grade'] = grade
    elif user.get('is_teacher'):
        user.pop('grade', None)

    # 修改负责课程（仅教师）
    if responsible_courses is not None and user.get('is_teacher'):
        # 验证负责课程是否有效
        invalid_courses = [course for course in responsible_courses if course not in COURSES]
        if invalid_courses:
            return jsonify({
                'success': False,
                'message': f'无效的课程名称: {", ".join(invalid_courses)}'
            }), 400
        user['responsible_courses'] = responsible_courses

    save_all_users(users)
    broadcast_user_update()

    # 如果被修改用户在线，强制其重新登录
    if username in active_sessions:
        with user_websockets_lock:
            if username in user_websockets:
                for ws in user_websockets[username]:
                    try:
                        ws.send(json.dumps({'type': 'force_logout', 'reason': '您的账号信息已被管理员修改，请重新登录'}))
                    except:
                        pass
                user_websockets[username] = []
        del active_sessions[username]

    return jsonify({'success': True, 'message': '用户信息已更新'})


# 获取所有可用课程列表
@app.route('/api/available-courses', methods=['GET'])
def get_available_courses():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    return jsonify({
        'success': True,
        'courses': COURSES
    })


# 获取所有课程状态
@app.route('/api/courses', methods=['GET'])
def get_courses():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': '请先登录'}), 401

    course_status = get_course_status()
    course_details = get_course_details()
    role = session.get('role', 'user')
    is_teacher = session.get('is_teacher', False)
    grade = session.get('grade', None)
    responsible_courses = session.get('responsible_courses', [])

    # 年级映射表，支持中英文数字
    grade_map = {
        '九年级': ['九年级', '9年级'],
        '十年级': ['十年级', '10年级'],
        '十一年级': ['十一年级', '11年级'],
        '十二年级': ['十二年级', '12年级'],
    }

    if role == 'admin':
        filtered_courses = course_status
    elif is_teacher:
        filtered_courses = {course: status for course, status in course_status.items()
                            if course in responsible_courses}
    else:
        filtered_courses = {}
        for course, status in course_status.items():
            if grade:
                grade_keywords = grade_map.get(grade, [grade])
                if any(g in course for g in grade_keywords):
                    filtered_courses[course] = status
                elif not any(g in course for gs in grade_map.values() for g in gs):
                    filtered_courses[course] = status
            else:
                if not any(g in course for gs in grade_map.values() for g in gs):
                    filtered_courses[course] = status

    # 添加课程详细信息
    courses_with_details = {}
    for course, status in filtered_courses.items():
        course_info = {
            'status': status,
            'details': course_details.get(course, {})
        }
        courses_with_details[course] = course_info

    return jsonify({
        'success': True,
        'courses': courses_with_details
    })


# 获取已完成课程计数
@app.route('/api/completed-courses', methods=['GET'])
def get_completed_courses_count():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': '请先登录'}), 401

    role = session.get('role', 'user')
    is_teacher = session.get('is_teacher', False)
    grade = session.get('grade', None)
    responsible_courses = session.get('responsible_courses', [])
    
    print(f"DEBUG: role={role}, is_teacher={is_teacher}, grade={grade}, responsible_courses={responsible_courses}")
    
    completed_courses = get_completed_courses()
    print(f"DEBUG: completed_courses={completed_courses}")
    
    # 年级映射表，支持中英文数字
    grade_map = {
        '九年级': ['九年级', '9年级'],
        '十年级': ['十年级', '10年级'],
        '十一年级': ['十一年级', '11年级'],
        '十二年级': ['十二年级', '12年级'],
    }
    
    if role == 'admin':
        # 管理员可以看到所有课程的完成计数
        filtered_completed = completed_courses
        print(f"DEBUG: admin path, filtered_completed={filtered_completed}")
    elif is_teacher:
        # 教师只能看到自己负责的课程的完成计数
        if responsible_courses:
            filtered_completed = {course: count for course, count in completed_courses.items()
                                if course in responsible_courses}
            print(f"DEBUG: teacher with responsible_courses path, filtered_completed={filtered_completed}")
        else:
            # 如果教师没有指定负责课程，显示所有课程
            filtered_completed = completed_courses
            print(f"DEBUG: teacher without responsible_courses path, filtered_completed={filtered_completed}")
    else:
        # 学生只能看到自己年级的课程的完成计数
        filtered_completed = {}
        for course, count in completed_courses.items():
            if grade:
                grade_keywords = grade_map.get(grade, [grade])
                if any(g in course for g in grade_keywords):
                    filtered_completed[course] = count
                elif not any(g in course for gs in grade_map.values() for g in gs):
                    filtered_completed[course] = count
            else:
                if not any(g in course for gs in grade_map.values() for g in gs):
                    filtered_completed[course] = count
        print(f"DEBUG: student path, filtered_completed={filtered_completed}")

    return jsonify({
        'success': True,
        'completed_courses': filtered_completed
    })


# 更新课程状态
@app.route('/api/courses', methods=['POST'])
def update_courses():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': '请先登录'}), 401

    role = session.get('role', 'user')
    is_teacher = session.get('is_teacher', False)
    responsible_courses = session.get('responsible_courses', [])
    username = session.get('username')

    # 只有管理员和教师可以更新课程状态
    if role != 'admin' and not is_teacher:
        return jsonify({'success': False, 'message': '无访问权限'}), 403

    data = request.get_json()
    course = data.get('course')
    status = data.get('status')
    password = data.get('password')

    if course not in COURSES:
        return jsonify({'success': False, 'message': '无效的课程名称'}), 400

    if not isinstance(status, bool):
        return jsonify({'success': False, 'message': '状态值无效'}), 400

    # 教师只能更新自己负责的课程
    if is_teacher and role != 'admin' and course not in responsible_courses:
        return jsonify({'success': False, 'message': '您没有权限管理此课程'}), 403

    # 验证密码（教师开启课程、管理员开启课程或管理员关闭课程需要）
    if (is_teacher and role != 'admin' and status) or (role == 'admin' and status) or (role == 'admin' and not status):
        if not password:
            return jsonify({'success': False, 'message': '请输入密码'}), 400
        
        users = get_all_users()
        user = users.get(username)
        if not user or user['password'] != password:
            return jsonify({'success': False, 'message': '密码错误'}), 400

    # 检查教师是否已经在开启其他课程
    if is_teacher and role != 'admin' and status:
        course_details = get_course_details()
        for course_name, details in course_details.items():
            if details.get('started_by') == username and details.get('is_active', False):
                return jsonify({'success': False, 'message': '您已经在开启一个课程，请先结束当前课程'}), 400

    # 更新课程状态
    course_status = get_course_status()
    course_details = get_course_details()
    
    if status:  # 开启课程
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=45)
        course_details[course] = {
            'started_by': username,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'is_active': True
        }
        course_status[course] = True
        # 增加课程完成计数
        increment_course_count(course)
    else:  # 关闭课程（仅管理员可以）
        if is_teacher and role != 'admin':
            return jsonify({'success': False, 'message': '课程开始后不能取消'}), 400
        course_status[course] = False
        if course in course_details:
            course_details[course]['is_active'] = False

    save_course_status(course_status)
    save_course_details(course_details)

    # 广播课程状态更新
    broadcast_course_update()

    return jsonify({'success': True, 'message': '课程状态已更新'})


# WebSocket 路由
@sock.route('/ws')
def handle_websocket(ws):
    # 将连接添加到全局列表
    with websocket_lock:
        websocket_connections.append(ws)

    # 记录当前连接的用户名（稍后绑定）
    current_user = None

    try:
        while True:
            # 等待客户端发送绑定用户名的消息
            message = ws.receive()
            if not message:
                continue

            try:
                data = json.loads(message)
                if data.get('type') == 'bind_user' and 'username' in data:
                    username = data['username']

                    # 添加到用户分组
                    with user_websockets_lock:
                        if username not in user_websockets:
                            user_websockets[username] = []
                        if ws not in user_websockets[username]:
                            user_websockets[username].append(ws)

                    current_user = username
                    print(f"用户 {username} 绑定 WebSocket 连接")
            except:
                # 忽略格式错误的消息
                pass
    except:
        # 连接关闭或出错
        pass
    finally:
        # 从全局连接列表移除
        with websocket_lock:
            if ws in websocket_connections:
                websocket_connections.remove(ws)

        # 从用户分组中移除
        if current_user:
            with user_websockets_lock:
                if current_user in user_websockets and ws in user_websockets[current_user]:
                    user_websockets[current_user].remove(ws)
                    # 如果列表为空，删除用户键
                    if not user_websockets[current_user]:
                        del user_websockets[current_user]
                    print(f"用户 {current_user} 移除 WebSocket 连接")


# 广播用户更新通知
def broadcast_user_update():
    message = json.dumps({'type': 'user_updated'})
    with websocket_lock:
        for connection in websocket_connections[:]:  # 复制列表避免修改问题
            try:
                connection.send(message)
            except:
                # 移除无效连接
                if connection in websocket_connections:
                    websocket_connections.remove(connection)


# 广播课程状态更新通知
def broadcast_course_update():
    course_status = get_course_status()
    course_details = get_course_details()
    
    # 添加课程详细信息
    courses_with_details = {}
    for course, status in course_status.items():
        course_info = {
            'status': status,
            'details': course_details.get(course, {})
        }
        courses_with_details[course] = course_info
    
    message = json.dumps({
        'type': 'course_updated',
        'courses': courses_with_details
    })
    with websocket_lock:
        for connection in websocket_connections[:]:
            try:
                connection.send(message)
            except:
                if connection in websocket_connections:
                    websocket_connections.remove(connection)


# 检查课程结束时间
def check_course_end_times():
    course_details = get_course_details()
    course_status = get_course_status()
    current_time = datetime.now()
    updated = False
    
    for course, details in course_details.items():
        if details.get('is_active', False):
            end_time_str = details.get('end_time')
            if end_time_str:
                end_time = datetime.fromisoformat(end_time_str)
                if current_time >= end_time:
                    # 课程结束
                    details['is_active'] = False
                    course_status[course] = False
                    updated = True
                    print(f"课程 {course} 已自动结束")
    
    if updated:
        save_course_status(course_status)
        save_course_details(course_details)
        broadcast_course_update()


if __name__ == '__main__':
    print("启动用户管理系统...")
    
    # 启动定时任务检查课程结束时间
    def run_course_checker():
        while True:
            try:
                check_course_end_times()
                time.sleep(30)  # 每30秒检查一次
            except Exception as e:
                print(f"课程检查任务出错: {e}")
                time.sleep(30)
    
    import threading
    course_checker_thread = threading.Thread(target=run_course_checker, daemon=True)
    course_checker_thread.start()
    
    # 确保安装依赖: pip install flask-sock
    app.run(host='0.0.0.0', port=5000)