from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import Flask, Response, json,request
from dashscope import Generation
import dashscope
from flask import Flask, request, jsonify
import openai
from dashscope import Generation
import dashscope
import requests
import json
from http import HTTPStatus
from datetime import datetime

app = Flask(__name__)
app.config.from_pyfile('config.py')  # 从配置文件中加载配置
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 接收全部的信息
messages_chatgpt = []
messages_tongyi = []
messages_wenxin = []

# 用户模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    conversation_current_id=db.Column(db.Integer ,default=0)

    @property
    def password(self):
        raise AttributeError('密码不可读取')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)




# 反馈信息模型
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('feedback', lazy=True))




# 登入
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 首页 有登录和注册按钮
@app.route('/')
def home():
    return render_template('home.html')

# 根据login跳转到用户界面或者管理员界面
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

# 用户首页 暂时有反馈信息和登出功能
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

# 管理员首页
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# 注册函数，注册成功后会重定向到用户登录界面
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('用户名已存在', 'danger')
        else:
            new_user = User(username=username)
            new_user.password = password
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# 登录函数，登录成功后根据账号不同跳转到各自的首页
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('登录失败，请检查用户名和密码', 'danger')
    return render_template('login.html')

# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# 管理员查看用户信息 最后返回的信息还要修改格式
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# 管理员查看反馈信息 最后返回的信息还要修改格式
@app.route('/admin/feedback')
@login_required
def admin_feedback():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    feedbacks = Feedback.query.all()
    return render_template('admin_feedback.html', feedbacks=feedbacks)


# 用户向管理员反馈信息
@app.route('/user/feedback', methods=['GET', 'POST'])
@login_required
def user_feedback():
    if request.method == 'POST':
        message = request.form['message']
        feedback = Feedback(user_id=current_user.id, message=message)
        db.session.add(feedback)
        db.session.commit()
        flash('反馈已提交', 'success')
        # return redirect(url_for('user_dashboard'))
    return render_template('user_feedback.html')


class Conversations(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    chatgpt_messages = db.Column(db.JSON)  # 改为 JSON 类型
    wenxin_messages = db.Column(db.JSON)   # 改为 JSON 类型
    tongyi_messages = db.Column(db.JSON)   # 改为 JSON 类型
    summary=db.Column(db.String(15))       # 来自文心一言的总结
    timestamp = db.Column(db.TIMESTAMP, default=datetime.utcnow)



#用户创建新的聊天记录时应该保存旧的聊天记录
@app.route('/conversations/new_conversation', methods=['POST'])
def save_and_clear_conversation():
    global messages_chatgpt,messages_tongyi,messages_wenxin
    # 检查列表是否为空  
    if not messages_chatgpt or not messages_tongyi or not messages_wenxin:  
        # 列表为空，可以选择返回一个错误响应或者进行其他处理  
        return jsonify({'error': 'Some of the message lists are empty.'}), 400
    user_id = current_user.id  # 请替换成你实际的用户 ID

    conversation_id=current_user.conversation_current_id + 1
    current_user.conversation_current_id=conversation_id

    current_timestamp = datetime.utcnow()
    current_summary=get_summary() #由文心一言总结对话内容
    # 列表不为空，创建一个新的 Conversations 对象并保存到数据库中
    conversation = Conversations(  
        id=conversation_id,  
        user_id=user_id,  
        chatgpt_messages=json.dumps(messages_chatgpt),  # 转换为 JSON 字符串  
        wenxin_messages=json.dumps(messages_wenxin),    # 注意：这里应该是 messages_wenxin 而不是 messages_tongyi  
        tongyi_messages=json.dumps(messages_tongyi),  
        timestamp=current_timestamp ,
        summary=current_summary
    )  
    db.session.add(conversation)  
    db.session.commit()  
    view_conversations()

    # 清空当前对话内容
    messages_chatgpt = []
    messages_tongyi = []
    messages_wenxin = []
  
    # 返回成功响应或其他适当的响应  
    return jsonify({'success': 'Conversation saved successfully.'}), 200 




#通过文心一言总结当前多轮对话的主题内容，不超过十个字
def get_summary():
    global messages_wenxin
    new_messages=messages_wenxin
    new_messages.append({'role': 'user', 'content': '请你用不超过十个字来总结我们的对话内容，不要多余的对话内容，只要总结内容'})

    url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/ernie-speed-128k?access_token=" + get_access_token()

    payload = json.dumps({
        "messages":new_messages,
        "stream": True
    })
    headers = {
        'Content-Type': 'application/json'
    }
    
    response = requests.request("POST", url, headers=headers, data=payload, stream=True)
    full_response = ""
    for line in response.iter_lines():
        line_decode = line.decode("UTF-8")
        if line_decode.startswith("data:"):  # 检查是否为 data: 行
            # 将 "data: " 替换为空字符串，然后解析为 JSON
            try:
                json_line = json.loads(line_decode.replace("data: ", ""))
                result = json_line.get("result", "")
                full_response+=result
            except json.JSONDecodeError:
                print("无法解析为 JSON 格式:", line_decode)
                continue
    print(full_response)
    return full_response
    


#用户点击某个聊天记录的主题，获取此次聊天记录的所有内容，类似chatgpt页面的功能
#从页面返回：对话id
#返回：chatgpt_messages、chatgpt_messages、tongyi_messages
@app.route('/conversations/get_conversation', methods=['GET'])
def get_conversation_by_id():
    #global messages_chatgpt,messages_tongyi,messages_wenxin
    conversation_id = request.args.get('id')
    user_id = current_user.id

    if not conversation_id or not user_id:
        return jsonify({'error': 'Missing id or user_id'}), 400

    conversation = Conversations.query.filter_by(id=conversation_id, user_id=user_id).first()

    if conversation is None:
        return jsonify({'error': 'Conversation not found'}), 404

    print("messages_chatgpt:",json.loads(conversation.chatgpt_messages) )
    print("messages_tongyi:", json.loads(conversation.tongyi_messages))
    print("messages_wenxin:", json.loads(conversation.wenxin_messages))

    return jsonify({
        'chatgpt_messages': conversation.chatgpt_messages,
        'wenxin_messages': conversation.wenxin_messages,
        'tongyi_messages': conversation.tongyi_messages
    }), 200





#获取当前用户的所有聊天记录的主题
#input：当前用户id 【不需要从页面获取，后端有记录】
#output： conversation.id 、conversation.summary
@app.route('/conversations/get_conversation_summary', methods=['GET'])
def get_user_conversations():
    user_id = current_user.id
    if not user_id:
        return jsonify({'error': 'Missing user_id'}), 400
    
    # 查询并按 id 从大到小排序,这样查出来的第一个是最近一次的对话主题
    conversations = Conversations.query.filter_by(user_id=user_id).order_by(Conversations.id.desc()).all()

    if not conversations:
        return jsonify({'error': 'No conversations found for this user'}), 404

    result = [
        {'id': conversation.id, 'summary': conversation.summary}
        for conversation in conversations
    ]
    print(result)
    return jsonify(result), 200


#for test
def view_conversations():
    conversations = Conversations.query.all()
    result = []
    for conversation in conversations:
        result.append({
            'id': conversation.id,
            'user_id': conversation.user_id,
            'chatgpt_messages': conversation.chatgpt_messages,
            'wenxin_messages': conversation.wenxin_messages,
            'tongyi_messages': conversation.tongyi_messages,
            'summary': conversation.summary,
            'timestamp': conversation.timestamp
        })
    return {'conversations': result}



@app.route('/messages/all', methods=['GET'])
def get_all_messages():
    global messages_chatgpt, messages_tongyi, messages_wenxin
    print("messages_chatgpt:", messages_chatgpt)
    print("messages_tongyi:", messages_tongyi)
    print("messages_wenxin:", messages_wenxin)
    return jsonify({
        'chatgpt': messages_chatgpt,
        'tongyi': messages_tongyi,
        'wenxin': messages_wenxin
    }),200


@app.route('/api/tongyi')
def get_tongyi_answer():
    global messages_tongyi
    query = request.args.get('query', default='default query')
    messages_tongyi.append({'role': 'user', 'content': query})
    def chat():
        print(query)
        dashscope.api_key = "sk-96f5960806d24c9cbb8b01de99e9c224"
        responses = Generation.call(
            model="qwen-turbo",
            messages=messages_tongyi,
            result_format='message',  # 设置输出为'message'格式
            stream=True,  # 设置输出方式为流式输出
            incremental_output=True  # 增量式流式输出
        )
        
        whole_message = ""
        for response in responses:
            if response.status_code == HTTPStatus.OK:
                answer_part = response.output.choices[0]['message']['content']
                whole_message += answer_part
                json_data = json.dumps({"message": response.output.choices[0]['message']['content']})
                yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据

        messages_tongyi.append({'role': 'assistant', 'content': whole_message})
        json_data = json.dumps({"message": 'done'})
        yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据
        #print('结束')
    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    }
    print("messages_chatgpt:", messages_chatgpt)
    print("messages_tongyi:", messages_tongyi)
    print("messages_wenxin:", messages_wenxin)
    return Response(chat(), content_type='text/event-stream', headers=headers)

@app.route('/api/chatgpt')
def get_chatgpt_answer():
    global messages_chatgpt
    query = request.args.get('query', default='default query')
    messages_chatgpt.append({'role': 'user', 'content': query})
    
    def chat():
        openai.api_base = "https://apikeyplus.com/v1"  # 换成代理，一定要加 v1
        openai.api_key = "sk-0oJ42VRZX4MU1GXQ8fB76c349aF649AbA0Fe017cE88b5dC5"
        
        response = ""
        for resp in openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages_chatgpt,
            stream=True
        ):
            if 'content' in resp.choices[0].delta:
                content = resp.choices[0].delta.content
                response += content
                json_data = json.dumps({"message": content})
                yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据
        
        messages_chatgpt.append({'role': 'system', 'content': response})
        json_data = json.dumps({"message": 'done'})
        yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据
        print('结束')
    
    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    }
    
    return Response(chat(), content_type='text/event-stream', headers=headers)

@app.route('/api/wenxin')
def wenxin_get_answer():
    global messages_wenxin
    query = request.args.get('query', default='default query')
    messages_wenxin.append({'role': 'user', 'content': query})
    def chat():
        url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/ernie-speed-128k?access_token=" + get_access_token()

        payload = json.dumps({
            "messages":messages_wenxin,
            "stream": True
        })
        headers = {
            'Content-Type': 'application/json'
        }
        
        response = requests.request("POST", url, headers=headers, data=payload, stream=True)
        
        full_response = ""
        for line in response.iter_lines():
            line_decode = line.decode("UTF-8")
            if line_decode.startswith("data:"):  # 检查是否为 data: 行
                # 将 "data: " 替换为空字符串，然后解析为 JSON
                try:
                    json_line = json.loads(line_decode.replace("data: ", ""))
                    result = json_line.get("result", "")
                    full_response+=result
                    if result:
                        json_data = json.dumps({"message":result})
                        yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据
                except json.JSONDecodeError:
                    print("无法解析为 JSON 格式:", line_decode)
                    continue
        messages_wenxin.append({'role': 'assistant', 'content': full_response})
        json_data = json.dumps({"message": 'done'})
        yield f"data: {json_data}\n\n"  # 按照SSE格式发送数据
        print('结束')
    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    }
    print("messages_chatgpt:", messages_chatgpt)
    print("messages_tongyi:", messages_tongyi)
    print("messages_wenxin:", messages_wenxin)
    return Response(chat(), content_type='text/event-stream', headers=headers)

def get_access_token():
    """
    使用 API Key，Secret Key 获取access_token，替换下列示例中的应用API Key、应用Secret Key
    """
        
    url = "https://aip.baidubce.com/oauth/2.0/token?client_id=zJlxOu8SlyQFR5kh2i0lw5eS&client_secret=HysKv0tQl7o650EkELYO6URhfswFgQeB&grant_type=client_credentials"
    
    payload = json.dumps("")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json().get("access_token")



if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host='0.0.0.0', debug=True)
