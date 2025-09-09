'''
https://diffing.quarkslab.com/differs/bindiff.html
'''

import os
import subprocess
import tempfile
import magic
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from bindiff_integration import run_bindiff_cli
from APTDiff import init_app
from start_ida_server import IDAServerManager
import atexit
import threading
import socket
import time
import config
import json

app = Flask(__name__)

# 从配置文件加载配置
app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# 初始化APT检测模块
init_app(app)

# 全局变量
ida_manager = None
ida_server_thread = None

def is_port_in_use(port):
    """检查端口是否被占用"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            is_used = (result == 0)
            return is_used
        finally:
            sock.close()
            
    except socket.error:
        return False

def init_ida_server():
    """初始化IDA服务器"""
    global ida_manager, ida_server_thread
    
    # 如果已经初始化过，直接返回
    if ida_manager is not None and ida_server_thread is not None and ida_server_thread.is_alive():
        return True
        
    try:
        # 验证配置
        config.validate_config()
        
        # 检查IDA客户端端口是否可用
        if is_port_in_use(config.IDA_CLIENT_PORT):
            print(f"错误：IDA客户端端口 {config.IDA_CLIENT_PORT} 已被占用")
            return False
            
        # 创建IDA服务器管理器实例
        ida_manager = IDAServerManager(max_processes=config.IDA_MAX_PROCESSES)
        
        # 启动主服务器线程
        ida_server_thread = threading.Thread(
            target=ida_manager.start, 
            args=(config.IDA_CLIENT_PORT,)
        )
        ida_server_thread.daemon = True
        ida_server_thread.start()
        
        # 等待服务器启动
        time.sleep(1)
        
        if not ida_server_thread.is_alive():
            print("错误：IDA服务器线程未能正常启动")
            return False
            
        print(f"IDA服务器初始化成功，运行在端口 {config.IDA_CLIENT_PORT}")
        return True
        
    except Exception as e:
        print(f"初始化IDA服务器失败: {str(e)}")
        return False

# 注册清理函数
@atexit.register
def cleanup():
    """清理资源"""
    global ida_manager
    if ida_manager:
        print("正在关闭IDA服务器...")
        try:
            ida_manager.stop_all_servers()
            ida_manager.running = False
            print("IDA服务器已关闭")
        except Exception as e:
            print(f"关闭IDA服务器时出错: {str(e)}")

def allowed_file(file_path):
    """检查文件是否为允许的类型"""
    try:
        file_type = magic.from_file(file_path, mime=True)
        file_desc = magic.from_file(file_path)
        
        print(f"文件类型: {file_type}")
        print(f"文件描述: {file_desc}")
        
        if file_type == 'application/x-dosexec':
            return True
        elif file_type == 'application/x-executable' or 'ELF' in file_desc:
            return True
        elif file_type == 'application/x-mach-binary':
            return True
        elif file_type == 'application/x-sharedlib':
            return True
        elif 'executable' in file_desc.lower():
            return True
            
        print(f"不支持的文件类型: {file_type}, {file_desc}")
        return False
    except Exception as e:
        print(f"文件类型检测错误: {e}")
        return False

def run_bindiff(primary_file, secondary_file):
    """
    Run BinDiff on two executable files and return the comparison results
    
    Returns a dictionary with the following structure:
    {
        "globalSimilarity": float, # 整体相似度
        "globalConfidence": float, # 整体置信度
        "matches": [               # 函数匹配列表
            (address1, address2, name1, name2, similarity, confidence),
            ...
        ]
    }
    """
    try:
        # 使用bindiff_integration中的函数，直接返回其结果
        return run_bindiff_cli(primary_file, secondary_file)
    except Exception as e:
        print(f"Error running BinDiff: {e}")
        # 返回一个包含空匹配列表的结构化结果
        return {
            "globalSimilarity": 0,
            "globalConfidence": 0,
            "matches": []
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    if 'primary_file' not in request.files or 'secondary_file' not in request.files:
        flash('Both files are required')
        return redirect(request.url)
    
    primary_file = request.files['primary_file']
    secondary_file = request.files['secondary_file']
    
    if primary_file.filename == '' or secondary_file.filename == '':
        flash('Both files must be selected')
        return redirect(request.url)
    
    primary_filename = secure_filename(primary_file.filename)
    secondary_filename = secure_filename(secondary_file.filename)
    
    primary_path = os.path.join(app.config['UPLOAD_FOLDER'], primary_filename)
    secondary_path = os.path.join(app.config['UPLOAD_FOLDER'], secondary_filename)
    
    # 先保存文件
    primary_file.save(primary_path)
    secondary_file.save(secondary_path)
    
    # 然后检查文件类型
    if not allowed_file(primary_path):
        os.remove(primary_path)  # 如果不是有效文件，则删除
        flash('Primary file is not a valid executable')
        return redirect(request.url)
    
    if not allowed_file(secondary_path):
        os.remove(secondary_path)  # 如果不是有效文件，则删除
        os.remove(primary_path)    # 同时删除已保存的primary文件
        flash('Secondary file is not a valid executable')
        return redirect(request.url)
    
    # Store file paths in session
    session['primary_path'] = primary_path
    session['secondary_path'] = secondary_path
    session['primary_name'] = primary_filename
    session['secondary_name'] = secondary_filename
    
    return redirect(url_for('compare'))

@app.route('/compare')
def compare():
    if 'primary_path' not in session or 'secondary_path' not in session:
        flash('Please upload files first')
        return redirect(url_for('index'))
    
    primary_path = session['primary_path']
    secondary_path = session['secondary_path']
    
    # 获取比较结果并传递给模板
    results = run_bindiff(primary_path, secondary_path)
    
    return render_template('results.html', 
                           results=results,
                           primary_filename=session['primary_name'],
                           secondary_filename=session['secondary_name'])

@app.route('/decompile')
def decompile_function():
    """获取函数的反编译结果"""
    try:
        file_type = request.args.get('file')  # 'primary' or 'secondary'
        address = request.args.get('address')
        
        if not file_type or not address:
            return jsonify({'success': False, 'error': '缺少必要参数'}), 400
            
        # 从session中获取文件路径
        if file_type == 'primary':
            binary_path = session.get('primary_path')
        else:
            binary_path = session.get('secondary_path')
            
        if not binary_path:
            return jsonify({'success': False, 'error': '找不到目标文件'}), 404
            
        # 移除地址字符串中的"0x"前缀
        address = address.replace('0x', '')
        
        # 发送反编译请求到IDA服务器
        request_data = {
            'action': 'decompile_function',
            'binary_path': binary_path,
            'address': address
        }
        
        # 确保IDA服务器已启动
        if not init_ida_server():
            return jsonify({'success': False, 'error': 'IDA服务器初始化失败'}), 500
            
        print(f"发送请求,{config.IDA_CLIENT_PORT},{request_data}")
        
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # 设置30秒超时
        
        try:
            # 连接到IDA服务器
            sock.connect(('localhost', config.IDA_CLIENT_PORT))
            
            # 发送请求
            sock.sendall(json.dumps(request_data).encode('utf-8'))
            
            # 接收响应
            response_data = bytearray()
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data.extend(chunk)
                
            # 解析响应
            response = json.loads(response_data.decode('utf-8'))
            
            if response.get('error'):
                return jsonify({'success': False, 'error': response['error']}), 500
                
            if response.get('success') and 'function' in response:
                function_data = response['function']
                # 格式化代码，确保完整显示
                code = function_data.get('decompiled_code', '// No decompiled code available')
                if code.endswith('...'):  # 如果代码被截断
                    code = code[:-3]  # 移除省略号
                
                return jsonify({
                    'success': True,
                    'code': code,
                    'name': function_data.get('name', 'Unknown'),
                    'address': function_data.get('address', '0x0'),
                    'size': function_data.get('size', 0)
                })
            else:
                return jsonify({'success': False, 'error': '无效的响应格式'}), 500
                
        except socket.error as e:
            return jsonify({'success': False, 'error': f'网络错误: {str(e)}'}), 500
        except json.JSONDecodeError as e:
            return jsonify({'success': False, 'error': f'解析响应失败: {str(e)}'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': f'未知错误: {str(e)}'}), 500
        finally:
            sock.close()
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # 在主进程中初始化IDA服务器
    if not init_ida_server():
        print("警告：IDA服务器初始化失败，某些功能可能无法使用")
    
    # 使用配置文件中的设置启动Flask应用
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False  # 禁用重新加载器，避免IDA服务器被重复初始化
    ) 