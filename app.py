import os
import subprocess
import tempfile
import magic
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from bindiff_integration import run_bindiff_cli

# 定义目录常量
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'out'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'so', 'bin', 'elf', 'out'}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-for-testing')

# 确保必要的目录存在
def ensure_directories_exist():
    """确保上传和输出目录存在"""
    for directory in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"已创建目录: {directory}")

# 在应用初始化时创建目录
ensure_directories_exist()

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

def allowed_file(file_path):
    """
    使用python-magic检查文件是否为可执行文件(PE或ELF)
    
    Args:
        file_path: 文件路径
    
    Returns:
        bool: 如果文件是可执行文件则返回True，否则返回False
    """
    try:
        # 获取文件的MIME类型
        file_type = magic.from_file(file_path, mime=True)
        
        # 使用magic获取详细的文件类型描述
        file_desc = magic.from_file(file_path)
        
        print(f"文件类型: {file_type}")
        print(f"文件描述: {file_desc}")
        
        # 检查是否为可执行文件类型
        if file_type == 'application/x-dosexec':
            # Windows PE可执行文件
            return True
        elif file_type == 'application/x-executable' or 'ELF' in file_desc:
            # Linux ELF可执行文件
            return True
        elif file_type == 'application/x-mach-binary':
            # macOS Mach-O可执行文件
            return True
        elif file_type == 'application/x-sharedlib':
            # 共享库文件(.so, .dll等)
            return True
        elif 'executable' in file_desc.lower():
            # 其他描述为可执行的文件
            return True
            
        # 不是已知的可执行文件类型
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
    ensure_directories_exist()
    
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

if __name__ == '__main__':
    app.run(debug=True) 