import os

# 端口配置
FLASK_PORT = 5001  # Flask Web应用端口
IDA_CLIENT_PORT = 6001  # IDA客户端管理器端口
IDA_SERVER_START_PORT = 7001  # IDA服务器起始端口

# IDA服务器配置
IDA_MAX_PROCESSES = 2  # 最大IDA进程数
IDA_SERVER_PORT_RANGE = (IDA_SERVER_START_PORT, IDA_SERVER_START_PORT + 99)  # IDA服务器端口范围

# 目录配置
UPLOAD_FOLDER = 'uploads'  # 上传文件目录
OUTPUT_FOLDER = 'out'  # 输出文件目录
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'elf', 'out'}  # 允许的文件类型

# 数据库配置
DATABASE_FILE = os.environ.get('MALWARE_DATABASE', '../gen_database/malware_simple.json')  # 恶意软件数据库文件路径

# IDA Pro路径配置
DEFAULT_IDA_PATHS = [
    # Linux路径
    "/home/zraxx/ida-pro-9.1/idat",
    # Windows路径
    "C:\\Program Files\\IDA Pro 7.5\\idat64.exe",
]

# 从环境变量获取IDA路径，如果未设置则使用默认路径
IDA_PATH = os.environ.get('IDAPATH', None)
if not IDA_PATH:
    for path in DEFAULT_IDA_PATHS:
        if os.path.exists(path):
            IDA_PATH = path
            break

# Flask应用配置
FLASK_DEBUG = True  # 是否启用调试模式
FLASK_HOST = "0.0.0.0"  # 监听地址
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 最大上传文件大小（50MB）
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-for-testing')  # 密钥

# 日志配置
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

def validate_config():
    """验证配置是否有效"""
    if not IDA_PATH:
        raise ValueError("未找到IDA Pro路径，请设置IDAPATH环境变量或检查默认路径")
        
    if not os.path.exists(IDA_PATH):
        raise ValueError(f"IDA Pro路径无效: {IDA_PATH}")
        
    # 确保端口范围合理
    if IDA_SERVER_START_PORT <= IDA_CLIENT_PORT:
        raise ValueError("IDA服务器起始端口必须大于IDA客户端端口")
        
    if FLASK_PORT == IDA_CLIENT_PORT or FLASK_PORT in range(*IDA_SERVER_PORT_RANGE):
        raise ValueError("Flask端口与IDA端口冲突")
        
    # 创建必要的目录
    for directory in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"已创建目录: {directory}")

def get_ida_server_ports(count=None):
    """获取IDA服务器端口范围
    
    Args:
        count: 需要的端口数量，如果为None则返回整个范围
        
    Returns:
        如果指定count，返回前count个端口的列表
        否则返回整个端口范围的元组
    """
    if count is None:
        return IDA_SERVER_PORT_RANGE
    return list(range(IDA_SERVER_PORT_RANGE[0], 
                     min(IDA_SERVER_PORT_RANGE[0] + count, IDA_SERVER_PORT_RANGE[1] + 1))) 