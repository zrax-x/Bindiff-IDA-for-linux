"""
BinDiff Integration Example

This module provides examples of how to integrate the actual BinDiff functionality
into the Flask application. Replace the placeholder implementation in app.py with
the appropriate code from this file based on your specific BinDiff setup.
"""

import os
import subprocess
import json
import tempfile
import xml.etree.ElementTree as ET
import hashlib
import sys
from pathlib import Path
from dotenv import load_dotenv

# 尝试加载.env文件中的环境变量
# 首先尝试加载.env文件
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    # 如果.env文件不存在，尝试使用默认IDA路径
    print("Warning: .env file not found. Using default settings.")

# 设置IDA_PATH环境变量，优先使用环境变量中的值
ida_path = os.environ.get('IDA_PATH')
if ida_path:
    print(f"Using IDA_PATH from environment: {ida_path}")
    os.environ["IDA_PATH"] = ida_path
else:
    # 如果环境变量中没有设置IDA_PATH，可以设置一个默认值
    # 根据操作系统自动检测可能的默认路径
    if sys.platform.startswith('win'):
        default_ida_path = "C:/Program Files/IDA Pro"
    elif sys.platform.startswith('darwin'):
        default_ida_path = "/Applications/IDA Pro.app/Contents/MacOS"
    else:  # Linux
        default_ida_path = "/opt/idapro"
    
    # 如果默认路径存在，则使用它
    if os.path.exists(default_ida_path):
        print(f"Using default IDA_PATH: {default_ida_path}")
        os.environ["IDA_PATH"] = default_ida_path
    else:
        print("Warning: IDA_PATH not set and default path not found. BinDiff may not work correctly.")

# 导入BinDiff - 确保IDA_PATH已经设置
try:
    from bindiff import BinDiff
except ImportError as e:
    print(f"Error importing BinDiff module: {e}")
    print("Please make sure python-bindiff is installed and IDA_PATH is correctly set.")
    print(f"Current IDA_PATH: {os.environ.get('IDA_PATH', 'Not set')}")

def calculate_file_sha1(file_path):
    """
    Calculate SHA1 hash for a file
    """
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b''):
            sha1.update(chunk)
    return sha1.hexdigest()


def run_bindiff_cli(primary_file, secondary_file):
    """
    Run BinDiff using the command line interface
    
    This function assumes BinDiff is properly installed and available in your PATH.
    Adjust the command and parameters based on your BinDiff version and setup.
    """
    try:
        # Calculate SHA1 for both files
        primary_sha1 = calculate_file_sha1(primary_file)
        secondary_sha1 = calculate_file_sha1(secondary_file)
        
        # Create a combined SHA1 value (you could customize this combination)
        combined_sha1 = hashlib.sha1((primary_sha1 + secondary_sha1).encode()).hexdigest()
        
        # Define output file name using the SHA1
        output_file_name = f"{combined_sha1}.BinDiff"
        output_file_path = os.path.join("out", output_file_name)
        
        # 确保out目录存在
        os.makedirs("out", exist_ok=True)
        
        print(f"Running BinDiff comparison...")
        print(f"Primary file: {primary_file}")
        print(f"Secondary file: {secondary_file}")
        print(f"Output file: {output_file_path}")
        
        diff = BinDiff.from_binary_files(primary_file, secondary_file, output_file_path)
        print(f"Global similarity: {diff.similarity}, Global confidence: {diff.confidence}")
        
        matches = []
        print("Extracting function matches...")
        for match in diff.iter_function_matches():
            _, _, funcMatch = match
            matches.append((funcMatch.address1, funcMatch.address2, funcMatch.name1, funcMatch.name2, funcMatch.similarity, funcMatch.confidence))
        
        print(f"Found {len(matches)} function matches.")
        
        result = {
            "globalSimilarity": diff.similarity,
            "globalConfidence": diff.confidence,
            "matches": matches
        }

        return result
        
    except Exception as e:
        print(f"Error in BinDiff processing: {e}")
        import traceback
        traceback.print_exc()
        return {
            "globalSimilarity": 0,
            "globalConfidence": 0,
            "matches": []
        }