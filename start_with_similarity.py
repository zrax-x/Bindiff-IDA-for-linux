#!/usr/bin/env python3
"""
带相似度搜索功能的 BinDiff Online 启动脚本
"""

import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description='启动 BinDiff Online 带相似度搜索功能')
    parser.add_argument('--database', '-d', 
                       default='../gen_database/malware_simple.json',
                       help='恶意软件数据库文件路径')
    parser.add_argument('--port', '-p', type=int, default=5001,
                       help='Flask 应用端口')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Flask 应用监听地址')
    parser.add_argument('--debug', action='store_true',
                       help='启用调试模式')
    
    args = parser.parse_args()
    
    # 设置环境变量
    os.environ['MALWARE_DATABASE'] = os.path.abspath(args.database)
    
    # 检查数据库文件
    if not os.path.exists(args.database):
        print(f"❌ 错误: 数据库文件不存在: {args.database}")
        print("请确保数据库文件路径正确，或使用 --database 参数指定正确路径")
        return 1
    
    print("🚀 启动 BinDiff Online 带相似度搜索功能...")
    print(f"📁 数据库文件: {args.database}")
    print(f"🌐 监听地址: http://{args.host}:{args.port}")
    print(f"🔍 相似度搜索: http://{args.host}:{args.port}/similarity/search")
    print("📊 功能特性:")
    print("  ✓ 二进制文件比较")
    print("  ✓ 恶意软件相似度搜索")
    print("  ✓ TOP-K 相似样本检索")
    print("  ✓ RESTful API 接口")
    print("  ✓ 多格式结果导出")
    print()
    
    # 导入并运行应用
    try:
        from app import app
        app.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n👋 应用已停止")
        return 0
    except Exception as e:
        print(f"❌ 启动失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
