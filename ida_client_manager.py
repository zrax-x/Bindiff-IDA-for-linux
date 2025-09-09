import socket
import json
import sys
import os
import time
from start_ida_server import IDAServerManager

class IDAClientManager:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_manager = IDAServerManager()
        self.server_running = False
    
    def _send_request(self, data):
        """向IDA服务器发送请求"""
        try:
            # 创建socket连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 设置5秒超时
            sock.connect((self.host, self.port))
            
            # 发送数据
            request = json.dumps(data).encode('utf-8')
            sock.send(request)
            
            # 接收响应
            response = sock.recv(4096).decode('utf-8')
            sock.close()
            
            return json.loads(response)
        except Exception as e:
            print(f"发送请求时出错: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _check_server_status(self):
        """检查服务器是否在运行"""
        try:
            # 尝试连接服务器
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # 设置超时时间
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except:
            return False
    
    def start_server(self):
        """启动IDA服务器"""
        if self._check_server_status():
            print("IDA服务器已经在运行")
            return True
        
        print("正在启动IDA服务器...")
        
        # 获取IDA脚本路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        ida_script_path = os.path.join(current_dir, "ida_decompile_server.py")
        
        # 启动服务器
        if self.server_manager.start_server(ida_script_path, self.port):
            print("等待服务器初始化...")
            time.sleep(5)  # 等待服务器完全启动
            
            if self._check_server_status():
                print("IDA服务器启动成功")
                self.server_running = True
                return True
            else:
                print("IDA服务器启动失败")
                return False
        return False
    
    def stop_server(self):
        """停止IDA服务器"""
        if not self._check_server_status():
            print("IDA服务器未运行")
            return True
        
        print("正在停止IDA服务器...")
        try:
            # 发送停止请求到服务器
            response = self._send_request({"action": "stop_server"})
            if response.get("success"):
                # 等待服务器完全停止
                time.sleep(2)
                if not self._check_server_status():
                    print("IDA服务器已停止")
                    self.server_running = False
                    return True
                
            # 如果通过请求无法停止，尝试使用进程终止
            self.server_manager.stop_server()
            time.sleep(2)
            
            if not self._check_server_status():
                print("IDA服务器已停止")
                self.server_running = False
                return True
            else:
                print("IDA服务器停止失败")
                return False
                
        except Exception as e:
            print(f"停止服务器时出错: {str(e)}")
            return False
    
    def restart_server(self):
        """重启IDA服务器"""
        print("正在重启IDA服务器...")
        self.stop_server()
        time.sleep(2)  # 等待完全停止
        return self.start_server()

def main():
    if len(sys.argv) < 2:
        print("用法: python ida_client_manager.py <command>")
        print("命令:")
        print("  start  - 启动IDA服务器")
        print("  stop   - 停止IDA服务器")
        print("  restart- 重启IDA服务器")
        print("  status - 检查服务器状态")
        return
    
    manager = IDAClientManager()
    command = sys.argv[1].lower()
    
    try:
        if command == "start":
            manager.start_server()
        elif command == "stop":
            manager.stop_server()
        elif command == "restart":
            manager.restart_server()
        elif command == "status":
            if manager._check_server_status():
                print("IDA服务器正在运行")
            else:
                print("IDA服务器未运行")
        else:
            print(f"未知命令: {command}")
    except KeyboardInterrupt:
        print("\n操作被用户中断")
        if manager.server_running:
            manager.stop_server()
    except Exception as e:
        print(f"发生错误: {str(e)}")
        if manager.server_running:
            manager.stop_server()

if __name__ == "__main__":
    main()