"""
IDA Pro自动化服务器脚本
用于处理二进制文件分析和反编译请求
"""

import ida_hexrays
import ida_funcs
import ida_lines
import ida_loader
import ida_auto
import ida_nalt
import ida_kernwin
import ida_pro
import ida_idaapi
import ida_segment
import idc
import idautils
import socket
import json
import sys
import os
import time

class IDAAnalysisServer:
    def __init__(self, port=5000):
        self.port = port
        self.server_socket = None
        self.running = False
        
        # 等待IDA完成初始分析
        print("等待IDA完成初始分析...")
        ida_auto.auto_wait()
    
    def decompile_function(self, func_addr):
        """
        反编译指定地址的函数
        """
        try:
            # 检查反编译器
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays反编译器不可用"}
            
            # 获取函数对象
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"地址 0x{func_addr:x} 处未找到函数"}
            
            # 反编译函数
            cfunc = ida_hexrays.decompile(func)
            if not cfunc:
                return {"error": f"函数 0x{func_addr:x} 反编译失败"}
            
            # 获取反编译结果
            decompiled_code = str(cfunc)
            cleaned_code = ida_lines.tag_remove(decompiled_code)
            
            # 获取函数信息
            func_name = ida_funcs.get_func_name(func_addr)
            
            return {
                "success": True,
                "function": {
                    "name": func_name,
                    "address": f"0x{func_addr:x}",
                    "start_addr": f"0x{func.start_ea:x}",
                    "end_addr": f"0x{func.end_ea:x}",
                    "size": func.size(),
                    "decompiled_code": cleaned_code
                }
            }
            
        except Exception as e:
            return {"error": f"反编译失败: {str(e)}"}
    
    def get_function_list(self):
        """
        获取当前二进制文件中的所有函数列表
        """
        try:
            functions = []
            # 使用 idautils.Functions() 获取所有函数
            for func_ea in idautils.Functions():
                func = ida_funcs.get_func(func_ea)
                if func:
                    functions.append({
                        "name": idc.get_func_name(func_ea),
                        "address": f"0x{func_ea:x}",
                        "size": func.size()
                    })
            
            return {"success": True, "functions": functions}
        except Exception as e:
            return {"error": f"获取函数列表失败: {str(e)}"}
    
    def stop(self):
        """
        停止服务器
        """
        try:
            self.running = False
            if self.server_socket:
                self.server_socket.close()
            print("IDA服务器已停止")
            # 退出IDA
            ida_pro.qexit(0)
        except Exception as e:
            print(f"停止服务器时出错: {str(e)}")
            ida_pro.qexit(1)
    
    def handle_request(self, request_data):
        """
        处理客户端请求
        """
        try:
            action = request_data.get('action')
            
            if action == 'hello':
                return {"success": True, "message": "hi"}
            
            elif action == 'decompile_function':
                func_addr = int(request_data.get('address'), 16)
                return self.decompile_function(func_addr)
                
            elif action == 'get_functions':
                return self.get_function_list()
                
            elif action == 'stop_server':
                return {"success": True, "message": "正在停止服务器"}
                
            else:
                return {"error": f"未知的操作: {action}"}
                
        except Exception as e:
            return {"error": f"处理请求时发生错误: {str(e)}"}
    
    def start(self):
        """
        启动服务器
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', self.port))
            self.server_socket.listen(1)
            self.server_socket.settimeout(1.0)  # 设置超时，以便能够检查停止信号
            
            print(f"IDA分析服务器启动在端口 {self.port}")
            self.running = True
            
            while self.running:
                client = None
                try:
                    client, addr = self.server_socket.accept()
                    print(f"接收到来自 {addr} 的连接")
                    
                    # 设置客户端连接的超时时间
                    client.settimeout(5.0)
                    
                    # 使用缓冲区接收数据
                    data = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if b'\n' in chunk or b'}' in chunk:  # 检查是否接收到完整的JSON
                            break
                    
                    # 如果没有收到任何数据
                    if not data:
                        print(f"警告: 从 {addr} 接收到空数据")
                        if client:
                            try:
                                error_response = {"error": "接收到空数据"}
                                client.send(json.dumps(error_response).encode('utf-8'))
                            except:
                                pass
                        continue
                    
                    # 尝试解析JSON数据
                    try:
                        decoded_data = data.decode('utf-8').strip()
                        print(f"收到数据: {decoded_data}")  # 调试输出
                        request = json.loads(decoded_data)
                    except json.JSONDecodeError as e:
                        print(f"JSON解析错误: {str(e)}, 原始数据: {decoded_data}")
                        if client:
                            try:
                                error_response = {"error": f"无效的JSON数据: {str(e)}"}
                                client.send(json.dumps(error_response).encode('utf-8'))
                            except:
                                pass
                        continue
                    
                    response = self.handle_request(request)
                    client.send(json.dumps(response).encode('utf-8'))
                    
                    # 如果是停止服务器的请求，退出循环
                    if request.get('action') == 'stop_server':
                        self.stop()
                        break
                        
                except socket.timeout:
                    continue
                except socket.error as e:
                    print(f"套接字错误: {str(e)}")
                    if client:
                        try:
                            error_response = {"error": f"网络错误: {str(e)}"}
                            client.send(json.dumps(error_response).encode('utf-8'))
                        except:
                            pass
                except Exception as e:
                    print(f"处理客户端请求时出错: {str(e)}")
                    if client:
                        try:
                            error_response = {"error": str(e)}
                            client.send(json.dumps(error_response).encode('utf-8'))
                        except:
                            pass
                finally:
                    if client:
                        try:
                            client.close()
                        except:
                            pass
                            
        except Exception as e:
            print(f"服务器运行时出错: {str(e)}")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass

def main():
    """
    主函数
    """
    try:
        # 使用 idc.ARGV 获取参数
        # idc.ARGV[0] 是脚本名称
        # idc.ARGV[1] 是端口号
        port = int(idc.ARGV[1]) if len(idc.ARGV) > 1 else 5000
        print(f"启动参数: 端口={port}")
        
        # 创建并启动服务器
        server = IDAAnalysisServer(port)
        server.start()
        
    except Exception as e:
        print(f"启动服务器失败: {str(e)}")
        ida_pro.qexit(1)

if __name__ == "__main__":
    main()