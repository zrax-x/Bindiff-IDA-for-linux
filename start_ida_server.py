import subprocess
import os
import sys
import time
import socket
import json
import signal
from typing import Dict, List, Optional, Tuple
import config
import threading

class IDAProcess:
    """表示一个IDA进程的类"""
    def __init__(self, process: subprocess.Popen, port: int, binary_path: Optional[str] = None):
        self.process = process
        self.port = port
        self.binary_path = binary_path
        self.last_used = time.time()

class IDAServerManager:
    def __init__(self, ida_path=None, max_processes=2):
        # IDA Pro可能的默认安装路径
        self.default_paths = config.DEFAULT_IDA_PATHS
        self.ida_path = ida_path or config.IDA_PATH
        self.max_processes = max_processes
        self.ida_processes: Dict[int, IDAProcess] = {}  # port -> IDAProcess
        self.reserved_ports: Dict[int, float] = {}  # port -> reservation_time
        self.server_socket = None
        self.running = False
        self.lock = threading.Lock()  # 添加线程锁
        
    def _find_ida_path(self):
        """查找IDA Pro的安装路径"""
        # 首先检查环境变量
        if 'IDAPATH' in os.environ:
            path = os.path.join(os.environ['IDAPATH'], 
                              'idat64.exe' if os.name == 'nt' else 'idat64')
            if os.path.exists(path):
                return path
        
        # 检查默认安装路径
        for path in self.default_paths:
            if os.path.exists(path):
                return path
        
        raise FileNotFoundError("未找到IDA Pro安装路径，请指定IDAPATH环境变量或提供正确的路径")
    
    def _is_port_in_use(self, port):
        """检查端口是否被占用"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except socket.error:
            return True

    def _wait_for_port_release(self, port, timeout=30, check_interval=1):
        """等待端口释放"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self._is_port_in_use(port):
                return True
            time.sleep(check_interval)
        return False

    def _force_release_port(self, port):
        """强制释放端口"""
        if os.name == 'nt':
            try:
                # Windows
                subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
                subprocess.run(['taskkill', '/F', '/PID', str(port)], capture_output=True)
            except:
                pass
        else:
            try:
                # Linux/Unix
                subprocess.run(['lsof', '-ti', f':{port}'], capture_output=True, text=True)
                subprocess.run(['kill', '-9', f'$(lsof -ti:{port})'], shell=True)
            except:
                pass

    def _find_available_port(self, base_port: int) -> int:
        """查找可用的端口号"""
        with self.lock:  # 使用线程锁保护端口分配
            # 获取IDA服务器端口范围
            port_range = config.get_ida_server_ports(self.max_processes)
            
            # 清理过期的端口预留（超过60秒未使用的预留）
            current_time = time.time()
            expired_ports = [port for port, reserve_time in self.reserved_ports.items() 
                           if current_time - reserve_time > 60]
            for port in expired_ports:
                del self.reserved_ports[port]
            
            # 检查已使用和预留的端口
            used_ports = set(self.ida_processes.keys()) | set(self.reserved_ports.keys())
            
            # 在端口范围内查找未使用的端口
            for port in port_range:
                if port not in used_ports and not self._is_port_in_use(port):
                    # 预留这个端口
                    self.reserved_ports[port] = current_time
                    return port
                    
            # 如果所有端口都在使用，尝试停止最久未使用的进程
            if len(self.ida_processes) >= self.max_processes:
                lru_port, _ = self._get_least_recently_used_process()
                self.stop_ida_server(lru_port)
                # 预留这个端口
                self.reserved_ports[lru_port] = current_time
                return lru_port
                
            raise RuntimeError(f"无法找到可用端口（尝试范围：{port_range[0]}-{port_range[-1]}）")

    def _send_ida_request(self, port: int, request: dict) -> dict:
        """向指定端口的IDA服务器发送请求"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)  # 设置10秒超时
            sock.connect(('localhost', port))
            
            print("连接成功")
            
            # 确保请求是有效的JSON
            request_json = json.dumps(request)
            print(f"发送请求到端口 {port}: {request_json}")
            
            # 发送数据
            sock.sendall(request_json.encode('utf-8'))
            
            # 使用缓冲区接收响应
            response_data = bytearray()
            while True:
                try:
                    chunk = sock.recv(8192)  # 增大接收缓冲区
                    if not chunk:
                        break
                    response_data.extend(chunk)
                except socket.timeout:
                    raise Exception("接收数据超时")
            
            if not response_data:
                return {"error": "服务器没有返回数据"}
            
            # 解析响应
            try:
                response = json.loads(response_data.decode('utf-8'))
                print(f"收到响应: {json.dumps(response, ensure_ascii=False)[:200]}...")  # 只打印前200个字符
                return response
            except json.JSONDecodeError as e:
                print(f"解析响应失败，接收到的数据大小: {len(response_data)} 字节")
                print(f"数据预览: {response_data[:200]}...")  # 打印前200字节的数据
                return {"error": f"解析响应失败: {str(e)}"}
                
        except socket.error as e:
            return {"error": f"网络错误: {str(e)}"}
        except Exception as e:
            return {"error": f"与IDA服务器通信失败: {str(e)}"}
        finally:
            try:
                sock.close()
            except:
                pass

    def _get_process_for_binary(self, binary_path: str) -> Optional[IDAProcess]:
        """查找已加载指定二进制文件的进程"""
        for proc in self.ida_processes.values():
            if proc.binary_path == binary_path:
                return proc
        return None

    def _get_least_recently_used_process(self) -> Optional[Tuple[int, IDAProcess]]:
        """获取最久未使用的进程"""
        if not self.ida_processes:
            return None
        return min(self.ida_processes.items(), key=lambda x: x[1].last_used)

    def _wait_for_ida_server(self, port: int, timeout=30):
        """等待IDA服务器启动"""
        print(f"等待IDA服务器在端口 {port} 启动...")
        start_time = time.time()
        retry_interval = 0.5  # 重试间隔时间（秒）
        
        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                
                if result == 0:
                    # 发送简单的hello测试
                    try:
                        test_response = self._send_ida_request(port, {"action": "hello"})
                        if test_response.get("success") and test_response.get("message") == "hi":
                            print(f"IDA服务器在端口 {port} 已准备就绪")
                            return True
                        else:
                            print(f"服务器响应错误: {test_response.get('error', '未知错误')}")
                    except Exception as e:
                        print(f"测试请求失败: {str(e)}")
                
            except socket.error:
                pass
            
            print(f"等待IDA服务器启动... 已等待 {int(time.time() - start_time)} 秒")
            time.sleep(retry_interval)
            
        print(f"等待IDA服务器启动超时（{timeout}秒）")
        return False

    def _ensure_binary_loaded(self, binary_path: str, base_port: int) -> Optional[IDAProcess]:
        """确保二进制文件已加载，如果需要则启动新的IDA进程"""
        try:
            # 检查文件是否存在
            if not os.path.exists(binary_path) and not os.path.exists(binary_path + ".i64"):
                print(f"错误: 既找不到二进制文件 {binary_path} 也找不到IDA数据库文件 {binary_path}.i64")
                return None
                
            # 查找是否已有进程加载了该文件
            existing_process = self._get_process_for_binary(binary_path)
            if existing_process:
                existing_process.last_used = time.time()
                return existing_process
                
            # 获取可用端口
            try:
                port = self._find_available_port(base_port)
            except RuntimeError as e:
                print(f"获取可用端口失败: {str(e)}")
                return None
                
            try:
                # 获取当前目录下的IDA服务器脚本路径
                current_dir = os.path.dirname(os.path.abspath(__file__))
                ida_script_path = os.path.join(current_dir, "ida_decompile_server.py")
                
                # 检查是否存在IDA数据库文件
                idb_path = binary_path + ".i64"
                use_idb = os.path.exists(idb_path)
                
                # 确定要加载的文件路径
                load_path = binary_path
                
                # IDA命令行参数
                cmd = [
                    self.ida_path,
                    "-A",
                    "-B",  # 批处理模式
                    f"-S\"{ida_script_path} {port}\"",  # 修改参数传递格式
                    "-L\"ida_server.log\"",
                    f"\"{load_path}\""
                ]
                
                # 过滤掉空字符串
                cmd = [arg for arg in cmd if arg]

                print(f"[IDA cmd] {' '.join(cmd)}")
                print(f"{'使用IDA数据库文件' if use_idb else '分析二进制文件'}: {load_path}")
                
                # 启动IDA进程
                process = subprocess.Popen(
                    ' '.join(cmd),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # 创建新的IDA进程对象
                ida_process = IDAProcess(process, port, binary_path)
                
                # 等待IDA服务器启动
                if not self._wait_for_ida_server(port):
                    # 如果启动失败，检查是否是数据库损坏导致
                    if use_idb:
                        print("使用IDA数据库启动失败，尝试重新分析二进制文件...")
                        try:
                            os.rename(idb_path, idb_path + ".bak")
                            print(f"已备份损坏的数据库文件到: {idb_path}.bak")
                            # 终止当前进程
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                            # 递归调用自身重试，这次会创建新数据库
                            return self._ensure_binary_loaded(binary_path, base_port)
                        except Exception as e:
                            print(f"备份损坏的数据库文件失败: {str(e)}")
                    
                    # 确保进程被终止
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    
                    # 释放预留的端口
                    with self.lock:
                        if port in self.reserved_ports:
                            del self.reserved_ports[port]
                    
                    raise RuntimeError("IDA服务器启动超时")
                
                # 服务器成功启动，保存进程信息
                with self.lock:
                    self.ida_processes[port] = ida_process
                    # 移除端口预留
                    if port in self.reserved_ports:
                        del self.reserved_ports[port]
                
                print(f"IDA服务器已启动，{'加载数据库' if use_idb else '分析文件'}: {load_path}")
                return ida_process
                
            except Exception as e:
                # 确保在出错时释放预留的端口
                with self.lock:
                    if port in self.reserved_ports:
                        del self.reserved_ports[port]
                raise
                
        except Exception as e:
            print(f"启动IDA服务器时出错: {str(e)}")
            return None

    def stop_ida_server(self, port: int):
        """停止指定的IDA服务器进程"""
        with self.lock:  # 使用线程锁保护进程管理
            if port in self.ida_processes:
                ida_process = self.ida_processes[port]
                try:
                    print(f"正在停止端口 {port} 的IDA服务器...")
                    
                    # 先尝试优雅地停止IDA服务器
                    try:
                        self._send_ida_request(port, {"action": "stop_server"})
                    except Exception as e:
                        print(f"发送停止请求失败: {str(e)}")
                    
                    time.sleep(2)  # 增加等待时间，确保端口释放
                    
                    # 如果进程还在运行，强制终止
                    if ida_process.process.poll() is None:
                        print(f"进程仍在运行，尝试强制终止...")
                        if os.name != 'nt':
                            os.kill(ida_process.process.pid, signal.SIGTERM)
                            try:
                                ida_process.process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                print("SIGTERM 超时，使用 SIGKILL...")
                                os.kill(ida_process.process.pid, signal.SIGKILL)
                        else:
                            subprocess.run(['taskkill', '/F', '/T', '/PID', str(ida_process.process.pid)])
                    
                    # 确保端口被释放
                    if not self._wait_for_port_release(port, timeout=10):
                        print(f"警告：端口 {port} 可能未完全释放")
                        self._force_release_port(port)
                    
                    del self.ida_processes[port]
                    print(f"IDA服务器(端口:{port})已停止")
                    
                except Exception as e:
                    print(f"停止服务器时出错: {str(e)}")
                    # 即使出错也要尝试强制释放端口
                    self._force_release_port(port)

    def stop_all_servers(self):
        """停止所有IDA服务器进程"""
        ports = list(self.ida_processes.keys())
        for port in ports:
            self.stop_ida_server(port)

    def handle_client_request(self, request: dict, base_port: int) -> dict:
        """处理客户端请求"""
        try:
            action = request.get('action')
            print(f"action: {action}")
            
            if action == 'stop_server':
                self.stop_all_servers()
                return {"success": True, "message": "所有服务器已停止"}
                
            # 对于其他请求，需要确定要使用哪个IDA进程
            binary_path = request.get('binary_path')
            if not binary_path:
                return {"error": "未指定二进制文件路径"}
                
            # 确保二进制文件已加载
            ida_process = self._ensure_binary_loaded(binary_path, base_port)
            if not ida_process:
                return {"error": "无法加载指定的二进制文件"}
            
            # 转发请求到对应的IDA进程
            if action in ['decompile_function', 'get_functions']:
                print(f"向端口 {ida_process.port} 发送请求")
                return self._send_ida_request(ida_process.port, request)
            else:
                return {"error": f"未知的操作: {action}"}
                
        except Exception as e:
            return {"error": f"处理请求失败: {str(e)}"}

    def start(self, port=5000):
        """启动主服务器"""
        try:
            # 确保启动端口可用
            if self._is_port_in_use(port):
                print(f"端口 {port} 被占用，尝试释放...")
                self._force_release_port(port)
                if not self._wait_for_port_release(port, timeout=10):
                    raise RuntimeError(f"无法释放端口 {port}")
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', port))
            self.server_socket.listen(1)
            self.server_socket.settimeout(1.0)
            
            print(f"主服务器启动在端口 {port}，最大IDA进程数: {self.max_processes}")
            self.running = True
            
            while self.running:
                client = None
                try:
                    client, addr = self.server_socket.accept()
                    print(f"接收到来自 {addr} 的连接")
                    
                    data = client.recv(4096).decode('utf-8')
                    request = json.loads(data)
                    
                    response = self.handle_client_request(request, port + 1)
                    client.send(json.dumps(response).encode('utf-8'))
                    
                except socket.timeout:
                    continue
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
            self.stop_all_servers()
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass

def main():
    # 获取命令行参数
    import argparse
    parser = argparse.ArgumentParser(description='IDA Pro自动化服务器')
    parser.add_argument('-p', '--port', type=int, default=5000, help='服务器端口号')
    parser.add_argument('-n', '--num-processes', type=int, default=2, help='最大IDA进程数')
    args = parser.parse_args()
    
    # 创建服务器管理器
    manager = IDAServerManager(max_processes=args.num_processes)
    
    try:
        # 启动服务器
        manager.start(args.port)
    except KeyboardInterrupt:
        print("\n正在停止服务器...")
        manager.stop_all_servers()
    except Exception as e:
        print(f"服务器启动失败: {str(e)}")
        manager.stop_all_servers()

if __name__ == "__main__":
    main()