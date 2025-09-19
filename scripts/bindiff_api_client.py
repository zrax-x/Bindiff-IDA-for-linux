#!/usr/bin/env python3
"""
BinDiff API 客户端脚本
支持目录扫描、批量相似度搜索和结果JSON输出

功能特性:
- 自动扫描目标目录中的可执行文件
- 通过API调用BinDiff相似度搜索服务
- 支持批量处理和并发请求
- 完整的错误处理和重试机制
- 结果保存为JSON格式
- 支持多种输出模式和过滤条件

作者: BinDiff API Client
版本: 1.0.0
"""

import os
import sys
import json
import time
import argparse
import requests
import hashlib
import magic
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class BinDiffAPIClient:
    """BinDiff API客户端类"""
    
    def __init__(self, base_url: str = "http://localhost:5001", timeout: int = 300):
        """
        初始化API客户端
        
        Args:
            base_url: BinDiff服务的基础URL
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BinDiff-API-Client/1.0.0'
        })
        
    def check_service_health(self) -> bool:
        """检查服务是否可用"""
        try:
            logger.info("正在检查BinDiff服务状态...")
            
            # 检查相似度搜索API
            response = self.session.get(
                f"{self.base_url}/similarity/api/database/info",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ BinDiff服务正常运行")
                    logger.info(f"📊 数据库统计: {data.get('statistics', {})}")
                    return True
            
            logger.error(f"❌ 服务响应异常: {response.status_code}")
            return False
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ 无法连接到BinDiff服务: {e}")
            return False
            
    def get_database_info(self) -> Optional[Dict]:
        """获取数据库信息"""
        try:
            response = self.session.get(
                f"{self.base_url}/similarity/api/database/info",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"获取数据库信息失败: {e}")
            return None
            
    def request_cleanup(self) -> bool:
        """请求服务端清理临时文件"""
        try:
            logger.info("🧹 请求服务端清理临时文件...")
            
            response = self.session.post(
                f"{self.base_url}/similarity/api/cleanup",
                timeout=30  # 清理操作可能需要一些时间
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    cleaned_files = data.get('cleaned_files', 0)
                    message = data.get('message', '清理完成')
                    logger.info(f"✅ {message}")
                    if cleaned_files > 0:
                        logger.info(f"🗑️ 清理了 {cleaned_files} 个临时文件")
                    return True
                else:
                    logger.error(f"❌ 服务端清理失败: {data.get('error', '未知错误')}")
                    return False
            else:
                logger.warning(f"⚠️ 清理请求失败 (HTTP {response.status_code})")
                logger.info("💡 提示：服务端已在每次搜索后自动清理临时文件")
                return False
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ 无法连接清理接口: {e}")
            logger.info("💡 提示：服务端已在每次搜索后自动清理临时文件")
            logger.info("📁 如需手动清理，可在服务器上执行: rm -rf ./out/*")
            return False
        except Exception as e:
            logger.error(f"请求清理失败: {e}")
            return False
            
    def search_similarity(self, file_path: str, top_k: int = 10) -> Optional[Dict]:
        """
        执行相似度搜索
        
        Args:
            file_path: 要搜索的文件路径
            top_k: 返回最相似的前K个结果
            
        Returns:
            搜索结果字典或None
        """
        try:
            # 准备请求数据
            request_data = {
                'file_path': os.path.abspath(file_path),
                'top_k': top_k
            }
            
            logger.info(f"🔍 正在搜索文件: {file_path}")
            logger.info(f"📊 请求TOP-{top_k}相似样本")
            
            start_time = time.time()
            
            # 发送API请求
            response = self.session.post(
                f"{self.base_url}/similarity/api/search",
                json=request_data,
                timeout=self.timeout
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            response.raise_for_status()
            result = response.json()
            
            if result.get('success'):
                result_count = len(result.get('results', []))
                logger.info(f"✅ 搜索完成，找到 {result_count} 个相似样本，耗时 {duration:.2f} 秒")
                
                # 添加额外的元数据
                result['search_duration'] = duration
                result['search_timestamp'] = datetime.now().isoformat()
                result['search_file'] = file_path
                result['client_version'] = "1.0.0"
                
                return result
            else:
                logger.error(f"❌ 搜索失败: {result.get('error', '未知错误')}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"❌ 搜索超时: {file_path}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ 网络请求失败: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ 搜索过程中出错: {e}")
            return None

class FileScanner:
    """文件扫描器类"""
    
    # 支持的可执行文件扩展名
    EXECUTABLE_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd',  # Windows
        '.elf', '.so', '.bin', '.out',  # Linux
        '.app', '.dylib', '.bundle',  # macOS
        '.apk', '.dex',  # Android
        '.jar', '.class',  # Java
        '.py', '.sh', '.pl', '.rb'  # Scripts
    }
    
    # 支持的MIME类型
    EXECUTABLE_MIMES = {
        'application/x-executable',
        'application/x-sharedlib',
        'application/x-object',
        'application/octet-stream',
        'application/x-dosexec',
        'application/x-mach-binary',
        'text/x-shellscript'
    }
    
    def __init__(self, use_magic: bool = True):
        """
        初始化文件扫描器
        
        Args:
            use_magic: 是否使用libmagic进行文件类型检测
        """
        self.use_magic = use_magic
        
    def is_executable_file(self, file_path: str) -> bool:
        """
        检查文件是否为可执行文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否为可执行文件
        """
        if not os.path.isfile(file_path):
            return False
            
        try:
            # 首先检查文件扩展名
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.EXECUTABLE_EXTENSIONS:
                return True
                
            # 如果启用magic检测
            if self.use_magic:
                try:
                    # 检查MIME类型
                    mime_type = magic.from_file(file_path, mime=True)
                    if mime_type in self.EXECUTABLE_MIMES:
                        return True
                        
                    # 检查文件描述
                    file_desc = magic.from_file(file_path)
                    if any(keyword in file_desc.lower() for keyword in 
                          ['executable', 'binary', 'elf', 'pe32', 'mach-o']):
                        return True
                        
                except Exception as e:
                    logger.debug(f"Magic检测失败 {file_path}: {e}")
                    
            # 检查文件权限（Linux/macOS）
            if os.access(file_path, os.X_OK):
                return True
                
        except Exception as e:
            logger.debug(f"文件类型检查失败 {file_path}: {e}")
            
        return False
        
    def scan_directory(self, directory: str, recursive: bool = True, 
                      max_files: Optional[int] = None) -> List[str]:
        """
        扫描目录中的可执行文件
        
        Args:
            directory: 目标目录路径
            recursive: 是否递归扫描子目录
            max_files: 最大文件数量限制
            
        Returns:
            可执行文件路径列表
        """
        logger.info(f"📁 开始扫描目录: {directory}")
        logger.info(f"🔄 递归扫描: {'是' if recursive else '否'}")
        
        executable_files = []
        scanned_count = 0
        
        try:
            if recursive:
                # 递归扫描
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        scanned_count += 1
                        
                        if scanned_count % 100 == 0:
                            logger.info(f"已扫描 {scanned_count} 个文件...")
                            
                        if self.is_executable_file(file_path):
                            executable_files.append(file_path)
                            logger.debug(f"✅ 发现可执行文件: {file_path}")
                            
                            if max_files and len(executable_files) >= max_files:
                                logger.info(f"⚠️ 已达到最大文件数量限制: {max_files}")
                                break
                                
                    if max_files and len(executable_files) >= max_files:
                        break
            else:
                # 仅扫描当前目录
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    scanned_count += 1
                    
                    if self.is_executable_file(file_path):
                        executable_files.append(file_path)
                        logger.debug(f"✅ 发现可执行文件: {file_path}")
                        
                        if max_files and len(executable_files) >= max_files:
                            logger.info(f"⚠️ 已达到最大文件数量限制: {max_files}")
                            break
                            
        except Exception as e:
            logger.error(f"❌ 扫描目录时出错: {e}")
            
        logger.info(f"📊 扫描完成: 共扫描 {scanned_count} 个文件，发现 {len(executable_files)} 个可执行文件")
        return executable_files

class BatchProcessor:
    """批量处理器类"""
    
    def __init__(self, api_client: BinDiffAPIClient, max_workers: int = 4):
        """
        初始化批量处理器
        
        Args:
            api_client: API客户端实例
            max_workers: 最大并发工作线程数
        """
        self.api_client = api_client
        self.max_workers = max_workers
        
    def process_files_batch(self, file_paths: List[str], top_k: int = 10,
                           progress_callback=None) -> List[Dict[str, Any]]:
        """
        批量处理文件
        
        Args:
            file_paths: 文件路径列表
            top_k: 每个文件返回的相似样本数量
            progress_callback: 进度回调函数
            
        Returns:
            处理结果列表
        """
        logger.info(f"🚀 开始批量处理 {len(file_paths)} 个文件")
        logger.info(f"⚙️ 并发线程数: {self.max_workers}")
        
        results = []
        completed = 0
        failed = 0
        
        start_time = time.time()
        
        # 使用线程池进行并发处理
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_file = {
                executor.submit(self._process_single_file, file_path, top_k): file_path
                for file_path in file_paths
            }
            
            # 处理完成的任务
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        results.append({
                            'file_path': file_path,
                            'success': True,
                            'data': result
                        })
                        logger.info(f"✅ [{completed}/{len(file_paths)}] 完成: {os.path.basename(file_path)}")
                    else:
                        failed += 1
                        results.append({
                            'file_path': file_path,
                            'success': False,
                            'error': '搜索失败'
                        })
                        logger.error(f"❌ [{completed}/{len(file_paths)}] 失败: {os.path.basename(file_path)}")
                        
                except Exception as e:
                    failed += 1
                    results.append({
                        'file_path': file_path,
                        'success': False,
                        'error': str(e)
                    })
                    logger.error(f"❌ [{completed}/{len(file_paths)}] 异常: {os.path.basename(file_path)} - {e}")
                    
                # 调用进度回调
                if progress_callback:
                    progress_callback(completed, len(file_paths), failed)
                    
        end_time = time.time()
        duration = end_time - start_time
        
        success_count = len(file_paths) - failed
        logger.info(f"📊 批量处理完成:")
        logger.info(f"   ✅ 成功: {success_count}/{len(file_paths)}")
        logger.info(f"   ❌ 失败: {failed}/{len(file_paths)}")
        logger.info(f"   ⏱️ 总耗时: {duration:.2f} 秒")
        logger.info(f"   📈 平均速度: {len(file_paths)/duration:.2f} 文件/秒")
        
        return results
        
    def _process_single_file(self, file_path: str, top_k: int) -> Optional[Dict]:
        """处理单个文件"""
        try:
            return self.api_client.search_similarity(file_path, top_k)
        except Exception as e:
            logger.error(f"处理文件失败 {file_path}: {e}")
            return None

class ResultManager:
    """结果管理器类"""
    
    @staticmethod
    def save_results(results: List[Dict[str, Any]], output_file: str, 
                    include_metadata: bool = True) -> bool:
        """
        保存结果到JSON文件
        
        Args:
            results: 结果列表
            output_file: 输出文件路径
            include_metadata: 是否包含元数据
            
        Returns:
            保存是否成功
        """
        try:
            # 准备输出数据
            output_data = {
                'results': results
            }
            
            if include_metadata:
                output_data['metadata'] = {
                    'total_files': len(results),
                    'successful_files': sum(1 for r in results if r.get('success')),
                    'failed_files': sum(1 for r in results if not r.get('success')),
                    'generation_time': datetime.now().isoformat(),
                    'client_version': '1.0.0'
                }
                
            # 确保输出目录存在
            output_dir = os.path.dirname(output_file)
            if output_dir:  # 只有当目录不为空时才创建
                os.makedirs(output_dir, exist_ok=True)
            
            # 保存到JSON文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
                
            logger.info(f"💾 结果已保存到: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ 保存结果失败: {e}")
            return False
            
    @staticmethod
    def filter_results(results: List[Dict[str, Any]], 
                      min_similarity: float = 0.0,
                      families: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        过滤结果
        
        Args:
            results: 原始结果
            min_similarity: 最小相似度阈值
            families: 指定的家族列表
            
        Returns:
            过滤后的结果
        """
        filtered_results = []
        
        for result in results:
            if not result.get('success'):
                filtered_results.append(result)
                continue
                
            data = result.get('data', {})
            search_results = data.get('results', [])
            
            # 过滤相似度和家族
            filtered_search_results = []
            for item in search_results:
                similarity = item.get('similarity', 0)
                family = item.get('family', '')
                
                if similarity >= min_similarity:
                    if not families or family in families:
                        filtered_search_results.append(item)
                        
            # 更新结果
            if filtered_search_results:
                new_data = data.copy()
                new_data['results'] = filtered_search_results
                new_data['total_results'] = len(filtered_search_results)
                
                filtered_results.append({
                    'file_path': result['file_path'],
                    'success': True,
                    'data': new_data
                })
            else:
                # 如果没有匹配结果，标记为失败
                filtered_results.append({
                    'file_path': result['file_path'],
                    'success': False,
                    'error': 'No results match filter criteria'
                })
                
        return filtered_results

def create_progress_callback():
    """创建进度回调函数"""
    def progress_callback(completed: int, total: int, failed: int):
        percentage = (completed / total) * 100
        success_rate = ((completed - failed) / completed) * 100 if completed > 0 else 0
        
        logger.info(f"📈 进度: {completed}/{total} ({percentage:.1f}%) | "
                   f"成功率: {success_rate:.1f}% | 失败: {failed}")
    
    return progress_callback

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='BinDiff API客户端 - 批量相似度搜索工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 扫描目录并搜索相似样本
  %(prog)s /path/to/malware/samples -o results.json
  
  # 指定服务地址和TOP-K参数
  %(prog)s /path/to/samples --url http://192.168.1.100:5001 --top-k 20
  
  # 递归扫描并限制文件数量
  %(prog)s /path/to/samples -r --max-files 100
  
  # 过滤结果（最小相似度和指定家族）
  %(prog)s /path/to/samples --min-similarity 0.8 --families Patchwork APT29
  
  # 调整并发参数
  %(prog)s /path/to/samples --workers 8 --timeout 600
        """
    )
    
    # 必需参数
    parser.add_argument('target_directory',
                       help='目标目录路径')
    
    # 输出选项
    parser.add_argument('-o', '--output', 
                       default=f'bindiff_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
                       help='输出文件路径 (默认: bindiff_results_<timestamp>.json)')
    
    # 服务配置
    parser.add_argument('--url', default='http://localhost:5001',
                       help='BinDiff服务URL (默认: http://localhost:5001)')
    parser.add_argument('--timeout', type=int, default=300,
                       help='请求超时时间(秒) (默认: 300)')
    
    # 搜索参数
    parser.add_argument('--top-k', type=int, default=10,
                       help='返回最相似的前K个结果 (默认: 10)')
    
    # 扫描选项
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='递归扫描子目录')
    parser.add_argument('--max-files', type=int,
                       help='最大文件数量限制')
    parser.add_argument('--no-magic', action='store_true',
                       help='禁用libmagic文件类型检测')
    
    # 并发选项
    parser.add_argument('--workers', type=int, default=4,
                       help='并发工作线程数 (默认: 4)')
    
    # 过滤选项
    parser.add_argument('--min-similarity', type=float, default=0.0,
                       help='最小相似度阈值 (默认: 0.0)')
    parser.add_argument('--families', nargs='+',
                       help='指定恶意软件家族列表')
    
    # 其他选项
    parser.add_argument('--check-only', action='store_true',
                       help='仅检查服务状态，不执行搜索')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='启用详细日志输出')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # 验证参数
    if not os.path.isdir(args.target_directory):
        logger.error(f"❌ 目标目录不存在: {args.target_directory}")
        return 1
        
    if args.top_k <= 0 or args.top_k > 100:
        logger.error(f"❌ TOP-K值必须在1-100之间: {args.top_k}")
        return 1
        
    logger.info(f"🚀 BinDiff API客户端启动")
    logger.info(f"📁 目标目录: {args.target_directory}")
    logger.info(f"🌐 服务地址: {args.url}")
    logger.info(f"📊 TOP-K: {args.top_k}")
    
    try:
        # 初始化API客户端
        api_client = BinDiffAPIClient(args.url, args.timeout)
        
        # 检查服务状态
        if not api_client.check_service_health():
            logger.error("❌ BinDiff服务不可用，请检查服务是否正常运行")
            return 1
            
        if args.check_only:
            logger.info("✅ 服务状态检查完成")
            return 0
            
        # 初始化文件扫描器
        scanner = FileScanner(use_magic=not args.no_magic)
        
        # 扫描文件
        executable_files = scanner.scan_directory(
            args.target_directory,
            recursive=args.recursive,
            max_files=args.max_files
        )
        
        if not executable_files:
            logger.warning("⚠️ 未发现任何可执行文件")
            return 0
            
        # 初始化批量处理器
        processor = BatchProcessor(api_client, args.workers)
        
        # 执行批量处理
        progress_callback = create_progress_callback()
        results = processor.process_files_batch(
            executable_files,
            args.top_k,
            progress_callback
        )
        
        # 过滤结果
        if args.min_similarity > 0 or args.families:
            logger.info(f"🔍 应用过滤条件...")
            results = ResultManager.filter_results(
                results,
                args.min_similarity,
                args.families
            )
            
        # 保存结果
        if ResultManager.save_results(results, args.output):
            logger.info(f"🎉 处理完成，结果已保存到: {args.output}")
            
            # 提供清理建议
            api_client.request_cleanup()
            
            return 0
        else:
            logger.error("❌ 保存结果失败")
            return 1
            
    except KeyboardInterrupt:
        logger.info("⚠️ 用户中断操作")
        return 1
    except Exception as e:
        logger.error(f"❌ 程序执行失败: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
