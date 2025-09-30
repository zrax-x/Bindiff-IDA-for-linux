"""
数据库加载模块
用于加载和管理恶意软件样本数据库
"""

import json
import os
import hashlib
from typing import List, Dict, Any, Tuple
from bindiff_integration import convert_pe_to_binexport, compare_binexport_files
from collections import defaultdict
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MalwareDatabaseLoader:
    def __init__(self, database_file: str = None):
        """
        初始化数据库加载器
        
        Args:
            database_file: 数据库JSON文件路径
        """
        self.database_file = database_file
        self.samples = []
        self.family_index = defaultdict(list)  # 按family分类的索引
        
        if database_file and os.path.exists(database_file):
            self.load_database()
    
    def load_database(self) -> bool:
        """
        从JSON文件加载数据库
        
        Returns:
            bool: 加载是否成功
        """
        try:
            logger.info(f"正在加载数据库文件: {self.database_file}")
            
            with open(self.database_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 检查数据库格式
            if isinstance(data, dict) and 'samples' in data:
                # 新格式：有metadata和samples字段
                self.samples = data['samples']
                logger.info(f"检测到新数据库格式，metadata: {data.get('metadata', {})}")
            elif isinstance(data, list):
                # 旧格式：直接是样本数组
                self.samples = data
                logger.info("检测到旧数据库格式")
            else:
                raise ValueError("未知的数据库格式")
            
            # 构建family索引
            self.family_index.clear()
            for i, sample in enumerate(self.samples):
                family = sample.get('family', 'Unknown')
                self.family_index[family].append(i)
            
            logger.info(f"成功加载 {len(self.samples)} 个样本")
            logger.info(f"包含 {len(self.family_index)} 个家族: {list(self.family_index.keys())}")
            
            return True
            
        except Exception as e:
            logger.error(f"加载数据库失败: {str(e)}")
            return False
    
    def get_sample_by_index(self, index: int) -> Dict[str, Any]:
        """
        根据索引获取样本信息
        
        Args:
            index: 样本索引
            
        Returns:
            Dict: 样本信息
        """
        if 0 <= index < len(self.samples):
            return self.samples[index]
        return None
    
    def get_samples_by_family(self, family: str) -> List[Dict[str, Any]]:
        """
        根据家族名称获取样本列表
        
        Args:
            family: 家族名称
            
        Returns:
            List: 该家族的所有样本
        """
        indices = self.family_index.get(family, [])
        return [self.samples[i] for i in indices]
    
    def get_all_families(self) -> List[str]:
        """
        获取所有家族名称
        
        Returns:
            List[str]: 所有家族名称列表
        """
        return list(self.family_index.keys())
    
    def get_samples_by_families(self, families: List[str]) -> List[Dict[str, Any]]:
        """
        根据家族列表获取样本
        
        Args:
            families: 家族名称列表
            
        Returns:
            List[Dict]: 匹配的样本列表
        """
        if not families:
            return self.samples
        
        filtered_samples = []
        for family in families:
            if family in self.family_index:
                for index in self.family_index[family]:
                    filtered_samples.append(self.samples[index])
        
        return filtered_samples
    
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取数据库统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = {
            'total_samples': len(self.samples),
            'total_families': len(self.family_index),
            'family_distribution': {}
        }
        
        for family, indices in self.family_index.items():
            stats['family_distribution'][family] = len(indices)
        
        return stats
    
    def validate_database(self) -> Dict[str, Any]:
        """
        验证数据库完整性
        
        Returns:
            Dict: 验证结果
        """
        validation_result = {
            'valid_samples': 0,
            'invalid_samples': 0,
            'missing_files': [],
            'invalid_entries': []
        }
        
        for i, sample in enumerate(self.samples):
            try:
                # 检查必要字段
                if not all(key in sample for key in ['family', 'hash', 'path']):
                    validation_result['invalid_entries'].append({
                        'index': i,
                        'reason': 'Missing required fields',
                        'sample': sample
                    })
                    validation_result['invalid_samples'] += 1
                    continue
                
                # 检查文件是否存在
                if not os.path.exists(sample['path']):
                    validation_result['missing_files'].append({
                        'index': i,
                        'path': sample['path'],
                        'hash': sample.get('hash', 'Unknown')
                    })
                    validation_result['invalid_samples'] += 1
                    continue
                
                validation_result['valid_samples'] += 1
                
            except Exception as e:
                validation_result['invalid_entries'].append({
                    'index': i,
                    'reason': str(e),
                    'sample': sample
                })
                validation_result['invalid_samples'] += 1
        
        return validation_result

# 创建全局实例
database_loader = None

def init_database(database_file: str) -> bool:
    """
    初始化全局数据库实例
    
    Args:
        database_file: 数据库文件路径
        
    Returns:
        bool: 初始化是否成功
    """
    global database_loader
    try:
        database_loader = MalwareDatabaseLoader(database_file)
        return database_loader.samples is not None and len(database_loader.samples) > 0
    except Exception as e:
        logger.error(f"初始化数据库失败: {str(e)}")
        return False

def get_database_loader() -> MalwareDatabaseLoader:
    """
    获取全局数据库实例
    
    Returns:
        MalwareDatabaseLoader: 数据库加载器实例
    """
    return database_loader

def search_similar_samples_optimized(target_file: str, top_k: int = 10, families: List[str] = None) -> List[Dict[str, Any]]:
    """
    优化的相似度搜索：先转换目标文件为BinExport，再批量比较
    
    Args:
        target_file: 目标文件路径
        top_k: 返回前K个最相似的样本
        families: 指定要搜索的家族列表，None表示搜索所有家族
        
    Returns:
        List[Dict]: 相似度搜索结果列表
    """
    global database_loader
    if not database_loader:
        logger.error("数据库未初始化")
        return []
    
    logger.info(f"开始优化的相似度搜索: {target_file}")
    
    # 根据家族过滤获取要比较的样本
    if families:
        samples_to_compare = database_loader.get_samples_by_families(families)
        logger.info(f"✓ 家族过滤: {', '.join(families)}")
        logger.info(f"✓ 过滤后样本数量: {len(samples_to_compare)}")
    else:
        samples_to_compare = database_loader.samples
        logger.info(f"✓ 搜索所有家族，样本数量: {len(samples_to_compare)}")
    
    if not samples_to_compare:
        logger.warning("没有匹配的样本可供比较")
        return []
    
    # 第一步：将目标文件转换为BinExport格式（只做一次）
    logger.info("第一步：转换目标文件为BinExport格式...")
    target_binexport = convert_pe_to_binexport(target_file)
    
    if not target_binexport:
        logger.error("目标文件转换为BinExport失败")
        return []
    
    logger.info(f"✓ 目标文件已转换为BinExport: {target_binexport}")
    
    # 第二步：与过滤后的样本进行BinExport到BinExport的比较
    logger.info("第二步：开始批量比较...")
    results = []
    
    try:
        for i, sample in enumerate(samples_to_compare):
            sample_path = sample.get('path')
            if not sample_path or not os.path.exists(sample_path):
                logger.warning(f"样本文件不存在: {sample_path}")
                continue
            
            logger.info(f"正在比较样本 {i+1}/{len(samples_to_compare)}: {sample.get('hash', 'Unknown')[:8]}...")
            
            # 使用高效的BinExport比较
            comparison_result = compare_binexport_files(target_binexport, sample_path)
            
            # 构建结果
            result = {
                'family': sample.get('family', 'Unknown'),
                'hash': sample.get('hash', 'Unknown'),
                'path': sample_path,
                'similarity': comparison_result.get('globalSimilarity', 0),
                'confidence': comparison_result.get('globalConfidence', 0)
            }
            
            results.append(result)
            logger.info(f"相似度: {result['similarity']:.4f}, 置信度: {result['confidence']:.4f}")
    
    finally:
        # 清理临时BinExport文件
        try:
            if os.path.exists(target_binexport):
                os.remove(target_binexport)
                logger.info(f"已清理临时BinExport文件: {target_binexport}")
        except Exception as e:
            logger.warning(f"清理临时文件失败: {e}")
    
    logger.info(f"搜索完成，共比较了 {len(results)} 个样本")
    return sorted(results, key=lambda x: x['similarity'], reverse=True)[:top_k]
