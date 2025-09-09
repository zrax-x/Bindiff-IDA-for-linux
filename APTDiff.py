import os
import json
from collections import defaultdict
from typing import Dict, List, Tuple
from bindiff_integration import run_bindiff_cli

class APTDiffAnalyzer:
    def __init__(self, family_dir: str = 'family'):
        """
        初始化APT分析器
        
        Args:
            family_dir: 包含已知APT家族样本的目录
        """
        self.family_dir = family_dir
        self.family_samples = self._load_family_samples()
        
    def _load_family_samples(self) -> Dict[str, List[str]]:
        """
        加载所有家族样本路径
        
        Returns:
            Dict[str, List[str]]: 家族名称到样本路径列表的映射
        """
        family_samples = defaultdict(list)
        
        # 遍历family目录下的所有家族子目录
        for family_name in os.listdir(self.family_dir):
            family_path = os.path.join(self.family_dir, family_name)
            if os.path.isdir(family_path):
                # 获取该家族下的所有样本文件
                for sample in os.listdir(family_path):
                    if not sample.endswith('.BinExport'):
                        sample_path = os.path.join(family_path, sample)
                        family_samples[family_name].append(sample_path)
        
        return dict(family_samples)
    
    def analyze_unknown_sample(self, unknown_sample_path: str, 
                             similarity_threshold: float = 0.7) -> Dict:
        """
        分析未知样本，确定其可能的家族归属
        
        Args:
            unknown_sample_path: 未知样本的路径
            similarity_threshold: 相似度阈值，默认0.7
            
        Returns:
            Dict: 分析结果，包含最可能的家族及相似度信息
        """
        family_similarities = defaultdict(list)
        
        # 与每个家族的样本进行比对
        for family_name, samples in self.family_samples.items():
            print(f"正在与{family_name}家族进行比对...")
            
            # 与该家族的每个样本进行比对
            for sample_path in samples:
                print(sample_path)
                if sample_path.endswith(".BinExport"): continue
                try:
                    result = run_bindiff_cli(unknown_sample_path, sample_path)
                    similarity = result.get("globalSimilarity", 0)
                    confidence = result.get("globalConfidence", 0)
                    
                    if similarity >= similarity_threshold:
                        family_similarities[family_name].append({
                            "sample": os.path.basename(sample_path),
                            "similarity": similarity,
                            "confidence": confidence
                        })
                except Exception as e:
                    print(f"比对样本 {sample_path} 时出错: {e}")
                    continue
        
        # 分析结果
        analysis_result = {
            "unknown_sample": os.path.basename(unknown_sample_path),
            "family_matches": {},
            "most_likely_family": None,
            "highest_similarity": 0
        }
        
        # 计算每个家族的平均相似度
        for family, matches in family_similarities.items():
            if matches:  # 如果有匹配结果
                avg_similarity = sum(m["similarity"] for m in matches) / len(matches)
                analysis_result["family_matches"][family] = {
                    "average_similarity": avg_similarity,
                    "matches": matches
                }
                
                # 更新最可能的家族
                if avg_similarity > analysis_result["highest_similarity"]:
                    analysis_result["highest_similarity"] = avg_similarity
                    analysis_result["most_likely_family"] = family
        
        return analysis_result

# Flask API路由处理
from flask import Blueprint, request, jsonify

apt_diff_bp = Blueprint('apt_diff', __name__)
analyzer = APTDiffAnalyzer()

@apt_diff_bp.route('/analyze', methods=['POST'])
def analyze_sample():
    """
    分析上传的样本
    
    请求体应包含:
    - file: 要分析的样本文件
    - similarity_threshold: (可选) 相似度阈值，默认0.7
    
    返回:
    - JSON格式的分析结果
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    # 获取相似度阈值参数
    similarity_threshold = float(request.form.get('similarity_threshold', 0.7))
    
    # 保存上传的文件
    temp_dir = "temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)
    
    try:
        # 分析样本
        result = analyzer.analyze_unknown_sample(temp_path, similarity_threshold)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # 清理临时文件
        if os.path.exists(temp_path):
            os.remove(temp_path)

# 注册Blueprint
def init_app(app):
    app.register_blueprint(apt_diff_bp, url_prefix='/apt')