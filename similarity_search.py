"""
相似度搜索模块 - 重写版本
使用URL参数直接传递文件路径，避免session复杂性
"""

import os
import json
import time
from typing import Dict, List, Any
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from werkzeug.utils import secure_filename
from database_loader import get_database_loader, search_similar_samples_optimized
import config
import magic
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建蓝图
similarity_bp = Blueprint('similarity', __name__, url_prefix='/similarity')

def allowed_file(filename):
    """检查文件是否允许上传"""
    if not filename:
        return False
    
    # 检查扩展名
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        if ext in config.ALLOWED_EXTENSIONS:
            return True
    
    # 检查文件内容类型
    try:
        file_path = os.path.join(config.UPLOAD_FOLDER, f"search_{filename}")
        if os.path.exists(file_path):
            mime = magic.from_file(file_path, mime=True)
            logger.info(f"文件MIME类型: {mime}")
            
            # 允许的可执行文件类型
            allowed_mimes = {
                'application/x-executable',
                'application/x-sharedlib',
                'application/x-object',
                'application/octet-stream',
                'text/x-shellscript'
            }
            
            if mime in allowed_mimes:
                return True
                
            # 检查文件描述
            file_desc = magic.from_file(file_path)
            logger.info(f"文件描述: {file_desc}")
            
            if any(keyword in file_desc.lower() for keyword in ['executable', 'binary', 'script']):
                return True
                
    except Exception as e:
        logger.warning(f"检查文件类型时出错: {e}")
    
    return False

@similarity_bp.route('/search')
def search_page():
    """相似度搜索页面"""
    return render_template('similarity_search.html')

@similarity_bp.route('/upload_for_search', methods=['POST'])
def upload_for_search():
    """处理文件上传并重定向到搜索结果"""
    try:
        # 添加详细日志
        logger.info("=== 收到文件上传请求 ===")
        logger.info(f"请求方法: {request.method}")
        logger.info(f"请求内容类型: {request.content_type}")
        logger.info(f"请求文件: {list(request.files.keys())}")
        logger.info(f"请求表单数据: {dict(request.form)}")
        
        # 确保上传目录存在
        os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
        
        if 'search_file' not in request.files:
            logger.error("请求中没有找到 'search_file' 字段")
            flash('请选择要搜索的文件')
            return redirect(url_for('similarity.search_page'))
        
        search_file = request.files['search_file']
        logger.info(f"上传文件信息: filename={search_file.filename}, content_type={search_file.content_type}")
        
        if search_file.filename == '':
            logger.error("上传文件名为空")
            flash('请选择要搜索的文件')
            return redirect(url_for('similarity.search_page'))
        
        # 获取TOP-K参数
        try:
            top_k = int(request.form.get('top_k', 10))
            if top_k <= 0 or top_k > 50:
                top_k = 10
        except (ValueError, TypeError):
            top_k = 10
        
        search_filename = secure_filename(search_file.filename)
        search_path = os.path.join(config.UPLOAD_FOLDER, f"search_{search_filename}")
        
        logger.info(f"开始处理上传文件: {search_filename}")
        
        # 保存文件
        search_file.save(search_path)
        logger.info(f"文件已保存到: {search_path}")
        
        # 检查文件类型
        if not allowed_file(search_filename):
            logger.warning(f"文件类型检查失败: {search_filename}")
            os.remove(search_path)
            flash('上传的文件不是有效的可执行文件')
            return redirect(url_for('similarity.search_page'))
        
        logger.info(f"文件类型检查通过: {search_filename}")
        
        # 直接重定向到搜索结果页面，通过URL参数传递文件信息
        return redirect(url_for('similarity.search_results', 
                               filename=search_filename, 
                               top_k=top_k))
        
    except Exception as e:
        logger.error(f"上传文件时出错: {str(e)}")
        flash(f'上传文件失败: {str(e)}')
        return redirect(url_for('similarity.search_page'))

@similarity_bp.route('/search_results')
def search_results():
    """显示搜索结果"""
    try:
        # 从URL参数获取信息
        search_filename = request.args.get('filename', 'Unknown')
        top_k = int(request.args.get('top_k', 10))
        
        logger.info(f"开始处理搜索结果请求: filename={search_filename}, top_k={top_k}")
        
        # 构建文件路径
        search_file_path = os.path.join(config.UPLOAD_FOLDER, f"search_{search_filename}")
        
        # 检查文件是否存在
        if not os.path.exists(search_file_path):
            logger.error(f"搜索文件不存在: {search_file_path}")
            logger.error(f"上传目录内容: {os.listdir(config.UPLOAD_FOLDER)}")
            flash('搜索文件不存在，请重新上传')
            return redirect(url_for('similarity.search_page'))
        
        # 检查数据库是否已加载
        db_loader = get_database_loader()
        if not db_loader or not db_loader.samples:
            flash('数据库未加载或为空，请联系管理员')
            return redirect(url_for('similarity.search_page'))
        
        # 执行优化的相似度搜索
        logger.info(f"开始对文件 {search_filename} 进行优化的相似度搜索")
        start_time = time.time()
        
        results = search_similar_samples_optimized(search_file_path, top_k)
        
        end_time = time.time()
        search_duration = end_time - start_time
        
        logger.info(f"优化搜索完成，耗时 {search_duration:.2f} 秒")
        
        # 清理out目录
        try:
            import shutil
            out_dir = config.OUTPUT_FOLDER
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir)
                os.makedirs(out_dir, exist_ok=True)
                logger.info(f"已清理out目录: {out_dir}")
        except Exception as e:
            logger.warning(f"清理out目录失败: {e}")
        
        # 准备渲染数据
        render_data = {
            'search_filename': search_filename,
            'results': results,
            'top_k': top_k,
            'search_duration': round(search_duration, 2),
            'total_samples': len(db_loader.samples),
            'total_families': len(db_loader.get_all_families())
        }
        
        return render_template('search_results.html', **render_data)
        
    except Exception as e:
        logger.error(f"处理搜索结果时出错: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'处理搜索结果时出错: {str(e)}')
        return redirect(url_for('similarity.search_page'))

@similarity_bp.route('/api/search', methods=['POST'])
def api_search():
    """API接口：相似度搜索"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '请求数据为空'}), 400
        
        search_file_path = data.get('file_path')
        top_k = data.get('top_k', 10)
        
        if not search_file_path or not os.path.exists(search_file_path):
            return jsonify({'success': False, 'error': '文件不存在'}), 400
        
        # 执行搜索
        results = search_similar_samples_optimized(search_file_path, top_k)
        
        # 清理out目录中的临时文件
        try:
            import shutil
            out_dir = config.OUTPUT_FOLDER
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir)
                os.makedirs(out_dir, exist_ok=True)
                logger.info(f"已清理out目录: {out_dir}")
        except Exception as e:
            logger.warning(f"清理out目录失败: {e}")
        
        return jsonify({
            'success': True,
            'results': results,
            'total_results': len(results)
        })
        
    except Exception as e:
        logger.error(f"API搜索时出错: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@similarity_bp.route('/api/database/info')
def api_database_info():
    """API接口：获取数据库信息"""
    try:
        db_loader = get_database_loader()
        if not db_loader:
            return jsonify({'success': False, 'error': '数据库未初始化'}), 500
        
        stats = db_loader.get_statistics()
        families = db_loader.get_all_families()
        
        return jsonify({
            'success': True,
            'database_file': config.DATABASE_FILE,
            'families': families,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"获取数据库信息时出错: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@similarity_bp.route('/api/cleanup', methods=['POST'])
def api_cleanup():
    """API接口：清理服务端临时文件"""
    try:
        logger.info("收到清理请求")
        
        # 清理out目录
        import shutil
        out_dir = config.OUTPUT_FOLDER
        cleaned_files = 0
        
        if os.path.exists(out_dir):
            # 统计要清理的文件数量
            for root, dirs, files in os.walk(out_dir):
                cleaned_files += len(files)
            
            # 清理目录
            shutil.rmtree(out_dir)
            os.makedirs(out_dir, exist_ok=True)
            logger.info(f"已清理out目录: {out_dir}")
        
        # 清理其他可能的临时目录
        temp_dirs = ['temp_binexports', 'temp_uploads']
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                temp_files = len(os.listdir(temp_dir))
                if temp_files > 0:
                    cleaned_files += temp_files
                    logger.info(f"清理临时目录: {temp_dir} ({temp_files} 个文件)")
                    # 实际清理目录中的文件
                    shutil.rmtree(temp_dir)
                    os.makedirs(temp_dir, exist_ok=True)
        
        return jsonify({
            'success': True,
            'message': f'成功清理 {cleaned_files} 个临时文件',
            'cleaned_files': cleaned_files
        })
        
    except Exception as e:
        logger.error(f"清理临时文件时出错: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def init_similarity_search(app, database_file):
    """初始化相似度搜索模块"""
    try:
        logger.info(f"正在初始化相似度搜索模块，数据库文件: {database_file}")
        
        # 初始化数据库
        from database_loader import init_database
        success = init_database(database_file)
        
        if success:
            logger.info("数据库初始化成功")
        else:
            logger.error("数据库初始化失败")
            return False
        
        # 注册蓝图
        app.register_blueprint(similarity_bp)
        logger.info("相似度搜索模块初始化完成")
        
        return True
        
    except Exception as e:
        logger.error(f"初始化相似度搜索模块失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
