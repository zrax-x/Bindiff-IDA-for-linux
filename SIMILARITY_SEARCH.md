# 恶意软件相似度搜索功能

## 功能概述

本功能为 BinDiff Online 项目新增了恶意软件相似度搜索能力，允许用户上传单个恶意软件样本，在预构建的恶意软件数据库中搜索最相似的 TOP-K 样本，并返回详细的相似度分析结果。

## 主要特性

### 🔍 智能相似度搜索
- **TOP-K 搜索**: 支持返回最相似的前 K 个样本（默认 TOP-10，可自定义 5-50）
- **多家族支持**: 支持多个 APT 家族的恶意软件样本数据库
- **精确评分**: 基于 BinDiff 技术提供精确的相似度和置信度评分
- **函数级匹配**: 提供函数级别的详细匹配信息

### 📊 丰富的结果展示
- **双视图模式**: 支持网格视图和表格视图
- **家族归属**: 自动识别样本的可能家族归属
- **统计信息**: 提供全面的搜索统计和数据库信息
- **结果导出**: 支持 JSON、CSV 格式的结果导出

### 🌐 Web 界面与 API
- **友好的 Web 界面**: 现代化的响应式设计
- **拖拽上传**: 支持文件拖拽上传
- **RESTful API**: 提供完整的 API 接口供程序化调用

## 文件结构

```
Bindiff-IDA-for-linux/
├── database_loader.py          # 数据库加载与管理模块
├── similarity_search.py        # 相似度搜索核心模块
├── templates/
│   ├── similarity_search.html  # 搜索页面模板
│   └── search_results.html     # 结果显示模板
├── test_similarity.py          # 功能测试脚本
└── SIMILARITY_SEARCH.md        # 本文档
```

## 数据库格式

项目使用 JSON 格式的恶意软件数据库，包含以下字段：

```json
[
  {
    "family": "Patchwork",
    "hash": "16aadf7a8fc02449d088670dd9b22aa9bff08c936822f84c02cb3b49f913a9cb",
    "path": "/path/to/sample.BinExport"
  }
]
```

### 字段说明
- `family`: 恶意软件家族名称
- `hash`: 文件的 SHA-256 哈希值
- `path`: BinExport 文件的完整路径

## API 接口

### 1. 相似度搜索
```http
POST /similarity/api/search
Content-Type: multipart/form-data

Parameters:
- file: 要搜索的恶意软件文件
- top_k: (可选) 返回结果数量，默认 10
```

**响应示例**:
```json
{
  "success": true,
  "search_filename": "malware.exe",
  "results": [
    {
      "family": "Patchwork",
      "hash": "abc123...",
      "path": "/path/to/sample.BinExport",
      "similarity": 0.85,
      "confidence": 0.92,
      "matches": 42,
      "index": 0
    }
  ],
  "search_duration": 120.5,
  "total_samples": 190
}
```

### 2. 数据库信息
```http
GET /similarity/api/database/info
```

**响应示例**:
```json
{
  "success": true,
  "statistics": {
    "total_samples": 190,
    "total_families": 1,
    "family_distribution": {
      "Patchwork": 190
    }
  },
  "families": ["Patchwork"]
}
```

### 3. 数据库验证
```http
GET /similarity/api/database/validate
```

## 配置说明

在 `config.py` 中添加了数据库配置：

```python
# 数据库配置
DATABASE_FILE = os.environ.get('MALWARE_DATABASE', '../gen_database/malware_simple.json')
```

可以通过环境变量 `MALWARE_DATABASE` 指定数据库文件路径。

## 安装与使用

### 1. 安装依赖
```bash
pip install python-dotenv
```

### 2. 配置数据库路径
```bash
export MALWARE_DATABASE="/path/to/your/malware_database.json"
```

### 3. 启动应用
```bash
python app.py
```

### 4. 访问功能
- Web 界面: `http://localhost:5001/similarity/search`
- 主页: `http://localhost:5001/` (包含新功能入口)

## 测试

运行测试脚本验证功能：

```bash
python test_similarity.py
```

测试包括：
- 配置文件验证
- 数据库加载测试
- API 端点可用性检查

## 性能考虑

### 搜索性能
- **时间复杂度**: O(n)，其中 n 是数据库中的样本数量
- **优化建议**: 对于大型数据库，建议：
  - 使用 SSD 存储数据库文件
  - 考虑实现索引机制
  - 使用多进程并行处理

### 内存使用
- 数据库完全加载到内存中以提高访问速度
- 对于大型数据库，建议增加系统内存

## 安全考虑

1. **文件类型验证**: 自动检测上传文件类型，只允许可执行文件
2. **文件大小限制**: 默认限制 50MB，可在配置中调整
3. **临时文件清理**: 自动清理处理过程中的临时文件
4. **路径安全**: 使用 `secure_filename` 处理文件名

## 扩展功能

### 1. 支持的扩展
- **多数据库支持**: 可轻松扩展支持多个数据库文件
- **缓存机制**: 可添加结果缓存以提高重复查询性能
- **批量搜索**: 可扩展支持批量文件搜索
- **相似度阈值**: 可添加相似度过滤功能

### 2. 未来计划
- **机器学习增强**: 集成机器学习模型提高匹配精度
- **实时数据库更新**: 支持动态添加新样本
- **高级过滤**: 支持按家族、时间等多维度过滤
- **可视化分析**: 增加相似度热图等可视化功能

## 故障排除

### 常见问题

1. **数据库加载失败**
   - 检查数据库文件路径是否正确
   - 验证 JSON 格式是否有效
   - 确保文件权限正确

2. **搜索速度慢**
   - 检查数据库文件是否在 SSD 上
   - 验证样本文件路径是否都有效
   - 考虑减少数据库大小进行测试

3. **内存不足**
   - 减少数据库大小
   - 增加系统内存
   - 考虑实现分批加载机制

### 日志调试

启用详细日志：
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 贡献指南

1. 功能请求和 Bug 报告请提交 Issue
2. 代码贡献请遵循现有代码风格
3. 新功能请包含相应的测试用例
4. 更新文档以反映代码变更

---

**注意**: 此功能需要有效的 BinDiff 环境和恶意软件样本数据库才能正常工作。
