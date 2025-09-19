# BinDiff API 客户端脚本

这是一个功能完整的 BinDiff API 客户端脚本，用于自动化调用 BinDiff 相似度搜索服务。

## 功能特性

### 🔍 智能文件扫描
- **多种文件类型支持**: 自动识别 Windows PE、Linux ELF、macOS Mach-O 等可执行文件
- **灵活扫描模式**: 支持递归和非递归目录扫描
- **智能类型检测**: 结合文件扩展名、MIME类型和libmagic检测
- **文件数量控制**: 支持最大文件数量限制，避免过度处理

### 🚀 高效批量处理
- **并发执行**: 支持多线程并发处理，大幅提升处理速度
- **进度监控**: 实时显示处理进度和成功率
- **错误恢复**: 完善的错误处理机制，单个文件失败不影响整体处理
- **资源管理**: 智能的资源管理和清理机制

### 📊 灵活的结果处理
- **JSON格式输出**: 结构化的JSON结果，便于后续分析
- **结果过滤**: 支持按相似度阈值和恶意软件家族过滤
- **详细元数据**: 包含处理时间、统计信息等详细元数据
- **数据完整性**: 保证所有处理结果的完整记录

### 🛡️ 企业级稳定性
- **服务状态检查**: 自动检查 BinDiff 服务可用性
- **超时控制**: 可配置的请求超时和重试机制
- **日志记录**: 完整的操作日志和错误记录
- **参数验证**: 全面的输入参数验证

## 安装依赖

```bash
# 安装Python依赖
pip install requests python-magic

# Ubuntu/Debian系统安装libmagic
sudo apt-get install libmagic1

# CentOS/RHEL系统安装libmagic
sudo yum install file-libs
```

## 快速开始

### 1. 基本使用

```bash

python3 bindiff_api_client.py /home/zraxx/APT/samples/patchwork_20000_5 -r --top-k 5 --min-similarity 0.3 --families Patchwork --workers 1 -o my_results.json

# 扫描目录并搜索相似样本
./bindiff_api_client.py /path/to/malware/samples

# 指定输出文件
./bindiff_api_client.py /path/to/samples -o my_results.json
```

### 2. 高级选项

```bash
# 递归扫描所有子目录
./bindiff_api_client.py /path/to/samples -r

# 限制最大文件数量
./bindiff_api_client.py /path/to/samples --max-files 100

# 调整TOP-K值
./bindiff_api_client.py /path/to/samples --top-k 20
```

### 3. 性能优化

```bash
# 增加并发线程数
./bindiff_api_client.py /path/to/samples --workers 8

# 调整超时时间
./bindiff_api_client.py /path/to/samples --timeout 600
```

### 4. 结果过滤

```bash
# 按相似度过滤
./bindiff_api_client.py /path/to/samples --min-similarity 0.8

# 按恶意软件家族过滤
./bindiff_api_client.py /path/to/samples --families Patchwork APT29

# 组合过滤条件
./bindiff_api_client.py /path/to/samples --min-similarity 0.7 --families Lazarus
```

## 详细参数说明

### 必需参数
- `target_directory`: 目标目录路径

### 输出选项
- `-o, --output`: 输出文件路径（默认：自动生成时间戳文件名）

### 服务配置
- `--url`: BinDiff服务URL（默认：http://localhost:5001）
- `--timeout`: 请求超时时间秒数（默认：300）

### 搜索参数
- `--top-k`: 返回最相似的前K个结果（默认：10）

### 扫描选项
- `-r, --recursive`: 递归扫描子目录
- `--max-files`: 最大文件数量限制
- `--no-magic`: 禁用libmagic文件类型检测

### 并发选项
- `--workers`: 并发工作线程数（默认：4）

### 过滤选项
- `--min-similarity`: 最小相似度阈值（默认：0.0）
- `--families`: 指定恶意软件家族列表

### 其他选项
- `--check-only`: 仅检查服务状态
- `--verbose, -v`: 启用详细日志输出

## 输出格式

脚本输出标准的JSON格式结果：

```json
{
  "results": [
    {
      "file_path": "/path/to/sample.exe",
      "success": true,
      "data": {
        "success": true,
        "results": [
          {
            "family": "Patchwork",
            "hash": "abc123...",
            "path": "/path/to/similar.BinExport",
            "similarity": 0.85,
            "confidence": 0.92,
            "matches": 42,
            "index": 0
          }
        ],
        "search_duration": 2.5,
        "search_timestamp": "2025-09-15T10:30:00",
        "total_results": 5
      }
    }
  ],
  "metadata": {
    "total_files": 10,
    "successful_files": 9,
    "failed_files": 1,
    "generation_time": "2025-09-15T10:35:00",
    "client_version": "1.0.0"
  }
}
```

## 性能建议

### 1. 并发优化
- **小文件集合**（<100个文件）：使用 `--workers 2-4`
- **中等文件集合**（100-1000个文件）：使用 `--workers 4-8`
- **大文件集合**（>1000个文件）：使用 `--workers 8-16`

### 2. 网络优化
- **本地服务**：超时时间可设置较短（180-300秒）
- **远程服务**：建议增加超时时间（600-1200秒）
- **不稳定网络**：减少并发数，增加超时时间

### 3. 存储优化
- 使用SSD存储可提高文件扫描速度
- 结果文件建议保存到高速存储设备

## 临时文件管理

### 🧹 自动清理机制

脚本已内置多重清理机制，确保临时文件不会占用过多磁盘空间：

1. **搜索完成自动清理**: 每次相似度搜索完成后，服务端会自动清理生成的临时文件
2. **批量处理后清理**: API客户端在批量处理完成后会请求服务端清理
3. **比较过程清理**: 每次BinExport文件比较完成后会立即清理生成的临时文件

### 🛠️ 手动清理选项

如果需要手动清理，可以使用以下方法：

```bash
# 方法1: 通过API客户端请求清理
python3 bindiff_api_client.py /tmp --check-only

# 方法2: 直接在服务器上清理
rm -rf ./out/*
rm -rf ./temp_binexports/*
rm -rf ./temp_uploads/*
```

### 📊 清理统计

脚本会在清理时显示详细统计信息：
- 清理的临时文件数量
- 清理的目录列表
- 清理操作耗时

## 故障排除

### 常见问题

1. **服务连接失败**
   ```
   ❌ 无法连接到BinDiff服务
   ```
   - 检查BinDiff服务是否正常运行
   - 验证服务URL是否正确
   - 确认网络连接正常

2. **文件类型检测失败**
   ```
   Magic检测失败: 文件路径
   ```
   - 确保已安装libmagic库
   - 尝试使用 `--no-magic` 参数
   - 检查文件权限

3. **处理超时**
   ```
   ❌ 搜索超时: 文件路径
   ```
   - 增加 `--timeout` 参数值
   - 减少 `--workers` 并发数
   - 检查服务器性能

4. **内存不足**
   ```
   内存分配失败
   ```
   - 减少 `--workers` 并发数
   - 使用 `--max-files` 限制处理文件数
   - 增加系统内存

### 调试模式

启用详细日志进行调试：

```bash
./bindiff_api_client.py /path/to/samples --verbose
```

### 服务状态检查

仅检查服务状态而不执行搜索：

```bash
./bindiff_api_client.py /path/to/samples --check-only
```

## 集成示例

### 1. Shell脚本集成

```bash
#!/bin/bash
# 批量处理多个目录

DIRS=("/path/to/dir1" "/path/to/dir2" "/path/to/dir3")
OUTPUT_DIR="/path/to/results"

for dir in "${DIRS[@]}"; do
    echo "处理目录: $dir"
    output_file="$OUTPUT_DIR/$(basename $dir)_results.json"
    ./bindiff_api_client.py "$dir" -o "$output_file" -r --top-k 15
done
```

### 2. Python脚本集成

```python
import subprocess
import json

def run_bindiff_analysis(directory, output_file):
    cmd = [
        './bindiff_api_client.py',
        directory,
        '-o', output_file,
        '--recursive',
        '--top-k', '10'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        with open(output_file, 'r') as f:
            return json.load(f)
    else:
        print(f"错误: {result.stderr}")
        return None
```

### 3. 定时任务集成

```bash
# 添加到crontab，每日凌晨2点执行
0 2 * * * /path/to/bindiff_api_client.py /path/to/samples -o /path/to/daily_results.json -r
```

## 安全考虑

1. **文件权限**: 确保脚本对目标目录有读取权限
2. **网络安全**: 在生产环境中使用HTTPS连接
3. **数据保护**: 结果文件可能包含敏感信息，注意访问控制
4. **资源限制**: 合理设置并发数和超时时间，避免资源耗尽

## 版本历史

- **v1.0.0**: 初始版本
  - 基本的目录扫描和API调用功能
  - 批量处理和并发支持
  - JSON结果输出
  - 完整的错误处理机制

## 支持与反馈

如有问题或建议，请检查：
1. BinDiff服务是否正常运行
2. 网络连接是否正常
3. 参数配置是否正确
4. 系统资源是否充足

---

**注意**: 此脚本需要配合运行中的BinDiff相似度搜索服务使用。请确保服务正常运行并且网络连接正常。
