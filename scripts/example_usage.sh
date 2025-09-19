#!/bin/bash
# BinDiff API客户端使用示例脚本
# 此脚本展示了各种常见的使用场景

set -e  # 遇到错误时退出

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_SCRIPT="$SCRIPT_DIR/bindiff_api_client.py"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印彩色消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查脚本是否存在
if [ ! -f "$CLIENT_SCRIPT" ]; then
    print_error "API客户端脚本不存在: $CLIENT_SCRIPT"
    exit 1
fi

# 检查脚本是否可执行
if [ ! -x "$CLIENT_SCRIPT" ]; then
    print_warning "API客户端脚本不可执行，正在添加执行权限..."
    chmod +x "$CLIENT_SCRIPT"
fi

print_info "BinDiff API客户端使用示例"
print_info "============================"

# 示例1: 检查服务状态
print_info "示例1: 检查BinDiff服务状态"
echo "命令: $CLIENT_SCRIPT /tmp --check-only"
if [ -d "/tmp" ]; then
    if python3 "$CLIENT_SCRIPT" /tmp --check-only; then
        print_success "服务状态检查完成"
    else
        print_error "服务状态检查失败，请确保BinDiff服务正在运行"
        print_warning "可以使用以下命令启动服务:"
        echo "  cd $(dirname "$SCRIPT_DIR")"
        echo "  python3 start_with_similarity.py"
        exit 1
    fi
else
    print_warning "跳过示例1: /tmp目录不存在"
fi

echo ""

# 示例2: 基本扫描（如果有测试目录）
if [ -d "$(dirname "$SCRIPT_DIR")/test" ]; then
    TEST_DIR="$(dirname "$SCRIPT_DIR")/test"
    print_info "示例2: 基本目录扫描"
    echo "命令: $CLIENT_SCRIPT $TEST_DIR -o basic_scan_results.json"
    
    if python3 "$CLIENT_SCRIPT" "$TEST_DIR" -o "$SCRIPT_DIR/basic_scan_results.json"; then
        print_success "基本扫描完成，结果保存到: $SCRIPT_DIR/basic_scan_results.json"
        
        # 显示结果摘要
        if [ -f "$SCRIPT_DIR/basic_scan_results.json" ]; then
            total_files=$(python3 -c "import json; data=json.load(open('$SCRIPT_DIR/basic_scan_results.json')); print(data.get('metadata', {}).get('total_files', 0))")
            successful_files=$(python3 -c "import json; data=json.load(open('$SCRIPT_DIR/basic_scan_results.json')); print(data.get('metadata', {}).get('successful_files', 0))")
            print_info "处理文件总数: $total_files"
            print_info "成功处理: $successful_files"
        fi
    else
        print_error "基本扫描失败"
    fi
    
    echo ""
fi

# 示例3: 递归扫描示例
if [ -d "$(dirname "$SCRIPT_DIR")/uploads" ]; then
    UPLOAD_DIR="$(dirname "$SCRIPT_DIR")/uploads"
    print_info "示例3: 递归扫描uploads目录"
    echo "命令: $CLIENT_SCRIPT $UPLOAD_DIR -r --top-k 5 -o recursive_scan_results.json"
    
    if python3 "$CLIENT_SCRIPT" "$UPLOAD_DIR" -r --top-k 5 -o "$SCRIPT_DIR/recursive_scan_results.json"; then
        print_success "递归扫描完成"
    else
        print_warning "递归扫描失败或无可执行文件"
    fi
    
    echo ""
fi

# 示例4: 高级过滤示例
print_info "示例4: 演示高级过滤选项"
echo "命令示例（需要实际目录）:"
echo "  # 按相似度过滤"
echo "  $CLIENT_SCRIPT /path/to/samples --min-similarity 0.8"
echo ""
echo "  # 按恶意软件家族过滤"
echo "  $CLIENT_SCRIPT /path/to/samples --families Patchwork APT29"
echo ""
echo "  # 组合过滤条件"
echo "  $CLIENT_SCRIPT /path/to/samples --min-similarity 0.7 --families Lazarus --top-k 20"
echo ""

# 示例5: 并发优化示例
print_info "示例5: 并发优化选项"
echo "命令示例:"
echo "  # 小文件集合（推荐2-4线程）"
echo "  $CLIENT_SCRIPT /path/to/small_samples --workers 4"
echo ""
echo "  # 大文件集合（推荐8-16线程）"
echo "  $CLIENT_SCRIPT /path/to/large_samples --workers 8 --timeout 600"
echo ""

# 示例6: 批量处理多个目录
print_info "示例6: 批量处理多个目录的脚本示例"
cat << 'EOF'

# 创建批量处理脚本 batch_process.sh:
#!/bin/bash
DIRS=("/path/to/dir1" "/path/to/dir2" "/path/to/dir3")
OUTPUT_DIR="/path/to/results"
mkdir -p "$OUTPUT_DIR"

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "处理目录: $dir"
        output_file="$OUTPUT_DIR/$(basename "$dir")_results.json"
        python3 bindiff_api_client.py "$dir" -o "$output_file" -r --top-k 15
    fi
done

EOF

echo ""

# 生成快速启动脚本
print_info "生成快速启动脚本..."

cat > "$SCRIPT_DIR/quick_scan.sh" << EOF
#!/bin/bash
# 快速扫描脚本 - 使用默认参数扫描指定目录

if [ \$# -eq 0 ]; then
    echo "用法: \$0 <目标目录> [输出文件]"
    echo "示例: \$0 /path/to/samples my_results.json"
    exit 1
fi

TARGET_DIR="\$1"
OUTPUT_FILE="\${2:-quick_scan_results_\$(date +%Y%m%d_%H%M%S).json}"

if [ ! -d "\$TARGET_DIR" ]; then
    echo "错误: 目录不存在: \$TARGET_DIR"
    exit 1
fi

echo "开始扫描目录: \$TARGET_DIR"
echo "结果将保存到: \$OUTPUT_FILE"

python3 "$CLIENT_SCRIPT" "\$TARGET_DIR" -o "\$OUTPUT_FILE" -r --top-k 10 --workers 4
EOF

chmod +x "$SCRIPT_DIR/quick_scan.sh"
print_success "快速启动脚本已生成: $SCRIPT_DIR/quick_scan.sh"

echo ""

# 生成配置示例
print_info "配置文件和文档"
print_info "- 配置示例: $SCRIPT_DIR/config_example.json"
print_info "- 详细文档: $SCRIPT_DIR/README.md"
print_info "- 快速启动: $SCRIPT_DIR/quick_scan.sh"

echo ""

# 显示使用提示
print_info "快速使用提示:"
echo "1. 检查服务状态:"
echo "   $CLIENT_SCRIPT /tmp --check-only"
echo ""
echo "2. 基本扫描:"
echo "   $CLIENT_SCRIPT /path/to/samples"
echo ""
echo "3. 快速扫描:"
echo "   $SCRIPT_DIR/quick_scan.sh /path/to/samples"
echo ""
echo "4. 高级扫描:"
echo "   $CLIENT_SCRIPT /path/to/samples -r --top-k 20 --workers 8 --min-similarity 0.8"
echo ""

print_success "示例演示完成！"
print_info "更多详细信息请查看: $SCRIPT_DIR/README.md"
