// 处理函数行点击事件
function handleFunctionClick(primaryAddr, secondaryAddr) {
    // 显示加载状态
    document.getElementById('decompile-view').style.display = 'block';
    document.getElementById('loading-indicator').style.display = 'block';
    
    // 获取主函数反编译结果
    fetch(`/decompile?file=primary&address=${primaryAddr}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            const codeElement = document.getElementById('primary-decompile');
            codeElement.textContent = data.success ? data.code : '// No decompiled code available';
            codeElement.classList.add('language-cpp');
            hljs.highlightElement(codeElement);
        })
        .catch(error => {
            console.error('Error fetching primary decompilation:', error);
            document.getElementById('primary-decompile').textContent = 'Error loading decompilation';
        });
    
    // 获取次函数反编译结果
    fetch(`/decompile?file=secondary&address=${secondaryAddr}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            const codeElement = document.getElementById('secondary-decompile');
            codeElement.textContent = data.success ? data.code : '// No decompiled code available';
            codeElement.classList.add('language-cpp');
            hljs.highlightElement(codeElement);
        })
        .catch(error => {
            console.error('Error fetching secondary decompilation:', error);
            document.getElementById('secondary-decompile').textContent = 'Error loading decompilation';
        })
        .finally(() => {
            document.getElementById('loading-indicator').style.display = 'none';
        });
}

// 关闭对比视图
function closeDecompileView() {
    document.getElementById('decompile-view').style.display = 'none';
}

// 初始化事件监听器
document.addEventListener('DOMContentLoaded', function() {
    // 为所有函数行添加点击事件
    const functionRows = document.querySelectorAll('.results-table tbody tr');
    functionRows.forEach(row => {
        row.addEventListener('click', function() {
            const primaryAddr = this.querySelector('.primary-col.address-col').textContent.trim();
            const secondaryAddr = this.querySelector('.secondary-col.address-col').textContent.trim();
            handleFunctionClick(primaryAddr, secondaryAddr);
        });
    });
    
    // 添加背景点击关闭功能
    document.getElementById('decompile-view').addEventListener('click', function(event) {
        if (event.target === this) {
            closeDecompileView();
        }
    });
}); 