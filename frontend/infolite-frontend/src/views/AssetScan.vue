<template>
  <div class="asset-scan-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">InfoLite 网络资产扫描平台</h1>

      <button 
        class="theme-toggle-btn"
        @click="toggleTheme"
        title="切换主题"
      >
        {{ theme === 'light' ? '🌙' : '☀️' }}
      </button>
    </div>

    <!-- 扫描表单 -->
    <div class="scan-form-card">
      <div class="form-container">
        <div class="form-row">
          <label for="ipInput" class="form-label">目标IP</label>
          <input
            id="ipInput"
            v-model="scanForm.ip"
            type="text"
            class="form-input"
            placeholder="请输入要扫描的IP（如127.0.0.1）"
            @keyup.enter="handleQuery"
          />
          <div class="form-buttons">
            <button 
              class="btn-primary" 
              @click="handleQuery"
            >
              查询/扫描
            </button>
            <button 
              class="btn-secondary" 
              @click="handleRefresh" 
              :disabled="!scanForm.ip"
            >
              刷新扫描
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 扫描结果 -->
    <div class="scan-result-card" v-if="hasResult">
      <div class="result-container">
        <div class="result-header">
          <h3>
            扫描结果
            <span class="tag" :class="{ 'tag-info': scanType === 'db_query', 'tag-primary': scanType !== 'db_query' }">
                {{ scanType === 'db_query' ? '从数据库查询' : '实时扫描结果' }}
              </span>
          </h3>
          <p>共检测到 {{ tableData.length }} 个开放端口/资产</p>
        </div>

        <!-- 结果表格 -->
        <div class="table-container">
          <table class="pixel-table">
            <thead>
              <tr>
                <th>目标IP</th>
                <th>开放端口</th>
                <th>协议</th>
                <th>端口状态</th>
                <th>Banner</th>
                <th>组件指纹</th>
                <th>扫描时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in tableData" :key="`${row.ip}-${row.port}`">
                <td>{{ row.ip }}</td>
                <td>{{ row.port }}</td>
                <td>
                  <span class="tag" :class="{ 'tag-danger': row.protocol === 'https', 'tag-success': row.protocol !== 'https' }">
                      {{ row.protocol }}
                    </span>
                </td>
                <td>
                  <span class="tag tag-success">{{ row.status }}</span>
                </td>
                <td>{{ row.banner }}</td>
                <td>
                  <span v-if="row.fingerprint.length > 0">
                    {{ row.fingerprint.join('、') }}
                  </span>
                  <span v-else class="text-muted">未识别</span>
                </td>
                <td>{{ row.scan_time_str }}</td>
                <td>
                  <button 
                    class="btn-text" 
                    @click="showDetail(row)"
                  >
                    详情
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 资产详情弹窗 -->
    <div class="modal-overlay" v-if="detailDialogVisible" @click="detailDialogVisible = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>资产详情</h3>
          <button class="modal-close" @click="detailDialogVisible = false">×</button>
        </div>
        <div class="modal-body" v-if="currentAsset">
          <div class="detail-item">
            <span class="detail-label">目标IP：</span>
            <span class="detail-value">{{ currentAsset.ip }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">开放端口：</span>
            <span class="detail-value">{{ currentAsset.port }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">协议：</span>
            <span class="detail-value">{{ currentAsset.protocol }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">端口状态：</span>
            <span class="detail-value">{{ currentAsset.status }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">服务Banner：</span>
            <span class="detail-value">{{ currentAsset.banner || '未知' }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">组件指纹：</span>
            <span class="detail-value">{{ currentAsset.fingerprint.length > 0 ? currentAsset.fingerprint.join('、') : '未识别' }}</span>
          </div>
          <div class="detail-item" v-if="currentAsset.http_info">
            <span class="detail-label">HTTP状态码：</span>
            <span class="detail-value">{{ currentAsset.http_info.status_code }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">扫描时间：</span>
            <span class="detail-value">{{ currentAsset.scan_time_str }}</span>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-secondary" @click="detailDialogVisible = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
// 引入封装的axios请求
import request from '../utils/request'

// 主题
import { inject } from 'vue'
const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

// 扫描表单数据
const scanForm = reactive({
  ip: '' // 目标IP
})

// 表格数据（扫描结果）
const tableData = ref([])
// 扫描类型（db_query:数据库查询，scan:实时扫描）
const scanType = ref('')
// 是否有结果（控制结果区域显示）
const hasResult = computed(() => tableData.value.length > 0)
// 详情弹窗
const detailDialogVisible = ref(false)
// 当前选中的资产
const currentAsset = ref({})

// IP格式校验
const validateIp = (ip) => {
  const reg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
  return reg.test(ip)
}

// 处理查询/扫描（默认不刷新）
const handleQuery = async () => {
  // IP校验
  if (!scanForm.ip) {
    alert('请输入目标IP地址')
    return
  }
  if (!validateIp(scanForm.ip)) {
    alert('请输入正确的IP地址（如127.0.0.1）')
    return
  }

  try {
    // 调用后端接口，refresh=false（默认不刷新）
    const res = await request.get('/asset/query', {
      params: { ip: scanForm.ip, refresh: false }
    })
    tableData.value = res.data
    scanType.value = res.scan_type
    // 提示成功
    alert(res.msg)
  } catch (error) {
    console.error('查询失败：', error)
    tableData.value = []
  }
}

// 处理刷新扫描（强制重新扫描）
const handleRefresh = async () => {
  if (confirm('确定要刷新扫描该IP吗？会重新执行端口探测并覆盖旧数据')) {
    try {
      // 调用后端接口，refresh=true（强制刷新）
      const res = await request.get('/asset/query', {
        params: { ip: scanForm.ip, refresh: true }
      })
      tableData.value = res.data
      scanType.value = res.scan_type
      alert(res.msg)
    } catch (error) {
      console.error('刷新扫描失败：', error)
      alert('刷新扫描失败')
    }
  }
}

// 查看资产详情
const showDetail = (row) => {
  currentAsset.value = row
  detailDialogVisible.value = true
}
</script>

<style scoped>
/* 像素风格字体 */
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

/* 页面整体样式：替换为CSS变量 👇 */
.asset-scan-page {
  /* max-width: 1400px; */
  width: 100%;
  margin: 0 auto;
  padding: 20px;
  background-color: var(--bg-main);
  min-height: 100vh;
  font-family: 'Press Start 2P', monospace;
}

/* 页面头部：新增flex布局，容纳切换按钮 */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  text-align: left;
  margin-bottom: 30px;
  padding-bottom: 15px;
  border-bottom: 2px solid var(--border-color);
}
.page-title {
  font-size: 24px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
}

/* 主题切换按钮样式 */
.theme-toggle-btn {
  font-size: 24px;
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 8px 12px;
  cursor: pointer;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
}
.theme-toggle-btn:hover {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}
.theme-toggle-btn:active {
  transform: translate(2px, 2px);
  box-shadow: 1px 1px 0 var(--border-color);
}

/* 扫描表单 */
.scan-form-card {
  margin-bottom: 30px;
}
.form-container {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 20px;
  box-shadow: 5px 5px 0 var(--border-color);
}
.form-row {
  display: flex;
  align-items: center;
  gap: 15px;
}
.form-label {
  font-size: 14px;
  color: var(--text-primary);
  white-space: nowrap;
}
.form-input {
  flex: 1;
  max-width: 300px;
  padding: 10px;
  border: 2px solid var(--border-color);
  background: var(--bg-main);
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
  font-size: 14px;
  box-shadow: 3px 3px 0 var(--border-color);
}
.form-input:focus {
  outline: none;
  border-color: var(--text-primary);
}
.form-buttons {
  display: flex;
  gap: 10px;
}

/* 按钮样式 */
.btn-primary, .btn-secondary, .btn-text {
  font-family: 'Press Start 2P', monospace;
  font-size: 12px;
  padding: 8px 12px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
}
.btn-primary {
  background: #4CAF50;
  color: white;
}
.btn-secondary {
  background: #2196F3;
  color: white;
}
.btn-text {
  background: transparent;
  color: var(--text-primary);
  border: none;
  box-shadow: none;
  text-decoration: underline;
}
.btn-primary:hover, .btn-secondary:hover {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}
.btn-primary:active, .btn-secondary:active {
  transform: translate(2px, 2px);
  box-shadow: 1px 1px 0 var(--border-color);
}
.btn-primary:disabled, .btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
  box-shadow: 3px 3px 0 var(--border-color);
}

/* 扫描结果 */
.scan-result-card {
  margin-top: 20px;
}
.result-container {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 20px;
  box-shadow: 5px 5px 0 var(--border-color);
}
.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 10px;
}
.result-header h3 {
  font-size: 16px;
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.result-header p {
  font-size: 12px;
  color: var(--text-secondary);
  margin: 0;
}

/* 标签样式 */
.tag {
  font-size: 10px;
  padding: 4px 8px;
  border-radius: 0;
  border: 1px solid var(--border-color);
}
.tag-primary {
  background: #2196F3;
  color: white;
}
.tag-info {
  background: #ff9800;
  color: white;
}
.tag-success {
  background: #4CAF50;
  color: white;
}
.tag-danger {
  background: #f44336;
  color: white;
}

/* 表格样式 */
.table-container {
  overflow-x: auto;
}
.pixel-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.pixel-table th, .pixel-table td {
  border: 2px solid var(--border-color);
  padding: 8px;
  text-align: center;
}
.pixel-table th {
  background: var(--bg-main);
  color: var(--text-primary);
  font-weight: bold;
}
.pixel-table tr:nth-child(even) {
  background: var(--hover-color);
}
.pixel-table tr:hover {
  background: var(--border-color);
}

/* 弹窗样式 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}
.modal-content {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 20px;
  width: 60%;
  max-width: 800px;
  box-shadow: 8px 8px 0 var(--border-color);
}
.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 2px solid var(--border-color);
}
.modal-header h3 {
  font-size: 16px;
  color: var(--text-primary);
  margin: 0;
}
.modal-close {
  font-size: 24px;
  background: none;
  border: none;
  cursor: pointer;
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
}
.modal-body {
  margin-bottom: 20px;
}
.detail-item {
  margin-bottom: 12px;
  display: flex;
  flex-wrap: wrap;
}
.detail-label {
  font-weight: bold;
  color: var(--text-primary);
  margin-right: 10px;
  min-width: 120px;
}
.detail-value {
  color: var(--text-secondary);
  flex: 1;
}
.modal-footer {
  display: flex;
  justify-content: flex-end;
  padding-top: 10px;
  border-top: 2px solid var(--border-color);
}

/* 文本样式 */
.text-muted {
  color: var(--text-secondary);
  font-style: italic;
}

/* 响应式适配 */
@media (max-width: 768px) {
  .asset-scan-page {
    padding: 10px;
  }
  .page-title {
    font-size: 18px;
  }
  .form-row {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }
  .form-input {
    width: 100%;
    max-width: none;
  }
  .form-buttons {
    width: 100%;
    justify-content: flex-start;
  }
  .result-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }
  .page-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
    text-align: left;
  }
  .theme-toggle-btn {
    align-self: flex-end;
  }
  .modal-content {
    width: 90%;
  }
  .pixel-table {
    font-size: 10px;
  }
  .pixel-table th, .pixel-table td {
    padding: 4px;
  }
}
</style>