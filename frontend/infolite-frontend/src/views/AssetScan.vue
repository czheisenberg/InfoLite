<template>
  <div class="asset-scan-page">
    <!-- 新的页面头部（包含输入IP部分） -->
    <div class="new-page-header">
      <!-- 顶部标题部分 -->
      <div class="header-top">
        <h1 class="page-title">InfoLite 网络资产扫描平台</h1>

        <div class="header-actions">
          <span class="user-info" v-if="username">
            {{ username }}
          </span>
          <button 
            class="btn-secondary" 
            @click="handleLogout"
            title="退出登录"
          >
            退出
          </button>
          <button 
            class="theme-toggle-btn"
            @click="toggleTheme"
            title="切换主题"
          >
            {{ theme === 'light' ? '🌙' : '☀️' }}
          </button>
        </div>
      </div>
      
      <!-- 扫描表单部分 -->
      <div class="header-form">
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

        <!-- 结果卡片 -->
        <div class="cards-container">
          <div 
            v-for="row in tableData" 
            :key="`${row.ip}-${row.port}`"
            class="asset-card"
          >
            <!-- 卡片头部 -->
            <div class="card-header">
              <div class="card-title">
                {{ row.protocol }}://{{ row.ip }}:{{ row.port }}
              </div>
              <div class="card-port">{{ row.port }}</div>
            </div>
            
            <!-- 卡片内容 -->
            <div class="card-content">
              <!-- 基本信息 -->
              <div class="info-row">
                <span class="info-label">目标IP：</span>
                <span class="info-value">{{ row.ip }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">端口状态：</span>
                <span class="info-value">{{ row.status }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">服务Banner：</span>
                <span class="info-value">{{ row.banner }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">组件指纹：</span>
                <span class="info-value">{{ row.fingerprint.length > 0 ? row.fingerprint.join('、') : '未识别' }}</span>
              </div>
              
              <!-- HTTP状态码 -->
              <div class="info-row" v-if="row.http_info">
                <span class="info-label">HTTP状态码：</span>
                <span class="info-value">{{ row.http_info.status_code }}</span>
              </div>
              
              <!-- HTTP响应头 -->
              <div class="headers-section" v-if="hasCardHeaders(row)">
                <div class="headers-tab">Header</div>
                <pre class="headers-content">{{ getCardHeaders(row) }}</pre>
              </div>
            </div>
            
            <!-- 卡片底部 -->
            <div class="card-footer">
              <span class="scan-time">{{ row.scan_time_str }}</span>
              <button class="btn-text" @click="showDetail(row)">详情</button>
            </div>
          </div>
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
          <!-- HTTP响应头信息 -->
          <div class="detail-item" v-if="hasHeaders">
            <span class="detail-label">HTTP响应头：</span>
            <div class="detail-value headers-container">
              <pre class="headers-pre">{{ formattedHeaders }}</pre>
            </div>
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
// 引入封装的API接口
import { queryAsset, getAssetDetail, getAssetList } from '../api/asset'
// 引入Pixelium Design的Message组件
import { Message } from '@pixelium/web-vue/es'
const $message = Message

// 主题
import { inject, onMounted } from 'vue'
const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

// 用户信息
const username = ref('')

// 初始化用户信息
onMounted(() => {
  username.value = localStorage.getItem('username') || ''
})

// 处理登出
const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  window.location.href = '/login'
}

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
    $message['info']('请输入目标IP地址')
    return
  }
  if (!validateIp(scanForm.ip)) {
    $message['info']('请输入正确的IP地址（如127.0.0.1）')
    return
  }

  try {
    // 调用后端接口，refresh=false（默认不刷新）
    const res = await queryAsset({ ip: scanForm.ip })
    if (res.code === 200) {
      tableData.value = res.data
      // 提示成功
      $message['success']('扫描/查询成功')
    } else {
      $message['info'](res.msg)
    }
  } catch (error) {
    console.error('查询失败：', error)
    tableData.value = []
    // 显示具体的错误信息
    const errorMsg = error.response?.data?.msg || '查询失败'
    $message['error'](errorMsg)
  }
}

// 处理刷新扫描（强制重新扫描）
const handleRefresh = async () => {
  if (!scanForm.ip) {
    $message['info']('请输入IP地址')
    return
  }
  
  if (!validateIp(scanForm.ip)) {
    $message['info']('请输入正确的IP地址（如127.0.0.1）')
    return
  }
  
  try {
    // 调用后端接口，refresh=true（强制刷新）
    const res = await queryAsset({ ip: scanForm.ip, refresh: true })
    if (res.code === 200) {
      tableData.value = res.data
      // 提示成功
      $message['success']('刷新扫描成功')
    } else {
      $message['info'](res.msg)
    }
  } catch (error) {
    console.error('刷新扫描失败：', error)
    // 显示具体的错误信息
    const errorMsg = error.response?.data?.msg || '刷新扫描失败'
    $message['error'](errorMsg)
  }
}

// 查看资产详情
const showDetail = (row) => {
  currentAsset.value = row
  detailDialogVisible.value = true
}

// 计算属性：是否有headers信息
const hasHeaders = computed(() => {
  // 检查http_info.headers（实时扫描结果）
  if (currentAsset.value.http_info && currentAsset.value.http_info.headers) {
    return Object.keys(currentAsset.value.http_info.headers).length > 0
  }
  // 检查headers（数据库查询结果）
  if (currentAsset.value.headers) {
    return Object.keys(currentAsset.value.headers).length > 0
  }
  return false
})

// 计算属性：格式化后的headers信息
const formattedHeaders = computed(() => {
  let headers = {}
  // 优先使用http_info.headers（实时扫描结果）
  if (currentAsset.value.http_info && currentAsset.value.http_info.headers) {
    headers = currentAsset.value.http_info.headers
  }
  // 否则使用headers（数据库查询结果）
  else if (currentAsset.value.headers) {
    headers = currentAsset.value.headers
  }
  
  // 格式化为字符串
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n')
})

// 响应头展开状态管理
const openHeaders = ref(new Set())

// 检查资产是否有headers信息（用于卡片）
const hasCardHeaders = (row) => {
  // 检查http_info.headers（实时扫描结果）
  if (row.http_info && row.http_info.headers) {
    return Object.keys(row.http_info.headers).length > 0
  }
  // 检查headers（数据库查询结果）
  if (row.headers) {
    return Object.keys(row.headers).length > 0
  }
  return false
}

// 切换响应头展开/收起状态
const toggleHeaders = (key) => {
  if (openHeaders.value.has(key)) {
    openHeaders.value.delete(key)
  } else {
    openHeaders.value.add(key)
  }
}

// 检查响应头是否展开
const isHeadersOpen = (key) => {
  return openHeaders.value.has(key)
}

// 获取格式化后的响应头信息（用于卡片）
const getCardHeaders = (row) => {
  let headers = {}
  // 优先使用http_info.headers（实时扫描结果）
  if (row.http_info && row.http_info.headers) {
    headers = row.http_info.headers
  }
  // 否则使用headers（数据库查询结果）
  else if (row.headers) {
    headers = row.headers
  }
  
  // 格式化为字符串
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n')
}
</script>

<style scoped>
/* 像素风格字体 */
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

/* 页面整体样式：替换为CSS变量 👇 */
.asset-scan-page {
  max-width: 1400px;
  /* width: 100%; */
  margin: 0 auto;
  padding: 20px;
  background-color: var(--bg-main);
  min-height: 100vh;
  font-family: 'Press Start 2P', monospace;
}

/* 新的页面头部（包含输入IP部分） */
.new-page-header {
  background: var(--bg-main);
  border-bottom: 3px solid var(--border-color);
  padding: 20px;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 100;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  max-width: 1400px;
  margin: 0 auto;
  width: calc(100% - 40px);
}

/* 头部顶部（标题和操作按钮） */
.header-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-top .header-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.header-top .user-info {
  font-size: 14px;
  color: var(--text-primary);
  padding: 8px 12px;
  background-color: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: 4px;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
}

.header-top .page-title {
  font-size: 24px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
}

/* 头部表单部分 */
.header-form {
  margin-top: 10px;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.user-info {
  font-size: 14px;
  color: var(--text-primary);
  padding: 8px 12px;
  background-color: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: 4px;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
}
.page-title {
  font-size: 24px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
}

/* 主题切换按钮：像素风格 */
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
  margin-top: 240px;
  margin-bottom: 30px;
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

/* HTTP响应头容器样式 */
.headers-container {
  width: 100%;
  margin-top: 8px;
}

.headers-pre {
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  padding: 12px;
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.4;
  color: var(--text-primary);
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 300px;
  overflow-y: auto;
  box-shadow: inset 2px 2px 0 var(--border-color);
}

/* 卡片容器样式 */
.cards-container {
  display: flex;
  flex-direction: column;
  gap: 20px;
  margin-top: 20px;
}

/* 资产卡片样式 */
.asset-card {
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  transition: all 0.3s ease;
}

.asset-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
}

/* 卡片头部 */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: var(--bg-secondary);
  border-bottom: 2px solid var(--border-color);
}

.card-title {
  font-size: 16px;
  font-weight: bold;
  color: var(--text-primary);
  word-break: break-all;
}

.card-port {
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 4px 8px;
  border: 2px solid var(--border-color);
  border-radius: 4px;
  font-size: 14px;
  font-weight: bold;
}

/* 卡片内容 */
.card-content {
  padding: 16px;
}

/* 信息行 */
.info-row {
  margin-bottom: 10px;
  font-size: 14px;
}

.info-label {
  color: var(--text-secondary);
  margin-right: 8px;
}

.info-value {
  color: var(--text-primary);
}

/* 响应头部分 */
.headers-section {
  margin-top: 16px;
  border-top: 2px solid var(--border-color);
  padding-top: 16px;
}

.headers-tab {
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 8px 16px;
  border: 2px solid var(--border-color);
  border-bottom: none;
  border-radius: 4px 4px 0 0;
  font-weight: bold;
  font-size: 14px;
  display: inline-block;
  margin-bottom: 0;
}

.headers-content {
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  padding: 12px;
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.4;
  color: var(--text-primary);
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 300px;
  overflow-y: auto;
  border-radius: 0 0 4px 4px;
  box-shadow: inset 2px 2px 0 var(--border-color);
}

/* 卡片底部 */
.card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: var(--bg-secondary);
  border-top: 2px solid var(--border-color);
  font-size: 12px;
  color: var(--text-secondary);
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
  /* 卡片布局响应式 */
  .asset-card {
    margin-bottom: 15px;
  }
  .card-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }
  .card-port {
    align-self: flex-end;
  }
}
</style>