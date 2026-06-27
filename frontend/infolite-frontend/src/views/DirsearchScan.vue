<template>
  <div class="dirsearch-page">
    <PageHeader 
      :username="username"
      :theme="theme"
      @logout="handleLogout"
      @toggle-theme="toggleTheme"
    />

    <div class="main-content">
      <!-- 左侧：参数配置区 -->
      <div class="left-panel">
        <!-- 目标设置 -->
        <div class="config-card">
          <div class="card-title">🎯 目标设置</div>
          <div class="form-group">
            <label class="form-label">目标 URL</label>
            <input 
              v-model="targetUrl" 
              type="text" 
              class="form-input" 
              placeholder="如：https://example.com/" 
            />
          </div>
        </div>

        <!-- 扩展名设置 -->
        <div class="config-card">
          <div class="card-title">📋 扩展名设置</div>
          <div class="extensions-grid">
            <label 
              v-for="ext in extensionOptions" 
              :key="ext.value" 
              class="extension-item"
              :class="{ active: selectedExtensions.includes(ext.value) }"
            >
              <input 
                type="checkbox" 
                v-model="selectedExtensions" 
                :value="ext.value"
                style="display:none"
              />
              <span>{{ ext.name }}</span>
            </label>
          </div>
          <div class="form-group" style="margin-top: 10px;">
            <label class="form-label">自定义扩展（逗号分隔）</label>
            <input 
              v-model="customExtensions" 
              type="text" 
              class="form-input" 
              placeholder="如：php,html,js,json"
            />
          </div>
        </div>

        <!-- 词表选择 -->
        <div class="config-card">
          <div class="card-title">📚 词表选择</div>
          <div class="wordlist-options">
            <label 
              v-for="wl in wordlistOptions" 
              :key="wl.value" 
              class="wordlist-item"
              :class="{ active: selectedWordlist === wl.value }"
            >
              <input 
                type="radio" 
                v-model="selectedWordlist" 
                :value="wl.value"
                style="display:none"
              />
              <span class="wordlist-name">{{ wl.name }}</span>
              <span class="wordlist-desc">{{ wl.desc }}</span>
            </label>
          </div>
        </div>

        <!-- 扫描选项 -->
        <div class="config-card">
          <div class="card-title">⚙️ 扫描选项</div>
          <div class="option-row">
            <label class="option-label">超时时间</label>
            <select v-model="timeout" class="form-select">
              <option value="5">5秒</option>
              <option value="10">10秒（推荐）</option>
              <option value="30">30秒</option>
              <option value="60">60秒</option>
            </select>
          </div>
          <div class="checkbox-list">
            <label class="checkbox-item">
              <input type="checkbox" v-model="followRedirects" />
              <span class="param-name">跟随重定向</span>
            </label>
          </div>
        </div>

        <!-- 过滤器 -->
        <div class="config-card">
          <div class="card-title">🔇 过滤器</div>
          <div class="checkbox-list">
            <label class="checkbox-item">
              <input type="checkbox" v-model="ignore404" />
              <span class="param-name">忽略 404</span>
            </label>
            <label class="checkbox-item">
              <input type="checkbox" v-model="ignore403" />
              <span class="param-name">忽略 403</span>
            </label>
            <label class="checkbox-item">
              <input type="checkbox" v-model="ignore5xx" />
              <span class="param-name">忽略 5xx</span>
            </label>
          </div>
        </div>

        <!-- 扫描按钮 -->
        <div class="scan-actions">
          <button 
            class="btn-scan" 
            @click="startScan"
            :disabled="scanning || !targetUrl.trim()"
          >
            <span v-if="scanning">🔄 扫描中...</span>
            <span v-else>🚀 开始扫描</span>
          </button>
          <button 
            class="btn-stop" 
            @click="stopScan"
            :disabled="!scanning"
            v-if="scanning"
          >
            ⏹ 停止
          </button>
        </div>
      </div>

      <!-- 右侧：结果展示区 -->
      <div class="right-panel">
        <!-- 结果头部 -->
        <div class="result-header" v-if="hasResult || scanning">
          <div class="result-info">
            <h3>扫描结果</h3>
            <p v-if="!scanning">共发现 {{ results.length }} 个路径</p>
            <p v-else>正在扫描，已发现 {{ results.length }} 个路径...</p>
          </div>
          <div class="result-actions">
            <button 
              class="btn-export" 
              @click="handleExport"
              :disabled="results.length === 0"
            >
              📊 导出 Excel
            </button>
          </div>
        </div>

        <!-- 扫描状态 -->
        <div class="scan-status" v-if="scanning">
          <div class="status-info">
            <span class="status-dot"></span>
            <span>正在扫描: {{ targetUrl }}</span>
          </div>
          <div class="status-progress">
            <div class="progress-bar">
              <div class="progress-fill" :style="{ width: progressPercent + '%' }"></div>
            </div>
            <span class="progress-text">{{ results.length }} 个路径发现</span>
          </div>
        </div>

        <!-- 结果列表 -->
        <div class="results-container" v-if="hasResult">
          <div 
            v-for="(result, index) in results" 
            :key="index"
            class="result-card"
            :class="'status-' + getStatusClass(result.status)"
          >
            <div class="result-card-header">
              <span class="status-badge" :class="'status-' + getStatusClass(result.status)">
                {{ result.status }}
              </span>
              <span class="result-path">{{ result.path || '/' }}</span>
            </div>
            <div class="result-card-body">
              <div class="result-url">{{ result.url }}</div>
              <div class="result-meta">
                <span v-if="result.content_type">类型: {{ result.content_type }}</span>
                <span v-if="result.length">大小: {{ formatLength(result.length) }}</span>
                <span v-if="result.elapsed">耗时: {{ result.elapsed.toFixed(2) }}s</span>
              </div>
              <div class="result-redirect" v-if="result.redirect">
                → 重定向到: {{ result.redirect }}
              </div>
            </div>
          </div>
        </div>

        <!-- 空状态 -->
        <div class="empty-state" v-if="!hasResult && !scanning">
          <div class="empty-icon">🔍</div>
          <p class="empty-text">输入目标 URL 开始扫描</p>
          <p class="empty-desc">dirsearch 将扫描常见的 Web 路径，发现潜在的管理后台、API 接口、备份文件等</p>
        </div>
      </div>
    </div>

    <!-- 页面底部 -->
    <PageFooter />
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import PageFooter from '../components/PageFooter.vue'
import * as XLSX from 'xlsx'
import { Message } from '@pixelium/web-vue/es'

const $message = Message

const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

const username = ref(localStorage.getItem('username') || '')

// 扫描参数
const targetUrl = ref('')
const selectedExtensions = ref(['php', 'html', 'js'])
const customExtensions = ref('')
const selectedWordlist = ref('default')
const timeout = ref(30)
const followRedirects = ref(false)
const ignore404 = ref(true)
const ignore403 = ref(false)
const ignore5xx = ref(false)

// 扫描状态
const scanning = ref(false)
const results = ref([])
const progressPercent = ref(0)

// 扩展名选项
const extensionOptions = [
  { name: 'PHP', value: 'php' },
  { name: 'HTML', value: 'html' },
  { name: 'JS', value: 'js' },
  { name: 'JSON', value: 'json' },
  { name: 'JSP', value: 'jsp' },
  { name: 'ASP', value: 'asp' },
  { name: 'ASPX', value: 'aspx' },
  { name: 'Python', value: 'py' },
  { name: 'Ruby', value: 'rb' },
  { name: 'Java', value: 'java' },
  { name: 'C#', value: 'cs' },
  { name: 'CGI', value: 'cgi' },
  { name: 'XML', value: 'xml' },
  { name: 'YAML', value: 'yaml,yml' },
  { name: 'TXT', value: 'txt' },
  { name: 'MD', value: 'md' },
  { name: 'Conf', value: 'conf' },
  { name: 'SQL', value: 'sql' },
  { name: '备份', value: 'bak,backup,old' },
  { name: 'LOG', value: 'log' },
]

// 词表选项
const wordlistOptions = [
  { name: '内置词表', value: 'default', desc: 'dicc.txt - 通用目录' },
  { name: '通用词表', value: 'common', desc: '常见路径' },
  { name: 'API 词表', value: 'api', desc: 'API 接口路径' },
  { name: '管理员', value: 'admin', desc: '管理后台路径' },
  { name: '认证', value: 'auth', desc: '认证相关路径' },
  { name: '备份', value: 'backups', desc: '备份文件路径' },
  { name: '数据库', value: 'db', desc: '数据库相关' },
  { name: '日志', value: 'logs', desc: '日志文件路径' },
]

// 计算属性
const hasResult = computed(() => results.value.length > 0)

// 获取所有选中的扩展名
const getExtensions = () => {
  const exts = [...selectedExtensions.value]
  if (customExtensions.value) {
    const custom = customExtensions.value.split(',').map(e => e.trim()).filter(e => e)
    exts.push(...custom)
  }
  return exts.join(',')
}

// 开始扫描
const startScan = async () => {
  if (!targetUrl.value.trim()) {
    $message['warning']('请输入目标 URL')
    return
  }

  // 验证 URL
  let url = targetUrl.value.trim()
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url
  }
  if (!url.endsWith('/')) {
    url += '/'
  }
  targetUrl.value = url

  scanning.value = true
  results.value = []
  progressPercent.value = 0

  try {
    const params = new URLSearchParams({
      url: targetUrl.value,
      extensions: getExtensions(),
      timeout: timeout.value.toString(),
      follow_redirects: followRedirects.value.toString(),
      ignore_404: ignore404.value.toString(),
      ignore_403: ignore403.value.toString(),
      ignore_5xx: ignore5xx.value.toString(),
      wordlist_type: selectedWordlist.value,
    })

    const response = await fetch(`/api/dirsearch/scan?${params}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
      }
    })

    if (!response.ok) {
      throw new Error('扫描请求失败')
    }

    const data = await response.json()
    
    if (data.success) {
      results.value = data.results
      $message['success'](`扫描完成，发现 ${data.results.length} 个路径`)
    } else {
      $message['error'](data.message || '扫描失败')
    }
  } catch (error) {
    console.error('扫描错误:', error)
    $message['error'](`扫描出错: ${error.message}`)
  } finally {
    scanning.value = false
  }
}

// 停止扫描
const stopScan = () => {
  scanning.value = false
  $message['info']('扫描已停止')
}

// 获取状态样式类
const getStatusClass = (status) => {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'redirect'
  if (status >= 400 && status < 500) return 'client-error'
  if (status >= 500) return 'server-error'
  return 'unknown'
}

// 格式化长度
const formatLength = (length) => {
  if (length < 1024) return length + ' B'
  if (length < 1024 * 1024) return (length / 1024).toFixed(1) + ' KB'
  return (length / (1024 * 1024)).toFixed(1) + ' MB'
}

// 导出 Excel
const handleExport = () => {
  if (results.value.length === 0) {
    $message['warning']('没有可导出的数据')
    return
  }

  const exportData = results.value.map(r => ({
    'URL': r.url,
    '路径': r.path || '/',
    '状态码': r.status,
    '内容类型': r.content_type || '',
    '大小': r.length || 0,
    '耗时(秒)': r.elapsed ? r.elapsed.toFixed(2) : 0,
    '重定向': r.redirect || '',
    'Content-Type': r.content_type || '',
  }))

  const ws = XLSX.utils.json_to_sheet(exportData)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Dirsearch结果')

  // 设置列宽
  ws['!cols'] = [
    { wch: 50 },  // URL
    { wch: 30 },  // 路径
    { wch: 10 },  // 状态码
    { wch: 20 },  // 内容类型
    { wch: 15 },  // 大小
    { wch: 12 },  // 耗时
    { wch: 40 },  // 重定向
    { wch: 20 },  // Content-Type
  ]

  const fileName = `dirsearch_${targetUrl.value.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.xlsx`
  XLSX.writeFile(wb, fileName)
  $message['success'](`已导出 ${exportData.length} 条结果到 ${fileName}`)
}

// 退出登录
const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  window.location.href = '/login'
}
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

.dirsearch-page {
  min-height: 100vh;
  background-color: var(--bg-main);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
  padding-top: 80px;
  display: flex;
  flex-direction: column;
}

/* 主内容区 */
.main-content {
  display: flex;
  gap: 20px;
  padding: 20px;
  max-width: 1600px;
  margin: 0 auto;
  flex: 1;
  width: 100%;
  box-sizing: border-box;
}

/* 左侧面板 */
.left-panel {
  width: 380px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 15px;
}

/* 右侧面板 */
.right-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 15px;
  min-width: 0;
}

/* 配置卡片 */
.config-card {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 15px;
  box-shadow: 4px 4px 0 var(--border-color);
}

.card-title {
  font-size: 11px;
  color: var(--text-primary);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--border-color);
}

/* 表单元素 */
.form-group {
  margin-bottom: 10px;
}

.form-label {
  display: block;
  font-size: 11px;
  color: var(--text-secondary);
  margin-bottom: 6px;
}

.form-input, .form-select {
  width: 100%;
  height: 36px;
  padding: 0 10px;
  border: 2px solid var(--border-color);
  background-color: var(--bg-main);
  color: var(--text-primary);
  font-size: 10px;
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
  box-sizing: border-box;
}

.form-input:focus, .form-select:focus {
  outline: none;
  border-color: #4CAF50;
}

.form-select {
  cursor: pointer;
}

/* 扩展名网格 */
.extensions-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.extension-item {
  padding: 5px 10px;
  font-size: 11px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  transition: all 0.2s;
  color: var(--text-secondary);
}

.extension-item.active {
  background: #4CAF50;
  color: white;
  border-color: #4CAF50;
}

.extension-item:hover {
  border-color: #4CAF50;
}

/* 词表选项 */
.wordlist-options {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.wordlist-item {
  padding: 8px 12px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.wordlist-item.active {
  background: rgba(76, 175, 80, 0.1);
  border-color: #4CAF50;
}

.wordlist-item:hover {
  border-color: #4CAF50;
}

.wordlist-name {
  font-size: 12px;
  color: var(--text-primary);
}

.wordlist-desc {
  font-size: 10px;
  color: var(--text-secondary);
}

/* 选项行 */
.option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.option-label {
  font-size: 11px;
  color: var(--text-secondary);
}

/* 复选框列表 */
.checkbox-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.checkbox-item {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 11px;
  color: var(--text-primary);
}

.checkbox-item input[type="checkbox"] {
  width: 16px;
  height: 16px;
  accent-color: #4CAF50;
  cursor: pointer;
}

/* 扫描按钮 */
.scan-actions {
  display: flex;
  gap: 10px;
}

.btn-scan {
  flex: 1;
  height: 44px;
  background: #4CAF50;
  color: white;
  border: 3px solid var(--border-color);
  font-size: 11px;
  font-family: 'Press Start 2P', monospace;
  cursor: pointer;
  box-shadow: 4px 4px 0 var(--border-color);
  transition: all 0.2s;
}

.btn-scan:hover:not(:disabled) {
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 var(--border-color);
}

.btn-scan:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-stop {
  width: 80px;
  height: 44px;
  background: #f44336;
  color: white;
  border: 3px solid var(--border-color);
  font-size: 10px;
  font-family: 'Press Start 2P', monospace;
  cursor: pointer;
  box-shadow: 4px 4px 0 var(--border-color);
}

/* 结果头部 */
.result-header {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 15px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: 4px 4px 0 var(--border-color);
}

.result-info h3 {
  font-size: 12px;
  color: var(--text-primary);
  margin: 0 0 5px 0;
}

.result-info p {
  font-size: 11px;
  color: var(--text-secondary);
  margin: 0;
}

.btn-export {
  background: #4CAF50;
  color: white;
  border: 3px solid var(--border-color);
  padding: 10px 16px;
  font-size: 10px;
  font-family: 'Press Start 2P', monospace;
  cursor: pointer;
  box-shadow: 4px 4px 0 var(--border-color);
  transition: all 0.2s;
}

.btn-export:hover:not(:disabled) {
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 var(--border-color);
}

.btn-export:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* 扫描状态 */
.scan-status {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 15px;
  box-shadow: 4px 4px 0 var(--border-color);
}

.status-info {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
  font-size: 10px;
  color: var(--text-primary);
}

.status-dot {
  width: 10px;
  height: 10px;
  background: #4CAF50;
  border-radius: 50%;
  animation: pulse 1s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.status-progress {
  display: flex;
  align-items: center;
  gap: 10px;
}

.progress-bar {
  flex: 1;
  height: 8px;
  background: var(--bg-main);
  border: 2px solid var(--border-color);
}

.progress-fill {
  height: 100%;
  background: #4CAF50;
  transition: width 0.3s;
}

.progress-text {
  font-size: 11px;
  color: var(--text-secondary);
}

/* 结果列表 */
.results-container {
  display: flex;
  flex-direction: column;
  gap: 10px;
  max-height: calc(100vh - 350px);
  overflow-y: auto;
}

.result-card {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  box-shadow: 4px 4px 0 var(--border-color);
  transition: all 0.2s;
}

.result-card:hover {
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 var(--border-color);
}

.result-card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 15px;
  border-bottom: 2px solid var(--border-color);
}

.status-badge {
  padding: 4px 8px;
  font-size: 10px;
  font-weight: bold;
  border: 2px solid;
}

.status-badge.status-success { color: #4CAF50; border-color: #4CAF50; }
.status-badge.status-redirect { color: #FF9800; border-color: #FF9800; }
.status-badge.status-client-error { color: #f44336; border-color: #f44336; }
.status-badge.status-server-error { color: #9C27B0; border-color: #9C27B0; }
.status-badge.status-unknown { color: var(--text-secondary); border-color: var(--text-secondary); }

.result-path {
  font-size: 10px;
  color: var(--text-primary);
  word-break: break-all;
}

.result-card-body {
  padding: 10px 15px;
}

.result-url {
  font-size: 11px;
  color: var(--text-secondary);
  word-break: break-all;
  margin-bottom: 8px;
}

.result-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 15px;
  font-size: 11px;
  color: var(--text-secondary);
}

.result-redirect {
  font-size: 11px;
  color: #FF9800;
  margin-top: 8px;
  word-break: break-all;
}

/* 空状态 */
.empty-state {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 60px 20px;
  text-align: center;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 20px;
}

.empty-text {
  font-size: 12px;
  color: var(--text-primary);
  margin: 0 0 10px 0;
}

.empty-desc {
  font-size: 11px;
  color: var(--text-secondary);
  margin: 0;
  line-height: 1.8;
  max-width: 400px;
}

/* 响应式 */
@media (max-width: 1024px) {
  .main-content {
    flex-direction: column;
  }
  .left-panel {
    width: 100%;
  }
}

@media (max-width: 768px) {
  .dirsearch-page {
    padding-top: 70px;
  }
  .main-content {
    padding: 10px;
  }
  .results-container {
    max-height: none;
  }
}
</style>
