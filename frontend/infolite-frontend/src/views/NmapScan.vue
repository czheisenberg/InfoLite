<template>
  <div class="nmap-scan-page">
    <!-- 顶部导航栏 -->
    <div class="top-nav">
      <div class="nav-left">
        <h1 class="nav-title">InfoLite Nmap 扫描</h1>
      </div>
      <div class="nav-right">
        <button class="nav-btn" @click="goToAssetScan">资产扫描</button>
        <button class="nav-btn" @click="handleLogout">退出</button>
        <button class="theme-toggle-btn" @click="toggleTheme">
          {{ theme === 'light' ? '🌙' : '☀️' }}
        </button>
      </div>
    </div>

    <div class="main-content">
      <!-- 左侧：参数配置区 -->
      <div class="left-panel">
        <!-- 目标设置 -->
        <div class="config-card">
          <div class="card-title">🎯 目标设置</div>
          <div class="form-group">
            <label class="form-label">目标 IP</label>
            <input v-model="targetIp" type="text" class="form-input" placeholder="如：127.0.0.1" />
          </div>
          <div class="form-group">
            <label class="form-label">端口范围</label>
            <input v-model="portRange" type="text" class="form-input" placeholder="如：1-65535 或 80,443,8080" />
          </div>
        </div>

        <!-- 扫描类型 -->
        <div class="config-card">
          <div class="card-title">🔍 扫描类型</div>
          <div class="options-grid">
            <label v-for="opt in scanTypeOptions" :key="opt.value" class="option-item" :class="{ active: selectedScanType === opt.value }">
              <input type="radio" v-model="selectedScanType" :value="opt.value" />
              <div class="option-content">
                <span class="option-name">{{ opt.name }}</span>
                <span class="option-desc">{{ opt.desc }}</span>
              </div>
            </label>
          </div>
        </div>

        <!-- 常用参数勾选 -->
        <div class="config-card">
          <div class="card-title">⚙️ 常用参数</div>
          <div class="checkbox-list">
            <label v-for="param in commonParams" :key="param.value" class="checkbox-item">
              <input type="checkbox" v-model="selectedParams" :value="param.value" />
              <span class="param-name">{{ param.name }}</span>
              <span class="param-value">{{ param.value }}</span>
            </label>
          </div>
        </div>

        <!-- 扫描速度 -->
        <div class="config-card">
          <div class="card-title">⚡ 扫描速度</div>
          <div class="speed-options">
            <label v-for="speed in speedOptions" :key="speed.value" class="speed-item" :class="{ active: selectedSpeed === speed.value }">
              <input type="radio" v-model="selectedSpeed" :value="speed.value" />
              <span>{{ speed.name }}</span>
            </label>
          </div>
        </div>

        <!-- 其他选项 -->
        <div class="config-card">
          <div class="card-title">📋 其他选项</div>
          <div class="checkbox-list">
            <label class="checkbox-item">
              <input type="checkbox" v-model="saveToDb" />
              <span class="param-name">保存结果到数据库</span>
            </label>
          </div>
        </div>

        <!-- 手动输入参数 -->
        <div class="config-card">
          <div class="card-title">✏️ 手动输入参数</div>
          <textarea
            v-model="manualArgs"
            class="form-textarea"
            placeholder="直接输入 Nmap 参数，如：-sV -T4 -O --script=default"
            rows="3"
          ></textarea>
          <button class="btn-secondary full-width" @click="applyManualArgs">应用手动参数</button>
        </div>

        <!-- 生成的命令预览 -->
        <div class="config-card">
          <div class="card-title">📝 生成的命令</div>
          <div class="command-preview">
            <span class="cmd-prefix">nmap</span>
            <span class="cmd-args">{{ generatedArgs }}</span>
            <span class="cmd-target">{{ targetIp || '[目标IP]' }}</span>
          </div>
        </div>

        <!-- 扫描按钮 -->
        <button class="btn-primary full-width scan-btn" @click="startScan" :disabled="scanning || !targetIp">
          <span v-if="scanning">⏳ 扫描中...</span>
          <span v-else>🚀 开始扫描</span>
        </button>
      </div>

      <!-- 右侧：结果展示区 -->
      <div class="right-panel">
        <div v-if="scanResult.length > 0" class="result-card">
          <div class="result-header">
            <h3>扫描结果</h3>
            <div class="result-header-right">
              <span class="result-count">共 {{ scanResult.length }} 个开放端口</span>
              <button class="btn-export" @click="handleExport">导出Excel</button>
            </div>
          </div>
          <div class="cards-container">
            <div v-for="row in scanResult" :key="`${row.ip}-${row.port}`" class="asset-card">
              <div class="card-header">
                <div class="card-title">
                  {{ row.protocol }}://{{ row.ip }}:{{ row.port }}
                </div>
                <div class="card-port">{{ row.port }}</div>
              </div>
              <div class="card-content">
                <div class="info-row">
                  <span class="info-label">服务名称：</span>
                  <span class="info-value">{{ row.service_name || '未知' }}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">产品版本：</span>
                  <span class="info-value">{{ row.product || '未知' }} {{ row.version || '' }}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">组件指纹：</span>
                  <span class="info-value">{{ row.fingerprint && row.fingerprint.length > 0 ? row.fingerprint.join('、') : '未识别' }}</span>
                </div>
                <div class="info-row" v-if="row.banner">
                  <span class="info-label">Banner：</span>
                  <span class="info-value">{{ row.banner }}</span>
                </div>
              </div>
              <div class="card-footer">
                <span class="scan-time">{{ row.scan_time_str }}</span>
              </div>
            </div>
          </div>
        </div>

        <div v-else-if="scanning" class="empty-state">
          <div class="loading-spinner"></div>
          <p>正在扫描中，请稍候...</p>
        </div>

        <div v-else class="empty-state">
          <p class="empty-icon">🔍</p>
          <p>配置左侧参数，点击开始扫描</p>
        </div>
      </div>
    </div>

    <PageFooter />
  </div>
</template>

<script setup>
import { ref, computed, inject, onMounted } from 'vue'
import PageFooter from '../components/PageFooter.vue'
import { nmapCustomScan } from '../api/asset'
import * as XLSX from 'xlsx'
import { Message } from '@pixelium/web-vue/es'
const $message = Message

const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

const targetIp = ref('')
const portRange = ref('1-1000')
const selectedScanType = ref('-sV')
const selectedParams = ref([])
const selectedSpeed = ref('-T4')
const saveToDb = ref(true)
const manualArgs = ref('')
const scanning = ref(false)
const scanResult = ref([])

const scanTypeOptions = [
  { name: '版本探测', value: '-sV', desc: '探测服务版本信息' },
  { name: 'TCP SYN', value: '-sS', desc: '半开扫描，速度快' },
  { name: 'TCP Connect', value: '-sT', desc: '完整TCP连接扫描' },
  { name: 'UDP扫描', value: '-sU', desc: 'UDP端口扫描' },
  { name: '操作系统', value: '-O', desc: '探测操作系统类型' },
  { name: '快速扫描', value: '-F', desc: '只扫描常用端口' }
]

const commonParams = [
  { name: '服务版本', value: '-sV' },
  { name: '操作系统', value: '-O' },
  { name: '脚本扫描', value: '-sC' },
  { name: '全端口', value: '-p-' },
  { name: '详细输出', value: '-v' },
  { name: '无主机发现', value: '-Pn' },
  { name: '快速扫描', value: '-F' },
  { name: '仅显示开放', value: '--open' },
  { name: '默认脚本', value: '--script=default' },
  { name: '暴力破解', value: '--script=brute' }
]

const speedOptions = [
  { name: 'T2 慢', value: '-T2' },
  { name: 'T3 正常', value: '-T3' },
  { name: 'T4 快', value: '-T4' },
  { name: 'T5 极速', value: '-T5' }
]

const generatedArgs = computed(() => {
  const args = []
  if (selectedScanType.value) {
    args.push(selectedScanType.value)
  }
  selectedParams.value.forEach(p => {
    if (!args.includes(p)) {
      args.push(p)
    }
  })
  if (selectedSpeed.value && !args.includes(selectedSpeed.value)) {
    args.push(selectedSpeed.value)
  }
  return args.join(' ')
})

const applyManualArgs = () => {
  if (!manualArgs.value.trim()) {
    $message['info']('请输入参数')
    return
  }
  selectedParams.value = []
  selectedScanType.value = ''
  selectedSpeed.value = ''
  const parts = manualArgs.value.trim().split(/\s+/)
  parts.forEach(p => {
    if (p.startsWith('-s') && p.length === 3) {
      selectedScanType.value = p
    } else if (p.startsWith('-T')) {
      selectedSpeed.value = p
    } else {
      selectedParams.value.push(p)
    }
  })
  $message['success']('参数已应用')
}

const validateIp = (ip) => {
  const reg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
  return reg.test(ip)
}

const startScan = async () => {
  if (!targetIp.value) {
    $message['info']('请输入目标IP')
    return
  }
  if (!validateIp(targetIp.value)) {
    $message['info']('请输入正确的IP地址')
    return
  }

  scanning.value = true
  scanResult.value = []

  try {
    const params = {
      ip: targetIp.value,
      ports: portRange.value,
      scan_args: generatedArgs.value,
      save_to_db: saveToDb.value
    }
    const res = await nmapCustomScan(params)
    if (res.code === 200) {
      scanResult.value = res.data
      $message['success'](`扫描完成，发现 ${res.data.length} 个开放端口`)
    } else {
      $message['error'](res.msg || '扫描失败')
    }
  } catch (error) {
    console.error('扫描失败：', error)
    const errorMsg = error.response?.data?.msg || '扫描失败'
    $message['error'](errorMsg)
  } finally {
    scanning.value = false
  }
}

const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  window.location.href = '/login'
}

const goToAssetScan = () => {
  window.location.href = '/'
}

const handleExport = () => {
  if (scanResult.value.length === 0) {
    $message['info']('没有可导出的数据')
    return
  }
  const exportData = scanResult.value.map(row => ({
    '目标IP': row.ip,
    '端口': row.port,
    '协议': row.protocol,
    '端口状态': row.status,
    '服务Banner': row.banner || '',
    '服务名称': row.service_name || '',
    '产品版本': row.product ? `${row.product} ${row.version || ''}` : '',
    '组件指纹': row.fingerprint && row.fingerprint.length > 0 ? row.fingerprint.join('、') : '未识别',
    '扫描时间': row.scan_time_str || ''
  }))
  const ws = XLSX.utils.json_to_sheet(exportData)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Nmap扫描结果')
  const ip = scanResult.value[0]?.ip || 'nmap'
  XLSX.writeFile(wb, `Nmap扫描_${ip}_${Date.now()}.xlsx`)
  $message['success']('导出成功')
}

onMounted(() => {
  const savedIp = localStorage.getItem('lastScanIp')
  if (savedIp) {
    targetIp.value = savedIp
  }
})
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

.nmap-scan-page {
  min-height: 100vh;
  background-color: var(--bg-main);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
  padding-top: 70px;
}

/* 顶部导航 */
.top-nav {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 60px;
  background: var(--bg-card);
  border-bottom: 3px solid var(--border-color);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  z-index: 100;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.nav-title {
  font-size: 18px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
}

.nav-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

.nav-btn {
  font-family: 'Press Start 2P', monospace;
  font-size: 10px;
  padding: 8px 12px;
  border: 2px solid var(--border-color);
  background: var(--bg-main);
  color: var(--text-primary);
  cursor: pointer;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
}

.nav-btn:hover {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}

.theme-toggle-btn {
  font-size: 20px;
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  padding: 6px 10px;
  cursor: pointer;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
}

.theme-toggle-btn:hover {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}

/* 主内容区 */
.main-content {
  display: flex;
  gap: 20px;
  padding: 20px;
  max-width: 1600px;
  margin: 0 auto;
}

/* 左侧面板 */
.left-panel {
  width: 380px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.config-card {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 15px;
  box-shadow: 4px 4px 0 var(--border-color);
}

.card-title {
  font-size: 12px;
  color: var(--text-primary);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--border-color);
}

.form-group {
  margin-bottom: 12px;
}

.form-label {
  display: block;
  font-size: 10px;
  color: var(--text-secondary);
  margin-bottom: 6px;
}

.form-input {
  width: 100%;
  height: 36px;
  padding: 0 10px;
  border: 2px solid var(--border-color);
  background: var(--bg-main);
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
  font-size: 10px;
  box-shadow: inset 2px 2px 0 var(--border-color);
  box-sizing: border-box;
}

.form-input:focus {
  outline: none;
  border-color: #4CAF50;
}

.form-textarea {
  width: 100%;
  padding: 10px;
  border: 2px solid var(--border-color);
  background: var(--bg-main);
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
  font-size: 9px;
  box-shadow: inset 2px 2px 0 var(--border-color);
  box-sizing: border-box;
  resize: vertical;
  margin-bottom: 10px;
}

.form-textarea:focus {
  outline: none;
  border-color: #4CAF50;
}

/* 扫描类型选项 */
.options-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.option-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  background: var(--bg-main);
  transition: all 0.2s;
}

.option-item.active {
  border-color: #4CAF50;
  background: rgba(76, 175, 80, 0.1);
}

.option-content {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.option-name {
  font-size: 10px;
  color: var(--text-primary);
}

.option-desc {
  font-size: 8px;
  color: var(--text-secondary);
}

/* 复选框列表 */
.checkbox-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.checkbox-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  cursor: pointer;
  font-size: 10px;
  color: var(--text-primary);
}

.checkbox-item:hover {
  background: var(--hover-color);
}

.param-name {
  flex: 1;
}

.param-value {
  color: var(--text-secondary);
  font-size: 9px;
}

/* 速度选项 */
.speed-options {
  display: flex;
  gap: 6px;
}

.speed-item {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  padding: 8px 4px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  background: var(--bg-main);
  font-size: 9px;
  color: var(--text-primary);
  transition: all 0.2s;
}

.speed-item.active {
  border-color: #2196F3;
  background: rgba(33, 150, 243, 0.1);
}

/* 命令预览 */
.command-preview {
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  padding: 12px;
  font-family: 'Courier New', monospace;
  font-size: 11px;
  word-break: break-all;
  box-shadow: inset 2px 2px 0 var(--border-color);
  line-height: 1.6;
}

.cmd-prefix {
  color: #4CAF50;
}

.cmd-args {
  color: #FF9800;
}

.cmd-target {
  color: #2196F3;
  margin-left: 8px;
}

/* 按钮 */
.btn-primary, .btn-secondary {
  font-family: 'Press Start 2P', monospace;
  font-size: 10px;
  padding: 10px 16px;
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
  background: var(--bg-card);
  color: var(--text-primary);
}

.btn-primary:hover, .btn-secondary:hover {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.full-width {
  width: 100%;
}

.scan-btn {
  padding: 14px !important;
  font-size: 12px !important;
}

/* 右侧面板 */
.right-panel {
  flex: 1;
  min-height: 400px;
}

.result-card {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 20px;
  box-shadow: 4px 4px 0 var(--border-color);
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 2px solid var(--border-color);
}

.result-header h3 {
  font-size: 14px;
  color: var(--text-primary);
  margin: 0;
}

.result-count {
  font-size: 10px;
  color: var(--text-secondary);
  padding: 4px 8px;
  background: var(--bg-main);
  border: 1px solid var(--border-color);
}

.result-header-right {
  display: flex;
  align-items: center;
  gap: 15px;
}

.btn-export {
  background: #4CAF50;
  color: white;
  border: 2px solid var(--border-color);
  padding: 6px 12px;
  font-size: 9px;
  cursor: pointer;
  font-family: 'Press Start 2P', monospace;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s ease;
}

.btn-export:hover {
  transform: translate(-1px, -1px);
  box-shadow: 4px 4px 0 var(--border-color);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 300px;
  background: var(--bg-card);
  border: 2px dashed var(--border-color);
  color: var(--text-secondary);
  font-size: 12px;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid var(--border-color);
  border-top-color: #4CAF50;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* 资产卡片 */
.cards-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
  max-height: 600px;
  overflow-y: auto;
  padding-right: 10px;
}

.asset-card {
  background: var(--bg-main);
  border: 2px solid var(--border-color);
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
}

.asset-card:hover {
  transform: translateY(-2px);
  box-shadow: 4px 5px 0 var(--border-color);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: var(--bg-secondary, var(--bg-card));
  border-bottom: 2px solid var(--border-color);
}

.card-header .card-title {
  font-size: 11px;
  color: var(--text-primary);
  border: none;
  padding: 0;
  margin: 0;
}

.card-port {
  font-size: 12px;
  padding: 4px 8px;
  border: 2px solid var(--border-color);
  font-weight: bold;
  color: var(--text-primary);
}

.card-content {
  padding: 12px 16px;
}

.info-row {
  margin-bottom: 8px;
  font-size: 10px;
  display: flex;
  gap: 8px;
}

.info-label {
  color: var(--text-secondary);
  white-space: nowrap;
}

.info-value {
  color: var(--text-primary);
  word-break: break-all;
}

.card-footer {
  padding: 10px 16px;
  border-top: 2px solid var(--border-color);
  font-size: 9px;
  color: var(--text-secondary);
}

/* 响应式 */
@media (max-width: 1200px) {
  .main-content {
    flex-direction: column;
  }
  .left-panel {
    width: 100%;
  }
}

@media (max-width: 768px) {
  .options-grid {
    grid-template-columns: 1fr;
  }
  .speed-options {
    flex-wrap: wrap;
  }
}
</style>
