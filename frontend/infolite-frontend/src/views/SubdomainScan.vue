<template>
  <div class="subdomain-scan-page">
    <PageHeader 
      :username="username"
      :theme="theme"
      @logout="handleLogout"
      @toggle-theme="toggleTheme"
    />

    <div class="main-content">
      <div class="left-panel">
        <div class="config-card">
          <div class="card-title">🎯 目标设置</div>
          <div class="form-group">
            <label class="form-label">目标域名</label>
            <input v-model="targetDomain" type="text" class="form-input" placeholder="如：example.com" />
          </div>
        </div>

        <div class="config-card">
          <div class="card-title">🔍 扫描方式</div>
          <div class="checkbox-list">
            <label v-for="opt in scanSourceOptions" :key="opt.value" class="checkbox-item source-item" :class="{ active: scanSources.includes(opt.value) }">
              <input type="checkbox" v-model="scanSources" :value="opt.value" />
              <div class="source-content">
                <span class="source-name">{{ opt.name }}</span>
                <span class="source-desc">{{ opt.desc }}</span>
              </div>
            </label>
          </div>
          <div class="dict-toggle">
            <label class="checkbox-item">
              <input type="checkbox" v-model="enableDict" />
              <span class="param-name">启用字典爆破</span>
            </label>
          </div>
        </div>

        <div v-if="enableDict" class="config-card">
          <div class="card-title">⚡ 爆破配置</div>
          <div class="form-group">
            <label class="form-label">并发线程数</label>
            <div class="speed-options">
              <label v-for="speed in workerOptions" :key="speed.value" class="speed-item" :class="{ active: maxWorkers === speed.value }">
                <input type="radio" v-model="maxWorkers" :value="speed.value" />
                <span>{{ speed.name }}</span>
              </label>
            </div>
          </div>
        </div>

        <div class="config-card">
          <div class="card-title">📊 扫描说明</div>
          <div class="info-text">
            <p>• <strong>crt.sh</strong>：证书透明度日志，速度快，被动扫描</p>
            <p>• <strong>chaziyu</strong>：查子域名网站，数据量大</p>
            <p>• <strong>字典爆破</strong>：主动 DNS 解析，常见子域名</p>
            <p>• 可多选组合，结果自动去重合并</p>
          </div>
        </div>

        <div class="action-buttons">
          <button class="btn-primary query-btn" @click="handleQuery" :disabled="scanning || !targetDomain">
            <span v-if="scanning && scanMode === 'query'">⏳ 查询中...</span>
            <span v-else>🔍 查询</span>
          </button>
          <button class="btn-secondary refresh-btn" @click="handleRefresh" :disabled="scanning || !targetDomain">
            <span v-if="scanning && scanMode === 'refresh'">⏳ 扫描中...</span>
            <span v-else>🔄 扫描</span>
          </button>
        </div>
      </div>

      <div class="right-panel">
        <div v-if="scanResult && scanResult.results && scanResult.results.length > 0" class="result-card">
          <div class="result-header">
            <h3>扫描结果
              <span v-if="fromCache" class="cache-badge">缓存</span>
              <span v-else class="live-badge">实时</span>
            </h3>
            <div class="result-header-right">
              <div class="result-stats">
                <span class="stat-item">总数: {{ scanResult.total }}</span>
                <span class="stat-item alive">存活: {{ scanResult.alive_count }}</span>
                <span class="stat-item">耗时: {{ scanResult.cost_time }}s</span>
              </div>
              <button class="btn-export" @click="handleExport">导出Excel</button>
            </div>
          </div>

          <div class="filter-bar">
            <label class="filter-item">
              <input type="checkbox" v-model="filterAlive" />
              <span>仅显示存活</span>
            </label>
          </div>

          <div class="result-table-wrap">
            <table class="result-table">
              <thead>
                <tr>
                  <th class="col-domain">子域名</th>
                  <th class="col-ip">IP 地址</th>
                  <th class="col-source">来源</th>
                  <th class="col-status">状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(item, index) in filteredResults" :key="index" class="result-row">
                  <td class="col-domain">
                    <span class="domain-text">{{ item.domain }}</span>
                  </td>
                  <td class="col-ip">
                    <span v-if="item.ips && item.ips.length > 0">{{ item.ips.join(', ') }}</span>
                    <span v-else class="muted">-</span>
                  </td>
                  <td class="col-source">
                    <div class="source-tags">
                      <span v-if="item.source.includes('crtsh')" class="tag tag-crtsh">crt.sh</span>
                      <span v-if="item.source.includes('chaziyu')" class="tag tag-chaziyu">查子域</span>
                      <span v-if="item.source.includes('dict')" class="tag tag-dict">字典</span>
                    </div>
                  </td>
                  <td class="col-status">
                    <span v-if="item.status === 'alive'" class="status-alive">● 存活</span>
                    <span v-else class="status-unknown">○ 未知</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div v-else-if="scanning" class="empty-state">
          <div class="loading-spinner"></div>
          <p>正在扫描子域名，请稍候...</p>
        </div>

        <div v-else class="empty-state">
          <p class="empty-icon">🌐</p>
          <p>输入目标域名，开始子域名扫描</p>
        </div>
      </div>
    </div>

    <PageFooter />
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import PageFooter from '../components/PageFooter.vue'
import { scanSubdomain } from '../api/subdomain'
import * as XLSX from 'xlsx'
import { Message } from '@pixelium/web-vue/es'
const $message = Message

const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

const username = ref(localStorage.getItem('username') || '')

const targetDomain = ref('')
const scanSources = ref(['crtsh', 'chaziyu'])
const enableDict = ref(true)
const maxWorkers = ref(50)
const scanning = ref(false)
const scanResult = ref(null)
const filterAlive = ref(false)
const fromCache = ref(false)
const scanMode = ref('')

const scanSourceOptions = [
  { name: 'crt.sh 查询', value: 'crtsh', desc: '证书透明度日志，速度快' },
  { name: 'chaziyu 查询', value: 'chaziyu', desc: '查子域名网站，数据量大' }
]

const workerOptions = [
  { name: '20', value: 20 },
  { name: '50', value: 50 },
  { name: '100', value: 100 },
  { name: '200', value: 200 }
]

const getScanType = () => {
  const hasCrtsh = scanSources.value.includes('crtsh')
  const hasChaziyu = scanSources.value.includes('chaziyu')
  const hasDict = enableDict.value
  
  if (hasCrtsh && hasChaziyu && hasDict) return 'all'
  if (hasCrtsh && hasChaziyu && !hasDict) return 'crtsh,chaziyu'
  if (hasCrtsh && !hasChaziyu && hasDict) return 'crtsh,dict'
  if (!hasCrtsh && hasChaziyu && hasDict) return 'chaziyu,dict'
  if (hasCrtsh) return 'crtsh'
  if (hasChaziyu) return 'chaziyu'
  if (hasDict) return 'dict'
  return ''
}

const filteredResults = computed(() => {
  if (!scanResult.value || !scanResult.value.results) return []
  if (filterAlive.value) {
    return scanResult.value.results.filter(r => r.status === 'alive')
  }
  return scanResult.value.results
})

const validateDomain = (domain) => {
  const reg = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/
  return reg.test(domain)
}

const doScan = async (refresh) => {
  if (!targetDomain.value) {
    $message['info']('请输入目标域名')
    return
  }
  if (!validateDomain(targetDomain.value)) {
    $message['info']('请输入正确的域名格式')
    return
  }
  const scanType = getScanType()
  if (!scanType) {
    $message['info']('请至少选择一种扫描方式')
    return
  }

  scanMode.value = refresh ? 'refresh' : 'query'
  scanning.value = true
  scanResult.value = null

  try {
    const res = await scanSubdomain({
      domain: targetDomain.value,
      scan_type: scanType,
      max_workers: maxWorkers.value,
      refresh: refresh
    })
    if (res.code === 200 && res.data) {
      scanResult.value = res.data
      fromCache.value = res.from_cache === true
      const modeText = fromCache.value ? '缓存查询' : '实时扫描'
      $message['success'](`${modeText}完成，发现 ${res.data.total} 个子域名，存活 ${res.data.alive_count} 个`)
    } else {
      $message['error'](res.msg || '查询失败')
    }
  } catch (error) {
    console.error('查询失败：', error)
    const errorMsg = error.response?.data?.msg || '查询失败'
    $message['error'](errorMsg)
  } finally {
    scanning.value = false
    scanMode.value = ''
  }
}

const handleQuery = () => {
  doScan(false)
}

const handleRefresh = () => {
  doScan(true)
}

const handleLogout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  window.location.href = '/login'
}

const goToAssetScan = () => {
  window.location.href = '/'
}

const goToNmapScan = () => {
  window.location.href = '/nmap-scan'
}

const handleExport = () => {
  if (!scanResult.value || !scanResult.value.results || scanResult.value.results.length === 0) {
    $message['info']('没有可导出的数据')
    return
  }
  const exportData = scanResult.value.results.map(item => ({
    '子域名': item.domain,
    'IP地址': item.ips && item.ips.length > 0 ? item.ips.join(', ') : '',
    '来源': item.source || '',
    '状态': item.status || ''
  }))
  const ws = XLSX.utils.json_to_sheet(exportData)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, '子域名扫描结果')
  XLSX.writeFile(wb, `子域名_${targetDomain.value}_${Date.now()}.xlsx`)
  $message['success']('导出成功')
}
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

.subdomain-scan-page {
  min-height: 100vh;
  background-color: var(--bg-main);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
  padding-top: 80px;
  display: flex;
  flex-direction: column;
}

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

.left-panel {
  width: 360px;
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
  border-color: #9C27B0;
}

.checkbox-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.source-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  background: var(--bg-main);
  transition: all 0.2s;
}

.source-item.active {
  border-color: #9C27B0;
  background: rgba(156, 39, 176, 0.1);
}

.source-content {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.source-name {
  font-size: 10px;
  color: var(--text-primary);
}

.source-desc {
  font-size: 11px;
  color: var(--text-secondary);
}

.dict-toggle {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--border-color);
}

.dict-toggle .checkbox-item {
  padding: 0;
}

.action-buttons {
  display: flex;
  gap: 10px;
}

.action-buttons .btn-primary,
.action-buttons .btn-secondary {
  flex: 1;
  padding: 12px !important;
  font-size: 11px !important;
}

.query-btn {
  background: #9C27B0;
  color: white;
  border: 2px solid var(--border-color);
  box-shadow: 3px 3px 0 var(--border-color);
  font-family: 'Press Start 2P', monospace;
  cursor: pointer;
  transition: all 0.2s;
}

.query-btn:hover:not(:disabled) {
  transform: translate(1px, 1px);
  box-shadow: 2px 2px 0 var(--border-color);
}

.refresh-btn {
  background: #FF9800 !important;
  color: white !important;
}

.cache-badge {
  display: inline-block;
  margin-left: 10px;
  padding: 3px 8px;
  font-size: 11px;
  background: #2196F3;
  color: white;
  border: 2px solid var(--border-color);
}

.live-badge {
  display: inline-block;
  margin-left: 10px;
  padding: 3px 8px;
  font-size: 11px;
  background: #4CAF50;
  color: white;
  border: 2px solid var(--border-color);
}

.options-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.option-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  background: var(--bg-main);
  transition: all 0.2s;
}

.option-item.active {
  border-color: #9C27B0;
  background: rgba(156, 39, 176, 0.1);
}

.option-content {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.option-name {
  font-size: 10px;
  color: var(--text-primary);
}

.option-desc {
  font-size: 11px;
  color: var(--text-secondary);
}

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
  font-size: 11px;
  color: var(--text-primary);
  transition: all 0.2s;
}

.speed-item.active {
  border-color: #FF9800;
  background: rgba(255, 152, 0, 0.1);
}

.info-text {
  font-size: 11px;
  line-height: 2;
  color: var(--text-secondary);
}

.info-text p {
  margin: 4px 0;
}

.btn-primary {
  font-family: 'Press Start 2P', monospace;
  font-size: 10px;
  padding: 10px 16px;
  border: 2px solid var(--border-color);
  cursor: pointer;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s;
  background: #9C27B0;
  color: white;
}

.btn-primary:hover {
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
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 2px solid var(--border-color);
}

.result-header h3 {
  font-size: 14px;
  color: var(--text-primary);
  margin: 0;
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
  font-size: 11px;
  cursor: pointer;
  font-family: 'Press Start 2P', monospace;
  box-shadow: 3px 3px 0 var(--border-color);
  transition: all 0.2s ease;
}

.btn-export:hover {
  transform: translate(-1px, -1px);
  box-shadow: 4px 4px 0 var(--border-color);
}

.result-stats {
  display: flex;
  gap: 10px;
}

.stat-item {
  font-size: 11px;
  padding: 4px 8px;
  border: 1px solid var(--border-color);
  background: var(--bg-main);
  color: var(--text-secondary);
}

.stat-item.alive {
  color: #4CAF50;
  border-color: #4CAF50;
}

.filter-bar {
  margin-bottom: 12px;
}

.filter-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 10px;
  color: var(--text-primary);
  cursor: pointer;
}

.result-table-wrap {
  max-height: 550px;
  overflow-y: auto;
  border: 2px solid var(--border-color);
}

.result-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 10px;
}

.result-table th {
  position: sticky;
  top: 0;
  background: var(--bg-main);
  text-align: left;
  padding: 10px 12px;
  border-bottom: 2px solid var(--border-color);
  color: var(--text-primary);
  font-size: 10px;
}

.result-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-primary);
}

.result-row:hover {
  background: var(--hover-color);
}

.col-domain {
  min-width: 200px;
}

.col-ip {
  min-width: 180px;
}

.col-source {
  width: 100px;
}

.col-status {
  width: 100px;
}

.domain-text {
  font-family: 'Courier New', monospace;
  font-size: 11px;
}

.tag {
  display: inline-block;
  padding: 3px 8px;
  font-size: 11px;
  border: 1px solid;
}

.tag-crtsh {
  color: #2196F3;
  border-color: #2196F3;
}

.tag-chaziyu {
  color: #E91E63;
  border-color: #E91E63;
}

.tag-dict {
  color: #FF9800;
  border-color: #FF9800;
}

.tag-all {
  color: #9C27B0;
  border-color: #9C27B0;
}

.source-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.status-alive {
  color: #4CAF50;
  font-size: 11px;
}

.status-unknown {
  color: var(--text-secondary);
  font-size: 11px;
}

.muted {
  color: var(--text-secondary);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 400px;
  background: var(--bg-card);
  border: 2px dashed var(--border-color);
  color: var(--text-secondary);
  font-size: 12px;
}

.empty-icon {
  font-size: 64px;
  margin-bottom: 16px;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid var(--border-color);
  border-top-color: #9C27B0;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

@media (max-width: 1200px) {
  .main-content {
    flex-direction: column;
  }
  .left-panel {
    width: 100%;
  }
}

@media (max-width: 768px) {
  .speed-options {
    flex-wrap: wrap;
  }
  .result-table-wrap {
    overflow-x: auto;
  }
  .result-table {
    min-width: 600px;
  }
}
</style>
