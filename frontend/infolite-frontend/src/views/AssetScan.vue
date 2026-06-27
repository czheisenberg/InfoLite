<template>
  <div class="asset-scan-page">
    <PageHeader 
      :username="username"
      :theme="theme"
      @logout="handleLogout"
      @toggle-theme="toggleTheme"
    />

    <div class="page-body">
      <!-- 扫描表单 -->
      <div class="scan-form-section">
        <div class="form-container">
          <div class="form-row">
            <label for="scanInput" class="form-label">扫描目标</label>
            <input
              id="scanInput"
              v-model="scanInput"
              type="text"
              class="form-input"
              placeholder='请输入扫描目标，如：ip="127.0.0.1" 或 domain="example.com"'
              @keyup.enter="doQuery"
            />
            
            <!-- 扫描模式选择 -->
            <div class="scan-mode-row">
              <span class="form-label">扫描引擎</span>
              <div class="mode-options">
                <label class="mode-option">
                  <input type="radio" v-model="scanMode" value="nmap" />
                  <span>Nmap 引擎（推荐）</span>
                </label>
                <label class="mode-option">
                  <input type="radio" v-model="scanMode" value="socket" />
                  <span>Socket 引擎</span>
                </label>
              </div>
            </div>

            <div class="form-buttons">
              <button 
                class="btn-primary" 
                @click="doQuery"
                :disabled="loading || !scanInput.trim()"
              >
                <span v-if="loading">扫描中...</span>
                <span v-else>查询</span>
              </button>
              <button 
                class="btn-secondary" 
                @click="doRefresh" 
                :disabled="loading || !scanInput.trim()"
              >
                <span v-if="loading">刷新中...</span>
                <span v-else>扫描</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 功能卡片区域 -->
      <div class="features-section" v-if="!hasResult">
        <div class="section-header">
          <h2 class="section-title">核心功能</h2>
          <p class="section-subtitle">四大核心模块，覆盖网络测绘关键能力</p>
        </div>
        <div class="feature-cards">
          <div class="feature-card feature-asset" @click="scrollToSearch">
            <div class="feature-icon">🔍</div>
            <h3 class="feature-title">资产扫描</h3>
            <p class="feature-desc">端口探测 + 指纹识别，快速发现目标资产</p>
            <div class="feature-tags">
              <span class="feature-tag">Nmap引擎</span>
              <span class="feature-tag">Socket引擎</span>
            </div>
          </div>
          <div class="feature-card feature-nmap" @click="goToNmapScan">
            <div class="feature-icon">⚡</div>
            <h3 class="feature-title">Nmap 扫描</h3>
            <p class="feature-desc">自定义参数，灵活调用成熟扫描工具</p>
            <div class="feature-tags">
              <span class="feature-tag">自定义参数</span>
              <span class="feature-tag">版本探测</span>
            </div>
          </div>
          <div class="feature-card feature-subdomain" @click="goToSubdomainScan">
            <div class="feature-icon">🌐</div>
            <h3 class="feature-title">子域名扫描</h3>
            <p class="feature-desc">多源聚合 + 字典爆破，全面发现子域名</p>
            <div class="feature-tags">
              <span class="feature-tag">crt.sh</span>
              <span class="feature-tag">chaziyu</span>
            </div>
          </div>
          <div class="feature-card feature-dirsearch" @click="goToDirsearchScan">
            <div class="feature-icon">🔎</div>
            <h3 class="feature-title">Dirsearch 扫描</h3>
            <p class="feature-desc">Web 目录发现，快速定位敏感路径</p>
            <div class="feature-tags">
              <span class="feature-tag">路径爆破</span>
              <span class="feature-tag">多扩展名</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 扫描结果 -->
      <div class="scan-result-card" v-if="hasResult">
        <div class="result-container">
          <div class="result-header">
            <div class="result-header-left">
              <h3>
                扫描结果
                <span class="tag" :class="{ 'tag-info': scanType === 'db_query', 'tag-primary': scanType !== 'db_query' }">
                    {{ scanType === 'db_query' ? '从数据库查询' : '实时扫描结果' }}
                  </span>
              </h3>
              <p>共检测到 {{ tableData.length }} 个开放端口/资产</p>
            </div>
            <button class="btn-export" @click="handleExport">
              📊 导出 Excel
            </button>
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
              <div class="card-info-container">
                <!-- 左侧基本信息 -->
                <div class="card-info-left">
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
                  
                  <!-- 服务名称（Nmap） -->
                  <div class="info-row" v-if="row.service_name">
                    <span class="info-label">服务名称：</span>
                    <span class="info-value">{{ row.service_name }}</span>
                  </div>
                  
                  <!-- 产品版本（Nmap） -->
                  <div class="info-row" v-if="row.product">
                    <span class="info-label">产品版本：</span>
                    <span class="info-value">{{ row.product }} {{ row.version || '' }}</span>
                  </div>
                  
                  <!-- HTTP状态码 -->
                  <div class="info-row" v-if="row.http_info">
                    <span class="info-label">HTTP状态码：</span>
                    <span class="info-value">{{ row.http_info.status_code }}</span>
                  </div>
                </div>
                
                <!-- 右侧响应头信息 -->
                <div class="card-info-right" v-if="hasCardHeaders(row)">
                  <div class="headers-section">
                    <div class="headers-tab">Header</div>
                    <pre class="headers-content">{{ getCardHeaders(row) }}</pre>
                  </div>
                </div>
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
          <!-- 服务名称（Nmap） -->
          <div class="detail-item" v-if="currentAsset.service_name">
            <span class="detail-label">服务名称：</span>
            <span class="detail-value">{{ currentAsset.service_name }}</span>
          </div>
          <!-- 产品版本（Nmap） -->
          <div class="detail-item" v-if="currentAsset.product">
            <span class="detail-label">产品版本：</span>
            <span class="detail-value">{{ currentAsset.product }} {{ currentAsset.version || '' }}</span>
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
    <!-- 页面底部 -->
    <PageFooter />
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
// 引入组件
import PageHeader from '../components/PageHeader.vue'
import PageFooter from '../components/PageFooter.vue'
// 引入封装的API接口
import { queryAsset, getAssetDetail, getAssetList } from '../api/asset'
import * as XLSX from 'xlsx'
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

const goToNmapScan = () => {
  window.location.href = '/nmap-scan'
}

const goToSubdomainScan = () => {
  window.location.href = '/subdomain-scan'
}

const goToDirsearchScan = () => {
  window.location.href = '/dirsearch-scan'
}

const scrollToSearch = () => {
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

// 扫描输入
const scanInput = ref('')
// 扫描模式（nmap 或 socket）
const scanMode = ref('nmap')
// 加载状态
const loading = ref(false)

// 解析输入格式
const parseScanInput = (input) => {
  const trimmedInput = input.trim()
  
  // 匹配 ip="xxx" && port="xxx" 格式
  const fullIpRegex = /^ip="([^"]+)"\s*&&\s*port="([^"]+)"$/i
  const fullIpMatch = trimmedInput.match(fullIpRegex)
  
  // 匹配只输入 ip="xxx" 格式
  const ipOnlyRegex = /^ip="([^"]+)"$/i
  const ipOnlyMatch = trimmedInput.match(ipOnlyRegex)
  
  // 匹配 domain="xxx" && port="xxx" 格式（域名+端口）
  const fullDomainRegex = /^domain="([^"]+)"\s*&&\s*port="([^"]+)"$/i
  const fullDomainMatch = trimmedInput.match(fullDomainRegex)
  
  // 匹配只输入 domain="xxx" 格式（域名）
  const domainOnlyRegex = /^domain="([^"]+)"$/i
  const domainOnlyMatch = trimmedInput.match(domainOnlyRegex)
  
  if (fullIpMatch) {
    return {
      target: fullIpMatch[1].trim(),
      targetType: 'ip',
      portOption: 'custom',
      portRange: fullIpMatch[2].trim(),
      scanMode: scanMode.value
    }
  } else if (ipOnlyMatch) {
    return {
      target: ipOnlyMatch[1].trim(),
      targetType: 'ip',
      portOption: 'all',
      portRange: '1-65535',
      scanMode: scanMode.value
    }
  } else if (fullDomainMatch) {
    return {
      target: fullDomainMatch[1].trim(),
      targetType: 'domain',
      portOption: 'custom',
      portRange: fullDomainMatch[2].trim(),
      scanMode: scanMode.value
    }
  } else if (domainOnlyMatch) {
    return {
      target: domainOnlyMatch[1].trim(),
      targetType: 'domain',
      portOption: 'all',
      portRange: '1-65535',
      scanMode: scanMode.value
    }
  } else {
    return null
  }
}

// 执行查询
const doQuery = () => {
  if (!scanInput.value.trim()) {
    return
  }
  
  const scanParams = parseScanInput(scanInput.value)
  if (!scanParams) {
    $message['info']('请使用正确的输入格式：ip="127.0.0.1" 或 domain="example.com"')
    return
  }
  
  loading.value = true
  handleQuery(scanParams, () => {
    loading.value = false
  })
}

// 执行刷新扫描
const doRefresh = () => {
  if (!scanInput.value.trim()) {
    return
  }
  
  const scanParams = parseScanInput(scanInput.value)
  if (!scanParams) {
    $message['info']('请使用正确的输入格式：ip="127.0.0.1" 或 domain="example.com"')
    return
  }
  
  loading.value = true
  handleRefresh(scanParams, () => {
    loading.value = false
  })
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



// 目标格式校验（支持IP或域名）
const validateTarget = (target, targetType) => {
  if (targetType === 'ip') {
    // IP格式校验
    const reg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
    return reg.test(target)
  } else if (targetType === 'domain') {
    // 域名格式校验
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
    return domainRegex.test(target)
  }
  return false
}

// 处理查询/扫描（默认不刷新）
const handleQuery = async (scanParams, callback) => {
  const { target, targetType, portOption, portRange, scanMode } = scanParams
  
  // 目标校验
  if (!target) {
    $message['info']('请输入目标')
    if (callback) callback()
    return
  }
  if (!validateTarget(target, targetType)) {
    if (targetType === 'ip') {
      $message['info']('请输入正确的IP地址（如127.0.0.1）')
    } else {
      $message['info']('请输入正确的域名（如example.com）')
    }
    if (callback) callback()
    return
  }

  try {
    console.log('调用API:', { target, targetType, portOption, portRange, scanMode })
    // 调用后端接口，refresh=false（默认不刷新）
    const res = await queryAsset({ 
      target: target,
      target_type: targetType,
      port_option: portOption,
      port_range: portRange,
      scan_mode: scanMode
    })
    console.log('API返回:', res)
    if (res.code === 200) {
      tableData.value = res.data
      scanType.value = res.scan_type
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
  } finally {
    if (callback) callback()
  }
}

// 处理刷新扫描（强制重新扫描）
const handleRefresh = async (scanParams, callback) => {
  const { target, targetType, portOption, portRange, scanMode } = scanParams
  
  if (!target) {
    $message['info']('请输入目标')
    if (callback) callback()
    return
  }
  
  if (!validateTarget(target, targetType)) {
    if (targetType === 'ip') {
      $message['info']('请输入正确的IP地址（如127.0.0.1）')
    } else {
      $message['info']('请输入正确的域名（如example.com）')
    }
    if (callback) callback()
    return
  }

  try {
    // 调用后端接口，refresh=true（强制刷新）
    const res = await queryAsset({ 
      target: target,
      target_type: targetType,
      refresh: true,
      port_option: portOption,
      port_range: portRange,
      scan_mode: scanMode
    })
    if (res.code === 200) {
      tableData.value = res.data
      scanType.value = res.scan_type
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
  } finally {
    if (callback) callback()
  }
}

// 查看资产详情
const showDetail = (row) => {
  currentAsset.value = row
  detailDialogVisible.value = true
}

// 导出Excel
const handleExport = () => {
  if (tableData.value.length === 0) {
    $message['info']('没有可导出的数据')
    return
  }
  const exportData = tableData.value.map(row => ({
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
  XLSX.utils.book_append_sheet(wb, ws, '资产扫描结果')
  const ip = tableData.value[0]?.ip || 'asset'
  XLSX.writeFile(wb, `资产扫描_${ip}_${Date.now()}.xlsx`)
  $message['success']('导出成功')
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
  margin: 0 auto;
  padding: 20px;
  background-color: var(--bg-main);
  min-height: 100vh;
  font-family: 'Press Start 2P', monospace;
  padding-top: 80px;
  display: flex;
  flex-direction: column;
}

.page-body {
  flex: 1;
}

/* 扫描表单区域 */
.scan-form-section {
  max-width: 900px;
  margin: 0 auto 30px;
}

.scan-form-section .form-container {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 24px;
  box-shadow: 6px 6px 0 var(--border-color);
}

.scan-form-section .form-row {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 15px;
}

.scan-form-section .form-label {
  font-size: 12px;
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
}

.scan-form-section .form-input {
  width: 100%;
  height: 44px;
  padding: 0 12px;
  border: 2px solid var(--border-color);
  background-color: var(--bg-main);
  color: var(--text-primary);
  font-size: 12px;
  box-sizing: border-box;
  font-family: 'Press Start 2P', monospace;
  box-shadow: inset 2px 2px 0 var(--border-color);
}

.scan-form-section .form-input:focus {
  outline: none;
  border-color: #4CAF50;
}

.scan-form-section .scan-mode-row {
  display: flex;
  align-items: center;
  gap: 15px;
  width: 100%;
}

.scan-form-section .mode-options {
  display: flex;
  gap: 20px;
}

.scan-form-section .mode-option {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 11px;
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
}

.scan-form-section .mode-option input[type="radio"] {
  cursor: pointer;
  accent-color: #4CAF50;
}

.scan-form-section .form-buttons {
  display: flex;
  gap: 12px;
  width: 100%;
  margin-top: 5px;
}

.scan-form-section .form-buttons button {
  flex: 1;
  padding: 12px 20px;
  font-size: 12px;
}

/* 功能卡片区域 */
.features-section {
  padding: 20px 0 40px;
}

.section-header {
  text-align: center;
  margin-bottom: 40px;
}

.section-title {
  font-size: 20px;
  color: var(--text-primary);
  margin: 0 0 12px 0;
  text-shadow: 2px 2px 0 var(--border-color);
}

.section-subtitle {
  font-size: 11px;
  color: var(--text-secondary);
  margin: 0;
}

.feature-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  max-width: 1400px;
  margin: 0 auto;
}

.feature-card {
  background: var(--bg-card);
  border: 3px solid var(--border-color);
  padding: 32px 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s ease;
  box-shadow: 6px 6px 0 var(--border-color);
  position: relative;
  overflow: hidden;
}

.feature-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 4px;
  transition: left 0.3s ease;
}

.feature-card.feature-asset::before {
  background: #4CAF50;
}

.feature-card.feature-nmap::before {
  background: #FF9800;
}

.feature-card.feature-subdomain::before {
  background: #9C27B0;
}

.feature-card.feature-dirsearch::before {
  background: #00BCD4;
}

.feature-card:hover {
  transform: translate(-4px, -4px);
  box-shadow: 10px 10px 0 var(--border-color);
}

.feature-card:hover::before {
  left: 0;
}

.feature-icon {
  font-size: 48px;
  margin-bottom: 20px;
  line-height: 1;
}

.feature-title {
  font-size: 15px;
  color: var(--text-primary);
  margin: 0 0 12px 0;
}

.feature-desc {
  font-size: 10px;
  line-height: 1.8;
  color: var(--text-secondary);
  margin: 0 0 20px 0;
}

.feature-tags {
  display: flex;
  justify-content: center;
  gap: 8px;
  flex-wrap: wrap;
}

.feature-tag {
  font-size: 11px;
  padding: 4px 10px;
  border: 1px solid var(--border-color);
  color: var(--text-secondary);
  background: var(--bg-main);
}



/* 扫描结果 */
.scan-result-card {
  margin-top: 30px;
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

.result-header-left {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.result-header-left p {
  font-size: 11px;
  color: var(--text-secondary);
  margin: 0;
}

.btn-export {
  background: linear-gradient(135deg, #4CAF50, #2E7D32);
  color: white;
  border: 3px solid var(--border-color);
  padding: 12px 20px;
  font-size: 11px;
  cursor: pointer;
  font-family: 'Press Start 2P', monospace;
  box-shadow: 4px 4px 0 var(--border-color);
  transition: all 0.2s ease;
}

.btn-export:hover {
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 var(--border-color);
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
  font-family: 'Press Start 2P', monospace;
}

.card-port {
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 4px 8px;
  border: 2px solid var(--border-color);
  border-radius: 4px;
  font-size: 14px;
  font-weight: bold;
  font-family: 'Press Start 2P', monospace;
}

/* 卡片内容 */
.card-content {
  padding: 16px;
}

/* 卡片信息容器（水平布局） */
.card-info-container {
  display: flex;
  gap: 20px;
  align-items: flex-start;
}

/* 左侧基本信息 */
.card-info-left {
  flex: 1;
  min-width: 0;
}

/* 右侧响应头信息 */
.card-info-right {
  flex: 1;
  min-width: 0;
  max-width: 50%;
}

/* 信息行 */
.info-row {
  margin-bottom: 10px;
  font-size: 14px;
}

.info-label {
  color: var(--text-secondary);
  margin-right: 8px;
  font-family: 'Press Start 2P', monospace;
}

.info-value {
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
}

/* 响应头部分 */
.headers-section {
  border: 2px solid var(--border-color);
  border-radius: 4px;
  overflow: hidden;
}

.headers-tab {
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 8px 16px;
  font-weight: bold;
  font-size: 14px;
  border-bottom: 2px solid var(--border-color);
  font-family: 'Press Start 2P', monospace;
}

.headers-content {
  background: var(--bg-main);
  padding: 12px;
  margin: 0;
  font-family: 'Press Start 2P', monospace;
  font-size: 10px;
  line-height: 1.4;
  color: var(--text-primary);
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 300px;
  overflow-y: auto;
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
  font-family: 'Press Start 2P', monospace;
}

/* 响应式适配 */
@media (max-width: 1024px) {
  .feature-cards {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .asset-scan-page {
    padding-top: 70px;
  }
  .scan-form-section .form-container {
    padding: 16px;
  }
  .scan-form-section .scan-mode-row {
    flex-direction: column;
    align-items: flex-start;
  }
  .scan-form-section .form-buttons {
    flex-direction: column;
  }
  .feature-cards {
    grid-template-columns: 1fr;
  }
  .section-title {
    font-size: 16px;
  }
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