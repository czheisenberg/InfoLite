<template>
  <div class="new-page-header">
    <!-- 顶部标题部分 -->
    <div class="header-top">
      <h1 class="page-title">InfoLite 网络资产扫描平台</h1>

      <div class="header-actions">
        <span class="user-info" v-if="username">
          {{ username }}
        </span>
        <button 
          class="btn-secondary nav-tab-btn nav-tab-subdomain" 
          @click="goToSubdomainScan"
          title="子域名扫描"
        >
          子域名
        </button>
        <button 
          class="btn-secondary nav-tab-btn" 
          @click="goToNmapScan"
          title="Nmap扫描"
        >
          Nmap 扫描
        </button>
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
          <label for="scanInput" class="form-label">扫描目标</label>
          <input
            id="scanInput"
            v-model="scanInput"
            type="text"
            class="form-input"
            placeholder='请输入扫描目标，如：ip="127.0.0.1" && port="1-100" 或 ip="127.0.0.1"'
            @keyup.enter="handleQuery"
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
              @click="handleQuery"
              :disabled="loading || !scanInput.trim()"
            >
              <span v-if="loading">扫描中...</span>
              <span v-else>查询</span>
            </button>
            <button 
              class="btn-secondary" 
              @click="handleRefresh" 
              :disabled="loading || !scanInput.trim()"
            >
              <span v-if="loading">刷新中...</span>
              <span v-else>扫描</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
// 引入Pixelium Design的Message组件
import { Message } from '@pixelium/web-vue/es'
const $message = Message

// 定义props
const props = defineProps({
  username: {
    type: String,
    default: ''
  },
  theme: {
    type: String,
    default: 'light'
  }
})

// 定义事件
const emit = defineEmits(['logout', 'toggle-theme', 'query', 'refresh'])

// 扫描输入
const scanInput = ref('')

// 扫描模式（nmap 或 socket）
const scanMode = ref('nmap')

// 加载状态
const loading = ref(false)

// 处理退出登录
const handleLogout = () => {
  emit('logout')
}

// 切换主题
const toggleTheme = () => {
  emit('toggle-theme')
}

// 跳转到Nmap扫描页面
const goToNmapScan = () => {
  window.location.href = '/nmap-scan'
}

// 跳转到子域名扫描页面
const goToSubdomainScan = () => {
  window.location.href = '/subdomain-scan'
}

// 解析输入格式
const parseScanInput = (input) => {
  const trimmedInput = input.trim()
  
  // 匹配 ip="xxx" && port="xxx" 格式
  const fullRegex = /^ip="([^"]+)"\s*&&\s*port="([^"]+)"$/i
  const fullMatch = trimmedInput.match(fullRegex)
  
  // 匹配只输入 ip="xxx" 格式
  const ipOnlyRegex = /^ip="([^"]+)"$/i
  const ipOnlyMatch = trimmedInput.match(ipOnlyRegex)
  
  if (fullMatch) {
    return {
      ip: fullMatch[1].trim(),
      portOption: 'custom',
      portRange: fullMatch[2].trim(),
      scanMode: scanMode.value
    }
  } else if (ipOnlyMatch) {
    return {
      ip: ipOnlyMatch[1].trim(),
      portOption: 'all',
      portRange: '1-65535',
      scanMode: scanMode.value
    }
  } else {
    // 非指定格式，返回空对象
    return null
  }
}

// 处理查询/扫描
const handleQuery = () => {
  if (!scanInput.value.trim()) {
    return
  }
  
  const scanParams = parseScanInput(scanInput.value)
  if (!scanParams) {
    // 输入格式不正确，提示用户
    $message['info']('请使用正确的输入格式：ip="127.0.0.1" && port="1-100" 或 ip="127.0.0.1"')
    return
  }
  
  loading.value = true
  emit('query', scanParams, () => {
    loading.value = false
  })
}

// 处理刷新扫描
const handleRefresh = () => {
  if (!scanInput.value.trim()) {
    return
  }
  
  const scanParams = parseScanInput(scanInput.value)
  if (!scanParams) {
    // 输入格式不正确，提示用户
    $message['info']('请使用正确的输入格式：ip="127.0.0.1" && port="1-100" 或 ip="127.0.0.1"')
    return
  }
  
  loading.value = true
  emit('refresh', scanParams, () => {
    loading.value = false
  })
}

// 监听回车键
const handleKeyup = (event) => {
  if (event.key === 'Enter') {
    handleQuery()
  }
}
</script>

<style scoped>
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
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.header-top .page-title {
  font-size: 24px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

/* 头部表单部分 */
.header-form {
  margin-top: 10px;
}

.form-container {
  background: var(--bg-card);
  border: 2px solid var(--border-color);
  padding: 20px;
  box-shadow: 5px 5px 0 var(--border-color);
}

.form-row {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 15px;
  flex-wrap: wrap;
}

.form-label {
  font-size: 14px;
  color: var(--text-primary);
  white-space: nowrap;
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.form-input {
  width: 100%;
  height: 3rem;
  border: 2px solid var(--border-color);
  border-radius: 4px;
  background-color: var(--bg-input);
  color: var(--text-primary);
  font-size: 14px;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.form-input:focus {
  outline: none;
  border-color: var(--accent-color);
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-buttons {
  display: flex;
  gap: 10px;
  width: 100%;
  margin-top: 10px;
}

/* 扫描模式选择 */
.scan-mode-row {
  display: flex;
  align-items: center;
  gap: 15px;
  width: 100%;
}

.mode-options {
  display: flex;
  gap: 20px;
}

.mode-option {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.mode-option input[type="radio"] {
  cursor: pointer;
  accent-color: #4CAF50;
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

/* 按钮样式 */
.btn-primary, .btn-secondary, .btn-text {
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
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

.nav-tab-btn {
  background: #FF9800 !important;
}

.nav-tab-subdomain {
  background: #9C27B0 !important;
}

/* 响应式适配 */
@media (max-width: 768px) {
  .new-page-header {
    padding: 10px;
  }
  .header-top {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
    text-align: left;
  }
  .header-top .header-actions {
    align-self: flex-end;
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
}
</style>