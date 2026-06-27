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
  </div>
</template>

<script setup>
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
const emit = defineEmits(['logout', 'toggle-theme'])

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
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

/* 新的页面头部 */
.new-page-header {
  background: var(--bg-main);
  border-bottom: 3px solid var(--border-color);
  padding: 15px 20px;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 100;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

/* 头部顶部（标题和操作按钮） */
.header-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1400px;
  margin: 0 auto;
}

.header-top .header-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.header-top .user-info {
  font-size: 12px;
  color: var(--text-primary);
  padding: 6px 10px;
  background-color: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: 4px;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.header-top .page-title {
  font-size: 18px;
  color: var(--text-primary);
  margin: 0;
  text-shadow: 2px 2px 0 var(--border-color);
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

/* 主题切换按钮：像素风格 */
.theme-toggle-btn {
  font-size: 20px;
  background: var(--bg-card);
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

.theme-toggle-btn:active {
  transform: translate(2px, 2px);
  box-shadow: 1px 1px 0 var(--border-color);
}

/* 按钮样式 */
.btn-primary, .btn-secondary, .btn-text {
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
  font-size: 10px;
  padding: 6px 10px;
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
}
</style>
