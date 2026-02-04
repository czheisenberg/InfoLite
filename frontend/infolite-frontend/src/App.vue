<template>
  <router-view />
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'

// 定义主题状态：light（亮色）/ dark（暗色），默认亮色
const theme = ref('light')

onMounted(() => {
  // 优先读取本地存储，无则检测系统主题
  const savedTheme = localStorage.getItem('infolite-theme')
  if (savedTheme) {
    theme.value = savedTheme
  } else {
    const isSystemDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    theme.value = isSystemDark ? 'dark' : 'light'
  }
  document.documentElement.className = theme.value
})

// 监听主题变化：同步到HTML根节点 + 保存到本地存储
watch(theme, (newVal) => {
  document.documentElement.className = newVal
  localStorage.setItem('infolite-theme', newVal)
}, { immediate: true })

// 提供主题切换方法，供子组件调用（通过provide/inject）
import { provide } from 'vue'
provide('theme', theme)
provide('toggleTheme', () => {
  theme.value = theme.value === 'light' ? 'dark' : 'light'
})
</script>

<style scoped>
/* 全局样式重置（移除scoped则全局生效，此处保留scoped，仅作用于根组件） */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
}
body {
  min-height: 100vh;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-primary);
}

/* 定义CSS变量：亮色/暗色主题（通过HTML根节点class区分） */
:root.light {
  --bg-main: #f5f7fa;
  --bg-card: #ffffff;
  --text-primary: #1f2937;
  --text-secondary: #6b7280;
  --border-color: #e5e7eb;
  --hover-color: #f3f4f6;
}
:root.dark {
  --bg-main: #18181b;
  --bg-card: #27272a;
  --text-primary: #fafafa;
  --text-secondary: #a1a1aa;
  --border-color: #3f3f46;
  --hover-color: #323235;
}
</style>

<!-- 全局样式：无scoped，作用于整个项目 -->
<style>
/* 全局CSS变量生效，供所有子组件使用 */
:root.light {
  --bg-main: #f5f7fa;
  --bg-card: #ffffff;
  --text-primary: #1f2937;
  --text-secondary: #6b7280;
  --border-color: #e5e7eb;
  --hover-color: #f3f4f6;
}
:root.dark {
  --bg-main: #18181b;
  --bg-card: #27272a;
  --text-primary: #fafafa;
  --text-secondary: #a1a1aa;
  --border-color: #3f3f46;
  --hover-color: #323235;
}

/* 暗黑模式下Element表格hover行背景适配 */
.dark .el-table__row:hover {
  background-color: var(--hover-color) !important;
}
/* 暗黑模式下输入框/卡片边框适配 */
.dark .el-input__wrapper, .dark .el-card {
  border-color: var(--border-color) !important;
  background-color: var(--bg-card) !important;
}

/* 全局body背景色和文字颜色 */
body {
  background-color: var(--bg-main);
  color: var(--text-primary);
}
</style>