<template>
  <div class="page-footer">
    <div class="footer-content">
      <p>© {{ currentYear }} InfoLite 网络资产扫描平台</p>
      <p>版本 1.0.0 | 安全扫描工具</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

// 当前年份
const currentYear = ref(new Date().getFullYear())

onMounted(() => {
  currentYear.value = new Date().getFullYear()
})
</script>

<style scoped>
/* 页面底部 */
.page-footer {
  background: var(--bg-secondary);
  border-top: 3px solid var(--border-color);
  padding: 20px;
  margin-top: 40px;
  font-family: 'Press Start 2P', monospace, 'SimHei', 'Microsoft YaHei';
}

.footer-content {
  max-width: 1400px;
  margin: 0 auto;
  text-align: center;
}

.footer-content p {
  margin: 10px 0;
  font-size: 12px;
  color: var(--text-secondary);
}

/* 响应式适配 */
@media (max-width: 768px) {
  .page-footer {
    padding: 15px;
    margin-top: 30px;
  }
  
  .footer-content p {
    font-size: 10px;
    margin: 8px 0;
  }
}
</style>