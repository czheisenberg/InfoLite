<template>
  <div class="page-footer">
    <div class="footer-content">
      <div class="footer-desc">
        轻量级网络空间测绘平台，支持端口探测、指纹识别、子域名扫描
      </div>
      <div class="footer-copyright">
        <p>© {{ currentYear }} InfoLite 网络资产扫描平台</p>
        <p>版本 1.0.0 | 安全扫描工具</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const currentYear = ref(new Date().getFullYear())

onMounted(() => {
  currentYear.value = new Date().getFullYear()
})
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

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

.footer-desc {
  font-size: 10px;
  color: var(--text-secondary);
  margin-bottom: 16px;
  line-height: 1.8;
}

.footer-copyright p {
  margin: 6px 0;
  font-size: 10px;
  color: var(--text-secondary);
}

@media (max-width: 768px) {
  .page-footer {
    padding: 15px;
    margin-top: 30px;
  }
  
  .footer-desc {
    font-size: 9px;
  }
  
  .footer-copyright p {
    font-size: 9px;
    margin: 5px 0;
  }
}
</style>
