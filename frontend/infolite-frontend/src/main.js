import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

// 引入Pixelium Design
import PixeliumDesign from '@pixelium/web-vue'
import '@pixelium/web-vue/es/index.css'

// 引入axios（后续封装，先全局挂载）
import axios from 'axios'

const app = createApp(App)

// 全局挂载axios
app.config.globalProperties.$axios = axios
// 配置axios默认超时时间
axios.defaults.timeout = 60000 // 扫描可能耗时，设置60秒超时

app.use(PixeliumDesign).use(router).mount('#app')