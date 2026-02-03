import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

// 引入Element Plus
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
// 引入Element Plus所有图标
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
// 引入axios（后续封装，先全局挂载）
import axios from 'axios'

const app = createApp(App)

// 全局注册Element Plus图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

// 全局挂载axios
app.config.globalProperties.$axios = axios
// 配置axios默认超时时间
axios.defaults.timeout = 60000 // 扫描可能耗时，设置60秒超时

app.use(ElementPlus).use(router).mount('#app')