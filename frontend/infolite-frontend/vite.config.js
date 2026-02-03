import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1', // 本地运行地址
    port: 5173, // 前端端口
    open: true, // 启动自动打开浏览器
    proxy: {
      // 跨域代理：匹配/api开头的请求
      '/api': {
        target: 'http://127.0.0.1:8000', // 后端API地址
        changeOrigin: true, // 开启跨域
        // rewrite: (path) => path.replace(/^\/api/, '') // 移除路径中的/api前缀
      }
    }
  }
})
