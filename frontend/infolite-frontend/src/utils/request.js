import axios from 'axios'
import { ElMessage, ElLoading } from 'element-plus'

// 创建axios实例
const service = axios.create({
  baseURL: '/api', // 匹配Vite代理的/api前缀
  timeout: 60000,
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'
  }
})

// 加载层实例
let loadingInstance = null

// 请求拦截器：添加加载层
service.interceptors.request.use(
  (config) => {
    // 扫描时显示加载层（GET请求且包含ip参数）
    if (config.method === 'get' && config.params?.ip) {
      loadingInstance = ElLoading.service({
        lock: true,
        text: '正在扫描/查询，请稍候...',
        background: 'rgba(0, 0, 0, 0.7)'
      })
    }
    return config
  },
  (error) => {
    ElMessage.error('请求异常，请稍后重试')
    return Promise.reject(error)
  }
)

// 响应拦截器：统一处理结果、关闭加载层
service.interceptors.response.use(
  (response) => {
    // 关闭加载层
    if (loadingInstance) loadingInstance.close()
    const res = response.data
    // 非200状态码，统一提示
    if (res.code !== 200) {
      ElMessage.error(res.msg || '请求失败')
      return Promise.reject(new Error(res.msg || '请求失败'))
    }
    // 成功：返回数据
    return res
  },
  (error) => {
    // 关闭加载层
    if (loadingInstance) loadingInstance.close()
    // 超时/网络错误提示
    ElMessage.error(error.message.includes('timeout') ? '请求超时，请检查服务是否运行' : '网络错误，请检查后端服务')
    return Promise.reject(error)
  }
)

export default service