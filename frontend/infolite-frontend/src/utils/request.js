import axios from 'axios'

// 创建axios实例
const service = axios.create({
  baseURL: '/api', // 匹配Vite代理的/api前缀
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json;charset=utf-8'
  }
})

// 请求拦截器：添加token和加载状态
service.interceptors.request.use(
  (config) => {
    // 添加token认证
    const token = localStorage.getItem('token')
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    console.error('请求异常:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器：统一处理结果
service.interceptors.response.use(
  (response) => {
    const res = response.data
    // 非200状态码，统一处理
    if (res.code !== 200) {
      return Promise.reject(new Error(res.msg || '请求失败'))
    }
    // 成功：返回数据
    return res
  },
  (error) => {
    console.error('响应异常:', error)
    // 401未授权，跳转到登录页
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('username')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default service