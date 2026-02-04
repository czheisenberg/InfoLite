import { createRouter, createWebHistory } from 'vue-router'
// 引入资产扫描页面
import AssetScan from '../views/AssetScan.vue'
// 引入登录页面
import Login from '../views/Login.vue'

const routes = [
  {
    path: '/',
    name: 'AssetScan',
    component: AssetScan,
    meta: { 
      title: 'InfoLite - 资产扫描查询',
      requiresAuth: true
    }
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { title: 'InfoLite - 登录' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫：修改页面标题和认证检查
router.beforeEach((to, from, next) => {
  if (to.meta.title) document.title = to.meta.title
  
  // 检查是否需要认证
  if (to.meta.requiresAuth) {
    const token = localStorage.getItem('token')
    if (token) {
      next()
    } else {
      next('/login')
    }
  } else {
    next()
  }
})

export default router