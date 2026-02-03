import { createRouter, createWebHistory } from 'vue-router'
// 引入资产扫描页面（后续创建）
import AssetScan from '../views/AssetScan.vue'

const routes = [
  {
    path: '/',
    name: 'AssetScan',
    component: AssetScan,
    meta: { title: 'InfoLite - 资产扫描查询' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫：修改页面标题
router.beforeEach((to, from, next) => {
  if (to.meta.title) document.title = to.meta.title
  next()
})

export default router