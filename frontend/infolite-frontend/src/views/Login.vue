<template>
  <div class="login-page">
    <div class="login-card">
      <h1 class="login-title">InfoLite</h1>
      <h2 class="login-subtitle">网络资产扫描平台</h2>
      
      <!-- 登录表单 -->
      <div v-if="!showRegister" class="login-form">
        <form @submit.prevent="handleLogin">
          <div class="form-group">
            <label for="username" class="form-label">用户名</label>
            <input 
              type="text" 
              id="username" 
              v-model="loginForm.username" 
              class="form-input" 
              placeholder="请输入用户名"
              required
            >
          </div>
          
          <div class="form-group">
            <label for="password" class="form-label">密码</label>
            <input 
              type="password" 
              id="password" 
              v-model="loginForm.password" 
              class="form-input" 
              placeholder="请输入密码"
              required
            >
          </div>
          
          <div class="form-actions">
            <button type="submit" class="btn-primary" :disabled="loading">
              {{ loading ? '登录中...' : '登录' }}
            </button>
            <button type="button" class="btn-secondary" @click="handleRegister" :disabled="loading">
              注册
            </button>
          </div>
        </form>
      </div>
      
      <!-- 注册表单 -->
      <div v-if="showRegister" class="register-form">
        <h3 class="register-title">用户注册</h3>
        <div class="form-group">
          <label for="reg-username" class="form-label">用户名</label>
          <input 
            type="text" 
            id="reg-username" 
            v-model="registerForm.username" 
            class="form-input" 
            placeholder="请输入用户名"
            required
          >
        </div>
        
        <div class="form-group">
          <label for="reg-password" class="form-label">密码</label>
          <input 
            type="password" 
            id="reg-password" 
            v-model="registerForm.password" 
            class="form-input" 
            placeholder="请输入密码"
            required
          >
        </div>
        
        <div class="form-actions">
          <button type="button" class="btn-primary" @click="submitRegister" :disabled="loading">
            {{ loading ? '注册中...' : '注册' }}
          </button>
          <button type="button" class="btn-secondary" @click="showRegister = false">
            取消
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
// 引入Pixelium Design的Message组件
import { Message } from '@pixelium/web-vue/es'
import { login, register } from '../api/auth'

const router = useRouter()

// 登录表单
const loginForm = ref({
  username: '',
  password: ''
})

// 注册表单
const registerForm = ref({
  username: '',
  password: ''
})

// 状态
const loading = ref(false)
const showRegister = ref(false)

// 处理登录
const handleLogin = async () => {
  if (loading.value) return
  
  if (!loginForm.value.username || !loginForm.value.password) {
    $message['info']('用户名和密码不能为空')
    return
  }
  
  try {
    loading.value = true
    
    const response = await login({
      username: loginForm.value.username,
      password: loginForm.value.password
    })
    
    if (response.code === 200) {
      // 存储token
      localStorage.setItem('token', response.data.access_token)
      localStorage.setItem('username', response.data.username)
      // 跳转到首页
      router.push('/')
    } else {
      $message['info']('登录失败，请检查用户名和密码')
    }
  } catch (error) {
    $message['error']('登录失败，请检查用户名和密码')
  } finally {
    loading.value = false
  }
}

// 处理注册
const handleRegister = () => {
  showRegister.value = true
}

// 提交注册
const submitRegister = async () => {
  if (loading.value) return
  
  if (!registerForm.value.username || !registerForm.value.password) {
    $message['info']('请输入用户名和密码') 
    return
  }
  
  try {
    loading.value = true
    
    const response = await register({
      username: registerForm.value.username,
      password: registerForm.value.password
    })
    
    if (response.code === 200) {
      $message['success']('注册成功，请登录')
      showRegister.value = false
    } else {
      $message['error'](response.msg)
    }
  } catch (error) {
    $message['error']('注册失败，请检查网络连接')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
/* 像素风格字体 */
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

.login-page {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: var(--bg-main);
  font-family: 'Press Start 2P', monospace;
}

.login-card {
  background-color: var(--bg-card);
  border: 2px solid var(--border-color);
  border-radius: 8px;
  padding: 40px;
  box-shadow: 4px 4px 0 rgba(0, 0, 0, 0.2);
  max-width: 400px;
  width: 100%;
}

.login-title {
  font-size: 32px;
  color: var(--text-primary);
  margin: 0 0 10px 0;
  text-shadow: 2px 2px 0 var(--border-color);
  text-align: center;
}

.login-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0 0 30px 0;
  text-align: center;
}

.login-form {
  margin-bottom: 30px;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  font-size: 12px;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.form-input {
  width: 100%;
  padding: 12px;
  font-size: 14px;
  border: 2px solid var(--border-color);
  border-radius: 4px;
  background-color: var(--bg-main);
  color: var(--text-primary);
  font-family: 'Press Start 2P', monospace;
  box-shadow: inset 2px 2px 0 rgba(0, 0, 0, 0.1);
}

.form-input:focus {
  outline: none;
  border-color: var(--text-primary);
  box-shadow: inset 2px 2px 0 rgba(0, 0, 0, 0.2);
}

.form-actions {
  display: flex;
  gap: 10px;
  margin-top: 30px;
}

.btn-primary {
  flex: 1;
  padding: 12px;
  font-size: 14px;
  background-color: #4ade80;
  color: #15803d;
  border: 2px solid #22c55e;
  border-radius: 4px;
  cursor: pointer;
  font-family: 'Press Start 2P', monospace;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
  transition: all 0.2s ease;
}

.btn-primary:hover {
  transform: translate(1px, 1px);
  box-shadow: 1px 1px 0 rgba(0, 0, 0, 0.2);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
}

.btn-secondary {
  flex: 1;
  padding: 12px;
  font-size: 14px;
  background-color: var(--bg-main);
  color: var(--text-primary);
  border: 2px solid var(--border-color);
  border-radius: 4px;
  cursor: pointer;
  font-family: 'Press Start 2P', monospace;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
  transition: all 0.2s ease;
}

.btn-secondary:hover {
  transform: translate(1px, 1px);
  box-shadow: 1px 1px 0 rgba(0, 0, 0, 0.2);
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
  box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
}

.register-form {
  margin-top: 30px;
  padding-top: 20px;
  border-top: 2px solid var(--border-color);
}

.register-title {
  font-size: 16px;
  color: var(--text-primary);
  margin: 0 0 20px 0;
  text-align: center;
}
</style>