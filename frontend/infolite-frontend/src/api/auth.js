// 认证相关API接口
import request from '../utils/request'

/**
 * 用户注册
 * @param {Object} data - 注册参数
 * @param {string} data.username - 用户名
 * @param {string} data.password - 密码
 * @returns {Promise} - 注册结果
 */
export const register = (data) => {
  return request({
    url: '/auth/register',
    method: 'post',
    data
  })
}

/**
 * 用户登录
 * @param {Object} data - 登录参数
 * @param {string} data.username - 用户名
 * @param {string} data.password - 密码
 * @returns {Promise} - 登录结果
 */
export const login = (data) => {
  return request({
    url: '/auth/login',
    method: 'post',
    data
  })
}
