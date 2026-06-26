// 资产相关API接口
import request from '../utils/request'

/**
 * 资产查询/扫描
 * @param {Object} data - 查询参数
 * @param {string} data.ip - 目标IP地址
 * @returns {Promise} - 查询结果
 */
export const queryAsset = (params) => {
  return request({
    url: '/asset/query',
    method: 'get',
    params
  })
}

/**
 * 资产详情
 * @param {Object} data - 查询参数
 * @param {string} data.asset_id - 资产ID
 * @returns {Promise} - 资产详情
 */
export const getAssetDetail = (params) => {
  return request({
    url: '/asset/detail',
    method: 'get',
    params
  })
}

/**
 * 资产列表
 * @param {Object} data - 查询参数
 * @param {number} data.page - 页码
 * @param {number} data.page_size - 每页数量
 * @returns {Promise} - 资产列表
 */
export const getAssetList = (params) => {
  return request({
    url: '/api/asset/list',
    method: 'get',
    params
  })
}

/**
 * Nmap自定义扫描
 * @param {Object} params - 扫描参数
 * @param {string} params.ip - 目标IP
 * @param {string} params.ports - 端口范围
 * @param {string} params.scan_args - Nmap参数
 * @param {boolean} params.save_to_db - 是否保存到数据库
 * @returns {Promise} - 扫描结果
 */
export const nmapCustomScan = (params) => {
  return request({
    url: '/asset/nmap-scan',
    method: 'get',
    params
  })
}
