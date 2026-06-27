import request from '../utils/request'

export const scanSubdomain = (params) => {
  return request({
    url: '/subdomain/scan',
    method: 'get',
    params
  })
}

/**
 * 导出子域名Excel
 * @param {string} domain - 目标域名
 */
export const exportSubdomainExcel = (domain) => {
  window.open(`/api/subdomain/export-excel?domain=${domain}`, '_blank')
}
