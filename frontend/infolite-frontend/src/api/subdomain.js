import request from '../utils/request'

export const scanSubdomain = (params) => {
  return request({
    url: '/subdomain/scan',
    method: 'get',
    params
  })
}
