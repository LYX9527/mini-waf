import axios from 'axios'
import msg from '../utils/messageApi'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

// 请求拦截器：携带 Token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('mini_waf_token')
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：统一处理错误
api.interceptors.response.use(
  (response) => {
    const data = response.data
    if (data && typeof data === 'object') {
      // 业务错误：接口返回 200 但 status 字段为 error
      if (data.status === 'error') {
        msg.error(data.message || '操作失败')
        return Promise.reject(new Error(data.message || '操作失败'))
      }
      // 业务警告
      if (data.status === 'warning') {
        msg.warning(data.message || '操作异常')
      }
      // GET 数据接口中如果带 error 字段也提示
      if (data.error && !data.status) {
        msg.error(data.error)
      }
    }
    return response
  },
  (error) => {
    if (error.response) {
      const { status, data } = error.response

      // 401 鉴权失败 → 跳转登录
      if (status === 401) {
        if (window.location.pathname !== '/login' && window.location.pathname !== '/system-init') {
          localStorage.removeItem('mini_waf_token')
          window.location.href = '/login'
        } else {
          msg.error(data?.message || '用户名或密码错误')
        }
        return Promise.reject(error)
      }

      // 其他 HTTP 错误
      const errMsg = data?.message || data?.error || `请求失败 (${status})`
      msg.error(errMsg)
    } else if (error.code === 'ECONNABORTED') {
      msg.error('请求超时，请检查网络连接')
    } else {
      msg.error(error.message || '网络错误')
    }

    return Promise.reject(error)
  }
)

export default api
