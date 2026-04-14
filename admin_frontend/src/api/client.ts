import axios from 'axios'

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

// 响应拦截器：处理鉴权失败
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      if (window.location.pathname !== '/login' && window.location.pathname !== '/system-init') {
        localStorage.removeItem('mini_waf_token')
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api
