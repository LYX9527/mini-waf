/**
 * 全局消息桥接
 * 解决 antd v5 静态 message API 在 React 树外无法使用的问题
 * 在 React 组件树中初始化后，非 React 代码也能调用
 */
import type { MessageInstance } from 'antd/es/message/interface'

let messageApi: MessageInstance | null = null

export function setMessageApi(api: MessageInstance) {
  messageApi = api
}

export function showMessage(type: 'success' | 'error' | 'warning' | 'info', content: string) {
  if (messageApi) {
    messageApi[type](content)
  } else {
    // 降级：使用 console
    console.warn(`[message.${type}]`, content)
  }
}

export default {
  success: (msg: string) => showMessage('success', msg),
  error: (msg: string) => showMessage('error', msg),
  warning: (msg: string) => showMessage('warning', msg),
  info: (msg: string) => showMessage('info', msg),
}
