import { useState } from 'react'
import { Card, Form, Input, Button } from 'antd'
import { UserOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import message from '../utils/messageApi'

export default function Login() {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const onFinish = async (values: any) => {
    setLoading(true)
    try {
      const res = await api.post('/auth/login', values)
      if (res.data.status === 'success') {
        message.success('登录成功，欢迎回来！')
        localStorage.setItem('mini_waf_token', res.data.token)
        window.location.href = '/'
      }
      // status=error 由拦截器弹 toast
    } catch {
      // 拦截器已处理（401/网络错误等）
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#0d1117',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* 科技感背景点缀 */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.1,
        backgroundImage: 'linear-gradient(#1668dc 1px, transparent 1px), linear-gradient(90deg, #1668dc 1px, transparent 1px)',
        backgroundSize: '30px 30px',
        pointerEvents: 'none'
      }} />

      <Card
        style={{
          width: 400,
          background: 'rgba(22, 27, 34, 0.75)',
          backdropFilter: 'blur(12px)',
          border: '1px solid #30363d',
          boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          borderRadius: 8
        }}
        styles={{ body: { padding: '40px 32px' } }}
      >
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <SafetyCertificateOutlined style={{ fontSize: 48, color: '#1668dc', marginBottom: 12 }} />
          <h2 style={{ color: '#e6edf3', margin: 0, fontWeight: 600, letterSpacing: 1 }}>MINI WAF</h2>
          <div style={{ color: '#8b949e', fontSize: 13, marginTop: 4 }}>企业级边缘防御系统</div>
        </div>

        <Form name="login" onFinish={onFinish} size="large">
          <Form.Item
            name="username"
            rules={[{ required: true, message: '请输入管理员账号！' }]}
          >
            <Input 
              prefix={<UserOutlined style={{ color: '#8b949e' }} />} 
              placeholder="请输入管理员账号" 
            />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[{ required: true, message: '请输入管理员密码！' }]}
          >
            <Input.Password 
              prefix={<LockOutlined style={{ color: '#8b949e' }} />} 
              placeholder="请输入管理凭证" 
            />
          </Form.Item>

          <Form.Item style={{ marginTop: 32, marginBottom: 0 }}>
            <Button type="primary" htmlType="submit" loading={loading} block style={{ fontWeight: 500, background: '#1668dc' }}>
              身份登录
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}
