import { useState } from 'react'
import { Card, Form, Input, Button, Alert } from 'antd'
import { UserOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import message from '../utils/messageApi'

export default function SystemInit() {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const onFinish = async (values: any) => {
    if (values.password !== values.confirm) {
        return message.error('两次输入的密码不一致！')
    }

    setLoading(true)
    try {
      const res = await api.post('/auth/init', { username: values.username, password: values.password })
      if (res.data.status === 'success') {
        message.success('系统初始化完毕！请重新登录。')
        navigate('/login')
      }
      // status=error 由拦截器处理
    } catch {
      // 拦截器已处理
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
      <Card
        style={{
          width: 420,
          background: '#161b22',
          border: '1px solid #30363d',
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          borderRadius: 8
        }}
        styles={{ body: { padding: '40px 32px' } }}
      >
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <SafetyCertificateOutlined style={{ fontSize: 48, color: '#1668dc', marginBottom: 16 }} />
          <h2 style={{ color: '#e6edf3', margin: 0, fontSize: 20, fontWeight: 500 }}>初始化管理员账号</h2>
          <div style={{ color: '#8b949e', fontSize: 13, marginTop: 8 }}>系统检测到尚未配置管理员，请设置初始管理凭证。</div>
        </div>

        <Alert 
          message="高权限操作" 
          description="该账户将具备完全的控制台访问权限，请妥善保管您的密码。" 
          type="info" 
          showIcon 
          style={{ marginBottom: 24, background: '#1f242c', borderColor: '#30363d', color: '#c9d1d9' }} 
        />

        <Form name="init" onFinish={onFinish} layout="vertical" size="large">
          <Form.Item
            label={<span style={{ color: '#c9d1d9' }}>管理员账号</span>}
            name="username"
            rules={[{ required: true, message: '必填项' }, { min: 4, message: '账号长度需大于等于4位' }]}
          >
            <Input 
              prefix={<UserOutlined style={{ color: '#8b949e' }} />} 
              placeholder="请输入管理员账号" 
            />
          </Form.Item>

          <Form.Item
            label={<span style={{ color: '#c9d1d9' }}>登录密码</span>}
            name="password"
            rules={[{ required: true, message: '必填项' }, { min: 8, message: '密码安全强度必须大于8位' }]}
          >
            <Input.Password 
              prefix={<LockOutlined style={{ color: '#8b949e' }} />} 
              placeholder="至少包含 8 个字符" 
            />
          </Form.Item>

          <Form.Item
            label={<span style={{ color: '#c9d1d9' }}>确认密码</span>}
            name="confirm"
            rules={[{ required: true, message: '请再次输入密码进行确认' }]}
          >
            <Input.Password 
              prefix={<LockOutlined style={{ color: '#8b949e' }} />} 
              placeholder="请再次输入上方密码" 
            />
          </Form.Item>

          <Form.Item style={{ marginTop: 24, marginBottom: 0 }}>
            <Button type="primary" htmlType="submit" loading={loading} block style={{ fontWeight: 500 }}>
              完成初始化
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}
