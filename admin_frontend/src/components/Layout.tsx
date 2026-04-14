import { Layout, Menu } from 'antd'
import {
  DashboardOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
  FileTextOutlined,
  SettingOutlined,
  SecurityScanOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'

const { Sider, Header, Content } = Layout

const menuItems = [
  { key: '/overview', icon: <DashboardOutlined />, label: '总览面板' },
  { key: '/sites', icon: <GlobalOutlined />, label: '站点管理' },
  {
    key: '/logs',
    icon: <FileTextOutlined />,
    label: '日志中心',
    children: [
      { key: '/logs/attacks', icon: <SafetyCertificateOutlined />, label: '防护日志' },
      { key: '/logs/access', icon: <UnorderedListOutlined />, label: '访问日志' },
    ],
  },
  { key: '/ip-lists', icon: <SecurityScanOutlined />, label: '黑白名单' },
  { key: '/rules', icon: <SafetyCertificateOutlined />, label: '安全规则' },
  { key: '/settings', icon: <SettingOutlined />, label: '系统设置' },
]

export default function MainLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const [openKeys, setOpenKeys] = useState<string[]>([])

  useEffect(() => {
    // 根据当前路径展开对应的父菜单
    if (location.pathname.startsWith('/logs')) {
      setOpenKeys(['/logs'])
    }
  }, [])

  const selectedKey = location.pathname

  return (
    <Layout style={{ height: '100vh', overflow: 'hidden', background: '#0b0f19' }}>
      <Sider
        width={220}
        theme="dark"
        style={{
          background: '#0d1117',
          borderRight: '1px solid #21262d',
        }}
      >
        <div
          style={{
            height: 64,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderBottom: '1px solid #21262d',
          }}
        >
          <span
            style={{
              color: '#00f0ff',
              fontSize: 18,
              fontWeight: 700,
              letterSpacing: 2,
              fontFamily: 'monospace',
            }}
          >
            MINI WAF
          </span>
        </div>
        <Menu
          mode="inline"
          selectedKeys={[selectedKey]}
          openKeys={openKeys}
          onOpenChange={(keys) => setOpenKeys(keys as string[])}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ background: 'transparent', borderRight: 0 }}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#0d1117',
            borderBottom: '1px solid #21262d',
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <span style={{ color: '#8b949e', fontSize: 14 }}>
             管理控制台
          </span>
        </Header>
        <Content
          style={{
            margin: 24,
            padding: 24,
            background: '#0d1117',
            borderRadius: 8,
            border: '1px solid #21262d',
            minHeight: 280,
            overflow: 'auto',
          }}
        >
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
