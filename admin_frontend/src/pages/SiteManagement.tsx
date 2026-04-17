import { Table, Button, Modal, Form, Input, Select, Switch, Tag, Popconfirm, Badge, AutoComplete, Tooltip } from 'antd'
import { PlusOutlined, DeleteOutlined, CheckCircleOutlined, LockOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

interface RouteItem {
  id: number
  path_prefix: string
  host_pattern?: string | null
  upstream: string
  route_type: string
  is_spa: boolean
  is_active?: boolean
}

type HealthStatus = 'unknown' | 'healthy' | 'unhealthy'

interface HealthInfo {
  status: HealthStatus
  latency?: number
}

export default function SiteManagement() {
  const [routes, setRoutes] = useState<RouteItem[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRoute, setEditingRoute] = useState<{ id: number; path_prefix: string; host_pattern: string | null } | null>(null)
  const [form] = Form.useForm()
  const [healthStatus, setHealthStatus] = useState<Record<string, HealthInfo>>({})
  const [checking, setChecking] = useState<Record<string, boolean>>({})
  const [certDomains, setCertDomains] = useState<string[]>([])

  const fetchRoutes = async () => {
    try {
      const res = await api.get('/routes')
      setRoutes(res.data.routes || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchRoutes() }, [])

  // 统一开启弹窗入口（新增 / 编辑）
  const openModal = async (route?: RouteItem) => {
    try {
      const res = await api.get('/ssl/domains')
      setCertDomains(res.data.domains || [])
    } catch { setCertDomains([]) }

    if (route) {
      form.setFieldsValue({
        path_prefix: route.path_prefix,
        host_pattern: route.host_pattern || '',
        route_type: route.route_type,
        upstream: route.upstream,
        is_spa: route.is_spa,
      })
      setEditingRoute({ id: route.id, path_prefix: route.path_prefix, host_pattern: route.host_pattern || null })
    } else {
      form.resetFields()
      setEditingRoute(null)
    }
    setModalOpen(true)
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      // normalize: empty string -> undefined (so backend stores NULL)
      if (!values.host_pattern) values.host_pattern = undefined
      if (editingRoute) {
        await api.put('/routes/edit', { ...values, old_path_prefix: editingRoute.path_prefix, old_host_pattern: editingRoute.host_pattern })
        message.success('路由更新成功')
      } else {
        await api.post('/routes', values)
        message.success('路由添加成功')
      }
      setModalOpen(false)
      setEditingRoute(null)
      form.resetFields()
      fetchRoutes()
    } catch {
      // 拦截器已处理
    }
  }

  const handleEditClick = (record: RouteItem) => openModal(record)

  const handleDisable = async (id: number) => {
    try {
      await api.post('/routes/disable', { id })
      message.success('路由已停用')
      fetchRoutes()
    } catch {
      // 拦截器已处理
    }
  }

  const handleRealDelete = async (id: number) => {
    try {
      await api.delete('/routes', { data: { id } })
      message.success('路由已彻底删除')
      fetchRoutes()
    } catch {
      // 拦截器已处理
    }
  }

  const handleEnable = async (id: number) => {
    try {
      await api.post('/routes/enable', { id })
      message.success('路由已启用')
      fetchRoutes()
    } catch {
      // 拦截器已处理
    }
  }

  const checkHealth = async (prefix: string, upstream: string) => {
    setChecking((prev) => ({ ...prev, [prefix]: true }))
    try {
      const res = await api.post('/routes/health-check', { upstream })
      setHealthStatus((prev) => ({
        ...prev,
        [prefix]: {
          status: res.data.reachable ? 'healthy' : 'unhealthy',
          latency: res.data.latency_ms,
        },
      }))
    } catch {
      setHealthStatus((prev) => ({ ...prev, [prefix]: { status: 'unhealthy' } }))
    } finally {
      setChecking((prev) => ({ ...prev, [prefix]: false }))
    }
  }

  const checkAllProxy = async () => {
    for (const r of routes) {
      if (r.is_active === false) continue
      // eslint-disable-next-line no-await-in-loop
      await checkHealth(r.path_prefix, r.upstream)
    }
  }

  useEffect(() => {
    if (routes.length > 0) checkAllProxy()
  }, [routes])

  const statusDot = (record: RouteItem) => {
    if (record.is_active === false) {
      return <Badge color="#f5222d" text={<span style={{ color: '#f5222d' }}>已停用</span>} />
    }
    const info = healthStatus[record.path_prefix] || { status: 'unknown' }
    const config: Record<HealthStatus, { color: string; text: string }> = {
      healthy: { color: '#52c41a', text: info.latency !== undefined ? `正常 (${info.latency}ms)` : '正常' },
      unhealthy: { color: '#f5222d', text: '异常' },
      unknown: { color: '#8b949e', text: '未知' },
    }
    const c = config[info.status]
    return <Badge color={c.color} text={<span style={{ color: c.color }}>{c.text}</span>} />
  }

  const columns = [
    {
      title: '路径前缀',
      dataIndex: 'path_prefix',
      key: 'path_prefix',
      render: (text: string) => <Tag color="blue">{text}</Tag>,
    },
    {
      title: '域名限制',
      dataIndex: 'host_pattern',
      key: 'host_pattern',
      width: 180,
      render: (h: string | null) => h
        ? <Tag color="purple">{h}</Tag>
        : <span style={{ color: '#484f58', fontSize: 12 }}>不限</span>,
    },
    {
      title: '目标地址',
      dataIndex: 'upstream',
      key: 'upstream',
      ellipsis: true,
    },
    {
      title: '状态',
      key: 'status',
      width: 120,
      render: (_: any, record: RouteItem) => statusDot(record),
    },
    {
      title: '操作',
      key: 'action',
      width: 400,
      render: (_: any, record: RouteItem) => (
        <div style={{ display: 'flex', gap: 8 }}>
          {record.is_active !== false && (
            <Button
              size="small"
              icon={<CheckCircleOutlined />}
              loading={checking[record.path_prefix]}
              onClick={() => checkHealth(record.path_prefix, record.upstream)}
            >
              测试连通性
            </Button>
          )}
          {record.is_active === false ? (
            <Button size="small" type="primary" onClick={() => handleEnable(record.id)}>
              启用
            </Button>
          ) : (
            <Popconfirm title="确定停用此路由？" onConfirm={() => handleDisable(record.id)}>
              <Button size="small" type="dashed">停用</Button>
            </Popconfirm>
          )}
          <Button size="small" onClick={() => handleEditClick(record)}>编辑</Button>
          <Popconfirm title="确定要彻底删除此路由吗？关联记录将丢失。" onConfirm={() => handleRealDelete(record.id)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </div>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0 }}>站点管理</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button icon={<CheckCircleOutlined />} onClick={checkAllProxy}>
            全部测试
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openModal()}>
            添加路由
          </Button>
        </div>
      </div>

      <Table
        dataSource={routes}
        columns={columns}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      <Modal
        title={editingRoute ? "编辑路由" : "添加路由"}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => { setModalOpen(false); setEditingRoute(null); form.resetFields() }}
        okText="保存"
        cancelText="取消"
      >
        <Form form={form} layout="vertical" initialValues={{ route_type: 'proxy', is_spa: false }}>
          <Form.Item name="path_prefix" label="路径前缀" rules={[{ required: true, message: '请输入路径前缀' }]}>
            <Input placeholder="/ 或 /api 或 /app" />
          </Form.Item>
          <Form.Item
            name="host_pattern"
            label={
              <span>
                域名限制&nbsp;
                <span style={{ color: '#8b949e', fontSize: 12, fontWeight: 400 }}>（可选，不填则匹配所有域名）</span>
                {certDomains.length > 0 && (
                  <span style={{ color: '#3fb950', fontSize: 12, marginLeft: 8 }}>
                    <LockOutlined style={{ marginRight: 3 }} />{certDomains.length} 个域名已安装 SSL
                  </span>
                )}
              </span>
            }
          >
            <AutoComplete
              options={certDomains.map(d => ({
                value: d,
                label: (
                  <span>
                    <LockOutlined style={{ color: '#3fb950', marginRight: 6 }} />
                    {d}
                    <Tag color="green" style={{ marginLeft: 8, fontSize: 10 }}>SSL 已安装</Tag>
                  </span>
                ),
              }))}
              placeholder="api.example.com 或 *.example.com"
              filterOption={(input, option) =>
                (option?.value as string || '').toLowerCase().includes(input.toLowerCase())
              }
              onChange={(val) => {
                if (certDomains.includes(val)) {
                  message.info(`域名 ${val} 已安装 SSL 证书，保存后 HTTPS 即生效`)
                }
              }}
            />
          </Form.Item>
          <Form.Item name="route_type" hidden initialValue="proxy">
            <Input />
          </Form.Item>
          <Form.Item name="upstream" label="目标地址" rules={[{ required: true, message: '请输入目标地址' }]}>
            <Input placeholder="nginx:80 或 backend-service:3000" />
          </Form.Item>
          <Form.Item name="is_spa" hidden valuePropName="checked">
            <Switch />
          </Form.Item>
          <div style={{
            background: 'rgba(0,240,255,0.04)',
            border: '1px solid rgba(0,240,255,0.12)',
            borderRadius: 6,
            padding: '10px 14px',
            color: '#8b949e',
            fontSize: 12,
            lineHeight: '20px',
          }}>
            <div style={{ color: '#c9d1d9', marginBottom: 4, fontWeight: 500 }}>路由匹配逻辑</div>
            支持同时配置多条路由以区分不同域名的服务：<br />
            • <code style={{color:'#00f0ff'}}>api.example.com</code> + <code style={{color:'#00f0ff'}}>/</code> → 后端 A<br />
            • <code style={{color:'#00f0ff'}}>web.example.com</code> + <code style={{color:'#00f0ff'}}>/</code> → 后端 B<br />
            • 不填域名 + <code style={{color:'#00f0ff'}}>/api</code> → 通配路由，所有域名均可匹配
          </div>
        </Form>
      </Modal>
    </div>
  )
}
