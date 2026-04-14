import { Table, Button, Modal, Form, Input, Select, Switch, message, Tag, Popconfirm, Badge } from 'antd'
import { PlusOutlined, DeleteOutlined, CheckCircleOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'

interface RouteItem {
  path_prefix: string
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
  const [editingRoute, setEditingRoute] = useState<string | null>(null)
  const [form] = Form.useForm()
  const [healthStatus, setHealthStatus] = useState<Record<string, HealthInfo>>({})
  const [checking, setChecking] = useState<Record<string, boolean>>({})

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

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingRoute) {
        await api.put('/routes/edit', { ...values, old_path_prefix: editingRoute })
        message.success('路由更新成功')
      } else {
        await api.post('/routes', values)
        message.success('路由添加成功')
      }
      setModalOpen(false)
      setEditingRoute(null)
      form.resetFields()
      fetchRoutes()
    } catch (e: any) {
      message.error(e.response?.data?.message || '保存失败')
    }
  }

  const handleEditClick = (record: RouteItem) => {
    form.setFieldsValue({
      path_prefix: record.path_prefix,
      route_type: record.route_type,
      upstream: record.upstream,
      is_spa: record.is_spa,
    })
    setEditingRoute(record.path_prefix)
    setModalOpen(true)
  }

  const handleDisable = async (prefix: string) => {
    try {
      await api.post('/routes/disable', { path_prefix: prefix })
      message.success('路由已停用')
      fetchRoutes()
    } catch (e: any) {
      message.error(e.response?.data?.message || '停用失败')
    }
  }

  const handleRealDelete = async (prefix: string) => {
    try {
      await api.delete('/routes', { data: { path_prefix: prefix } })
      message.success('路由已彻底删除')
      fetchRoutes()
    } catch (e: any) {
      message.error(e.response?.data?.message || '删除失败')
    }
  }

  const handleEnable = async (prefix: string) => {
    try {
      await api.post('/routes/enable', { path_prefix: prefix })
      message.success('路由已启用')
      fetchRoutes()
    } catch (e: any) {
      message.error(e.response?.data?.message || '启用失败')
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
      if (r.route_type === 'proxy') {
        // eslint-disable-next-line no-await-in-loop
        await checkHealth(r.path_prefix, r.upstream)
      }
    }
  }

  useEffect(() => {
    if (routes.length > 0) checkAllProxy()
  }, [routes])

  const statusDot = (record: RouteItem) => {
    if (record.is_active === false) {
      return <Badge color="#f5222d" text={<span style={{ color: '#f5222d' }}>已停用</span>} />
    }
    if (record.route_type === 'static') {
      return <Badge color="#8b949e" text={<span style={{ color: '#8b949e' }}>静态</span>} />
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
      title: '类型',
      dataIndex: 'route_type',
      key: 'route_type',
      render: (type: string) => (
        <Tag color={type === 'proxy' ? 'green' : 'purple'}>
          {type === 'proxy' ? '反向代理' : '静态文件'}
        </Tag>
      ),
    },
    {
      title: '目标',
      dataIndex: 'upstream',
      key: 'upstream',
      ellipsis: true,
    },
    {
      title: 'SPA',
      dataIndex: 'is_spa',
      key: 'is_spa',
      render: (is_spa: boolean) => (is_spa ? <Tag color="cyan">SPA</Tag> : '-'),
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
          {record.route_type === 'proxy' && (
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
            <Button size="small" type="primary" onClick={() => handleEnable(record.path_prefix)}>
              启用
            </Button>
          ) : (
            <Popconfirm title="确定停用此路由？" onConfirm={() => handleDisable(record.path_prefix)}>
              <Button size="small" type="dashed">停用</Button>
            </Popconfirm>
          )}
          <Button size="small" onClick={() => handleEditClick(record)}>编辑</Button>
          <Popconfirm title="确定要彻底删除此路由吗？关联记录将丢失。" onConfirm={() => handleRealDelete(record.path_prefix)}>
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
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
            添加路由
          </Button>
        </div>
      </div>

      <Table
        dataSource={routes}
        columns={columns}
        rowKey="path_prefix"
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
            <Input placeholder="/api 或 /app" />
          </Form.Item>
          <Form.Item name="route_type" label="路由类型" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="proxy">反向代理 (host:port)</Select.Option>
              <Select.Option value="static">静态文件 (目录路径)</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="upstream" label="目标地址" rules={[{ required: true, message: '请输入目标地址' }]}>
            <Input placeholder="127.0.0.1:3000 或 /var/www/html" />
          </Form.Item>
          <Form.Item name="is_spa" label="SPA 模式" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
