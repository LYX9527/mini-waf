import { Table, Button, Modal, Form, Input, InputNumber, Popconfirm, Tag, Tabs, Switch, Spin } from 'antd'
import { PlusOutlined, DeleteOutlined, EditOutlined, CheckCircleOutlined, SaveOutlined } from '@ant-design/icons'
import { useEffect, useState, useRef } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

interface NginxConfig {
  listen_port: number
  site_name: string | null
  server_name: string | null
  root_path: string
  filename: string
  raw_content: string
}

// ─── 代码编辑器组件 ─────────────────────────────────

function CodeEditor({
  value,
  onChange,
  height = 400,
  readOnly = false,
}: {
  value: string
  onChange?: (v: string) => void
  height?: number
  readOnly?: boolean
}) {
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const lines = (value || '').split('\n')

  return (
    <div style={{
      display: 'flex',
      border: '1px solid #30363d',
      borderRadius: 6,
      overflow: 'hidden',
      background: '#0d1117',
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
      fontSize: 13,
      lineHeight: '20px',
      height,
    }}>
      <div style={{
        padding: '12px 0',
        background: '#161b22',
        color: '#484f58',
        textAlign: 'right',
        userSelect: 'none',
        minWidth: 44,
        borderRight: '1px solid #21262d',
        overflowY: 'hidden',
      }}>
        {lines.map((_, i) => (
          <div key={i} style={{ padding: '0 10px', height: 20 }}>{i + 1}</div>
        ))}
      </div>
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        readOnly={readOnly}
        spellCheck={false}
        style={{
          flex: 1,
          padding: 12,
          background: 'transparent',
          color: '#c9d1d9',
          border: 'none',
          outline: 'none',
          resize: 'none',
          fontFamily: 'inherit',
          fontSize: 'inherit',
          lineHeight: 'inherit',
          height: '100%',
          boxSizing: 'border-box',
          tabSize: 4,
          whiteSpace: 'pre',
          overflowX: 'auto',
          overflowY: 'auto',
        }}
      />
    </div>
  )
}

// ─── 主配置编辑 Tab ─────────────────────────────────

function MainConfEditor() {
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    api.get('/nginx/main-conf').then(res => {
      // 拦截器已处理 res.data.error 的 toast 提示
      if (res.data.error) {
        setLoadError(res.data.error)
      }
      setContent(res.data.content || '')
    }).catch((e: any) => {
      // 拦截器已弹 toast，这里只记录状态
      setLoadError(e.message || '读取失败')
    }).finally(() => setLoading(false))
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const res = await api.put('/nginx/main-conf', { content })
      if (res.data.status === 'success') {
        message.success(res.data.message)
      }
      // warning 由拦截器处理
    } catch {
      // 拦截器已处理
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await api.post('/nginx/test')
      setTestResult({ ok: res.data.status === 'success', msg: res.data.message })
    } catch (e: any) {
      setTestResult({ ok: false, msg: e.message || '测试失败' })
    } finally {
      setTesting(false)
    }
  }

  if (loading) return <div style={{ textAlign: 'center', padding: 60 }}><Spin /></div>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ color: '#8b949e', fontSize: 13 }}>
          编辑 nginx 主配置文件 <code style={{ color: '#00f0ff' }}>/etc/nginx/nginx.conf</code>
        </span>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button icon={<CheckCircleOutlined />} loading={testing} onClick={handleTest}>
            测试配置
          </Button>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            loading={saving}
            onClick={handleSave}
            disabled={!!loadError && !content}
          >
            保存并生效
          </Button>
        </div>
      </div>

      {loadError && (
        <div style={{
          padding: '10px 14px',
          marginBottom: 12,
          borderRadius: 6,
          background: 'rgba(248,81,73,0.08)',
          border: '1px solid rgba(248,81,73,0.25)',
          color: '#f85149',
          fontSize: 13,
          lineHeight: '20px',
        }}>
          <strong>读取失败:</strong> {loadError}
          <div style={{ marginTop: 4, color: '#8b949e', fontSize: 12 }}>
            请确认 docker-compose.yml 中已为 mini-waf 容器挂载 <code>/var/run/docker.sock</code>
          </div>
        </div>
      )}

      {testResult && (
        <div style={{
          padding: '8px 12px',
          marginBottom: 12,
          borderRadius: 6,
          background: testResult.ok ? 'rgba(82,196,26,0.1)' : 'rgba(248,81,73,0.1)',
          border: `1px solid ${testResult.ok ? 'rgba(82,196,26,0.3)' : 'rgba(248,81,73,0.3)'}`,
          color: testResult.ok ? '#52c41a' : '#f85149',
          fontSize: 13,
        }}>
          {testResult.ok ? '✓' : '✗'} {testResult.msg}
        </div>
      )}

      <CodeEditor value={content} onChange={setContent} height={560} />
    </div>
  )
}

// ─── 站点配置 Tab ───────────────────────────────────

function SiteConfigsTab() {
  const [configs, setConfigs] = useState<NginxConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingFilename, setEditingFilename] = useState<string | null>(null)
  const [advancedMode, setAdvancedMode] = useState(false)
  const [rawContent, setRawContent] = useState('')
  const [form] = Form.useForm()

  const fetchConfigs = async () => {
    try {
      const res = await api.get('/nginx/configs')
      setConfigs(res.data.configs || [])
    } catch {
      // 拦截器已处理
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchConfigs() }, [])

  const openCreateModal = () => {
    setEditingFilename(null)
    setAdvancedMode(false)
    setRawContent('')
    form.resetFields()
    setModalOpen(true)
  }

  const openEditModal = (record: NginxConfig) => {
    form.setFieldsValue({
      listen_port: record.listen_port,
      site_name: record.site_name,
      server_name: record.server_name,
      root_path: record.root_path,
    })
    setRawContent(record.raw_content || '')
    setEditingFilename(record.filename)
    setAdvancedMode(false)
    setModalOpen(true)
  }

  const handleSubmit = async () => {
    try {
      if (advancedMode) {
        const port = form.getFieldValue('listen_port')
        if (!port) {
          message.error('请填写监听端口')
          return
        }
        if (editingFilename !== null) {
          await api.put('/nginx/configs', { old_filename: editingFilename, listen_port: port, raw_content: rawContent })
        } else {
          await api.post('/nginx/configs', { listen_port: port, raw_content: rawContent })
        }
      } else {
        const values = await form.validateFields()
        if (editingFilename !== null) {
          await api.put('/nginx/configs', { ...values, old_filename: editingFilename })
        } else {
          await api.post('/nginx/configs', values)
        }
      }
      // 成功走到这里说明拦截器没有 reject（status !== 'error'）
      message.success(editingFilename !== null ? '配置已更新' : '配置已创建')
      setModalOpen(false)
      setEditingFilename(null)
      form.resetFields()
      fetchConfigs()
    } catch {
      // 拦截器已处理 toast
    }
  }

  const handleDelete = async (filename: string) => {
    try {
      await api.delete('/nginx/configs', { data: { filename } })
      message.success('配置已删除')
      fetchConfigs()
    } catch {
      // 拦截器已处理
    }
  }

  const handleModeSwitch = (checked: boolean) => {
    if (checked && !rawContent.trim()) {
      const port = form.getFieldValue('listen_port') || 80
      const sn = form.getFieldValue('server_name') || '_'
      setRawContent(`server {
    listen ${port};
    server_name ${sn};

    location / {
        proxy_pass         http://mini-waf:48080;
        proxy_set_header   Host               $host;
        proxy_set_header   X-Real-IP          $remote_addr;
        proxy_set_header   X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto  $scheme;
    }
}
`)
    }
    setAdvancedMode(checked)
  }

  const columns = [
    {
      title: '监听端口',
      dataIndex: 'listen_port',
      key: 'listen_port',
      width: 120,
      render: (port: number) => <Tag color="cyan">{port}</Tag>,
    },
    {
      title: '站点名称',
      dataIndex: 'filename',
      key: 'filename',
      render: (name: string) => <code style={{ color: '#8b949e', fontSize: 12 }}>{name}</code>,
    },
    {
      title: '域名',
      dataIndex: 'server_name',
      key: 'server_name',
      render: (name: string | null) => name || <span style={{ color: '#8b949e' }}>_</span>,
    },
    {
      title: '路由引用',
      key: 'hint',
      width: 160,
      render: (_: any, record: NginxConfig) => (
        <Tag color="blue" style={{ fontFamily: 'monospace' }}>nginx:{record.listen_port}</Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_: any, record: NginxConfig) => (
        <div style={{ display: 'flex', gap: 8 }}>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEditModal(record)}>编辑</Button>
          <Popconfirm title="确定删除此站点配置？" onConfirm={() => handleDelete(record.filename)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </div>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{
          background: 'rgba(0,240,255,0.05)',
          border: '1px solid rgba(0,240,255,0.15)',
          borderRadius: 8,
          padding: '10px 16px',
          color: '#8b949e',
          fontSize: 13,
          flex: 1,
          marginRight: 12,
        }}>
          管理 Nginx 虚拟主机。在「站点管理」中，将路由的目标地址设为 <code style={{ color: '#00f0ff' }}>nginx:端口号</code> 即可。
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreateModal}>
          新增站点
        </Button>
      </div>

      <Table dataSource={configs} columns={columns} rowKey="listen_port" loading={loading} pagination={false} />

      <Modal
        title={
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingRight: 24 }}>
            <span>{editingFilename !== null ? '编辑站点配置' : '新增站点配置'}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 400 }}>
              <span style={{ color: '#8b949e' }}>高级模式</span>
              <Switch size="small" checked={advancedMode} onChange={handleModeSwitch} />
            </div>
          </div>
        }
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => { setModalOpen(false); setEditingFilename(null); form.resetFields(); setAdvancedMode(false); setRawContent('') }}
        okText="保存并生效"
        cancelText="取消"
        width={advancedMode ? 750 : 520}
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={{ listen_port: 8090 }}>
          <Form.Item name="listen_port" label="监听端口" rules={[{ required: true, message: '请输入端口号' }]}>
            <InputNumber min={1} max={65535} style={{ width: '100%' }} />
          </Form.Item>

          {!advancedMode ? (
            <>
              <Form.Item
                name="site_name"
                label="站点名称"
                extra="用于配置文件命名，留空时自动使用域名或端口号">
                <Input placeholder="例如: my-site（留空则自动推导）" />
              </Form.Item>
              <Form.Item name="server_name" label="域名 (可选)">
                <Input placeholder="example.com（留空则为通配）" />
              </Form.Item>
              <Form.Item
                name="root_path"
                label={
                  <span>
                    静态文件根目录
                    <span style={{ color: '#8b949e', fontSize: 12, fontWeight: 400, marginLeft: 8 }}>
                      （可选，留空则使用 WAF 反向代理模式）
                    </span>
                  </span>
                }
              >
                <Input placeholder="/usr/share/nginx/html（留空则为 WAF 代理模式）" />
              </Form.Item>
            </>
          ) : (
            <div style={{ marginBottom: 16 }}>
              <div style={{ marginBottom: 8, color: '#c9d1d9', fontSize: 13 }}>
                Nginx Server Block 配置
              </div>
              <CodeEditor value={rawContent} onChange={setRawContent} height={360} />
            </div>
          )}
        </Form>
      </Modal>
    </div>
  )
}

// ─── 主页面 ─────────────────────────────────────────

export default function NginxManagement() {
  return (
    <div>
      <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0, marginBottom: 16 }}>Nginx 配置管理</h2>
      <Tabs
        defaultActiveKey="sites"
        items={[
          { key: 'sites', label: '站点配置', children: <SiteConfigsTab /> },
          { key: 'main', label: '主配置文件', children: <MainConfEditor /> },
        ]}
      />
    </div>
  )
}
