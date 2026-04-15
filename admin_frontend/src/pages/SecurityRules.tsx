import {
  Table, Button, Modal, Form, Input, Select, Tag, Popconfirm,
  Tooltip, Badge, Tabs, Space, Drawer, Divider, Progress, Alert
} from 'antd'
import {
  PlusOutlined, DeleteOutlined, DownloadOutlined, UploadOutlined,
  ThunderboltOutlined, EyeOutlined, SafetyCertificateOutlined,
  ReloadOutlined, InfoCircleOutlined
} from '@ant-design/icons'
import { useEffect, useState, useRef } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

const TARGET_COLORS: Record<string, string> = {
  URL: 'blue',
  Header: 'cyan',
  'User-Agent': 'geekblue',
}
const MATCH_COLORS: Record<string, string> = {
  Contains: 'orange',
  Exact: 'gold',
  Regex: 'purple',
}
const CATEGORY_COLORS: Record<string, string> = {
  'SQL 注入': '#f5222d',
  'XSS': '#fa541c',
  '路径穿越': '#fa8c16',
  'RCE': '#d4380d',
  'SSRF': '#9254de',
  'Log4Shell': '#c41d7f',
  '扫描器': '#1677ff',
  '敏感文件探测': '#52c41a',
}

function guessCategory(desc: string): string {
  if (desc.includes('SQL')) return 'SQL 注入'
  if (desc.includes('XSS')) return 'XSS'
  if (desc.includes('路径穿越')) return '路径穿越'
  if (desc.includes('RCE') || desc.includes('PHP') || desc.includes('命令')) return 'RCE'
  if (desc.includes('SSRF')) return 'SSRF'
  if (desc.includes('Log4')) return 'Log4Shell'
  if (desc.includes('扫描器')) return '扫描器'
  return '敏感文件探测'
}

export default function SecurityRules() {
  const [rules, setRules] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [defaultDrawerOpen, setDefaultDrawerOpen] = useState(false)
  const [defaultRules, setDefaultRules] = useState<any[]>([])
  const [defaultLoading, setDefaultLoading] = useState(false)
  const [loadingDefaults, setLoadingDefaults] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<any>(null)
  const [form] = Form.useForm()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const fetchRules = async () => {
    setLoading(true)
    try {
      const res = await api.get('/rules')
      setRules(res.data.rules || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const fetchDefaultRules = async () => {
    setDefaultLoading(true)
    try {
      const res = await api.get('/rules/defaults')
      setDefaultRules(res.data.rules || [])
    } catch (e) {
      console.error(e)
    } finally {
      setDefaultLoading(false)
    }
  }

  useEffect(() => { fetchRules() }, [])

  const handleAdd = async () => {
    try {
      const values = await form.validateFields()
      await api.post('/rules', {
        rule: values.rule,
        target_field: values.target_field || 'URL',
        match_type: values.match_type || 'Contains'
      })
      message.success('规则添加成功')
      setAddOpen(false)
      form.resetFields()
      fetchRules()
    } catch {
      // 拦截器已处理
    }
  }

  const handleDelete = async (rule: string) => {
    try {
      await api.delete('/rules', { data: { rule } })
      message.success('规则已删除')
      fetchRules()
    } catch {
      // 拦截器已处理
    }
  }

  // 导出规则为 JSON 文件
  const handleExport = async () => {
    try {
      const res = await api.get('/rules/export')
      const data = JSON.stringify({ rules: res.data.rules }, null, 2)
      const blob = new Blob([data], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mini-waf-rules-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      message.success(`已导出 ${res.data.count} 条规则`)
    } catch {
      message.error('导出失败')
    }
  }

  // 导入本地 JSON 文件
  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true)
    setImportResult(null)
    try {
      const text = await file.text()
      const json = JSON.parse(text)
      const rules = json.rules || json
      if (!Array.isArray(rules)) { message.error('文件格式错误：需要包含 rules 数组'); return }
      const res = await api.post('/rules/import', { rules, replace_all: false })
      setImportResult(res.data)
      message.success(res.data.message)
      fetchRules()
    } catch (err: any) {
      message.error(err?.response?.data?.message || '导入失败')
    } finally {
      setImporting(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  // 一键加载默认规则集
  const handleLoadDefaults = async () => {
    setLoadingDefaults(true)
    try {
      const res = await api.post('/rules/load-defaults')
      message.success(res.data.message)
      setImportResult(res.data)
      fetchRules()
      setDefaultDrawerOpen(false)
    } catch {
      message.error('加载默认规则失败')
    } finally {
      setLoadingDefaults(false)
    }
  }

  const columns = [
    {
      title: '#',
      key: 'index',
      width: 55,
      render: (_: any, __: any, index: number) => (
        <span style={{ color: '#8b949e', fontSize: 12 }}>{index + 1}</span>
      ),
    },
    {
      title: '规则内容',
      dataIndex: 'keyword',
      key: 'keyword',
      render: (keyword: string) => (
        <Tag color="red" style={{ fontFamily: 'monospace', fontSize: 12 }}>{keyword}</Tag>
      ),
    },
    {
      title: '目标区域',
      dataIndex: 'target_field',
      key: 'target_field',
      width: 130,
      render: (text: string) => (
        <Tag color={TARGET_COLORS[text] || 'blue'}>{text || 'URL'}</Tag>
      ),
    },
    {
      title: '匹配模式',
      dataIndex: 'match_type',
      key: 'match_type',
      width: 130,
      render: (text: string) => (
        <Tag color={MATCH_COLORS[text] || 'orange'}>{text || 'Contains'}</Tag>
      ),
    },
    {
      title: '状态',
      key: 'status',
      width: 80,
      render: () => <Badge status="success" text={<span style={{ color: '#3fb950', fontSize: 12 }}>启用</span>} />,
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      render: (_: any, record: any) => (
        <Popconfirm title="确定删除此规则？" onConfirm={() => handleDelete(record.keyword)}
          okText="删除" cancelText="取消" okType="danger">
          <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ]

  const defaultColumns = [
    {
      title: '规则内容',
      dataIndex: 'keyword',
      key: 'keyword',
      render: (k: string) => <Tag color="red" style={{ fontFamily: 'monospace', fontSize: 12 }}>{k}</Tag>,
    },
    {
      title: '说明',
      dataIndex: 'description',
      key: 'description',
      render: (d: string) => {
        const cat = guessCategory(d)
        return (
          <Space>
            <Tag color={CATEGORY_COLORS[cat] || 'default'} style={{ fontSize: 11 }}>{cat}</Tag>
            <span style={{ color: '#8b949e', fontSize: 12 }}>{d}</span>
          </Space>
        )
      },
    },
    {
      title: '目标',
      dataIndex: 'target_field',
      width: 110,
      render: (t: string) => <Tag color={TARGET_COLORS[t] || 'blue'} style={{ fontSize: 11 }}>{t}</Tag>,
    },
    {
      title: '模式',
      dataIndex: 'match_type',
      width: 100,
      render: (m: string) => <Tag color={MATCH_COLORS[m] || 'orange'} style={{ fontSize: 11 }}>{m}</Tag>,
    },
  ]

  // 按类别分组统计
  const categoryCounts = defaultRules.reduce((acc: Record<string, number>, r) => {
    const cat = guessCategory(r.description || '')
    acc[cat] = (acc[cat] || 0) + 1
    return acc
  }, {})

  const existingKeywords = new Set(rules.map(r => r.keyword))
  const newCount = defaultRules.filter(r => !existingKeywords.has(r.keyword)).length

  return (
    <div>
      {/* 顶部操作栏 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <SafetyCertificateOutlined style={{ color: '#4493f8', fontSize: 20 }} />
          <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0 }}>安全规则</h2>
          <Tag color="blue" style={{ marginLeft: 4 }}>{rules.length} 条</Tag>
        </div>
        <Space>
          {/* 默认规则集 */}
          <Tooltip title="查看并加载内置 OWASP Top10 规则集">
            <Button
              icon={<ThunderboltOutlined />}
              style={{ borderColor: '#f0b72f', color: '#f0b72f' }}
              onClick={() => { setDefaultDrawerOpen(true); fetchDefaultRules() }}
            >
              默认规则集
            </Button>
          </Tooltip>
          {/* 导入 */}
          <Tooltip title="从本地 JSON 文件导入规则">
            <Button
              icon={<UploadOutlined />}
              loading={importing}
              onClick={() => fileInputRef.current?.click()}
            >
              导入
            </Button>
          </Tooltip>
          <input ref={fileInputRef} type="file" accept=".json" style={{ display: 'none' }} onChange={handleImportFile} />
          {/* 导出 */}
          <Tooltip title="将所有规则导出为 JSON 文件">
            <Button icon={<DownloadOutlined />} onClick={handleExport}>
              导出
            </Button>
          </Tooltip>
          {/* 刷新 */}
          <Button icon={<ReloadOutlined />} onClick={fetchRules} loading={loading} />
          {/* 新增 */}
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>
            添加规则
          </Button>
        </Space>
      </div>

      {/* 导入结果提示 */}
      {importResult && (
        <Alert
          style={{ marginBottom: 12 }}
          type={importResult.status === 'success' ? 'success' : 'warning'}
          message={importResult.message}
          description={importResult.errors?.length > 0 ? (
            <div style={{ marginTop: 4, fontSize: 12, color: '#f85149' }}>
              {importResult.errors.slice(0, 5).join('\n')}
            </div>
          ) : undefined}
          closable
          onClose={() => setImportResult(null)}
          showIcon
        />
      )}

      {/* 规则列表 */}
      <Table
        dataSource={rules.map((r, i) => ({ ...r, key: `${r.keyword}-${i}` }))}
        columns={columns}
        loading={loading}
        pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条规则` }}
        size="middle"
        style={{ background: 'transparent' }}
      />

      {/* 新增规则弹窗 */}
      <Modal
        title={<span><PlusOutlined style={{ marginRight: 8, color: '#4493f8' }} />添加安全规则</span>}
        open={addOpen}
        onOk={handleAdd}
        onCancel={() => { setAddOpen(false); form.resetFields() }}
        okText="添加" cancelText="取消"
      >
        <Form form={form} layout="vertical">
          <Form.Item name="target_field" label="匹配目标" initialValue="URL">
            <Select>
              <Select.Option value="URL">URL / Query 参数</Select.Option>
              <Select.Option value="Header">所有请求头 (Headers)</Select.Option>
              <Select.Option value="User-Agent">User-Agent</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="match_type" label="匹配模式" initialValue="Contains">
            <Select>
              <Select.Option value="Contains">部分包含 (Contains) — 推荐</Select.Option>
              <Select.Option value="Exact">完全相等 (Exact)</Select.Option>
              <Select.Option value="Regex">正则表达式 (Regex)</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="rule"
            label="规则内容 / 正则表达式"
            rules={[{ required: true, message: '请输入规则内容' }]}
            extra={<span style={{ color: '#8b949e', fontSize: 12 }}><InfoCircleOutlined style={{ marginRight: 4 }} />Contains: 填关键词如 <code>../</code>；Regex: 填如 <code>{'(?i)union.{0,10}select'}</code></span>}
          >
            <Input placeholder="如: union select  /  ../  /  <script" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 默认规则集抽屉 */}
      <Drawer
        title={
          <Space>
            <ThunderboltOutlined style={{ color: '#f0b72f' }} />
            <span>内置 OWASP Top10 规则集</span>
            <Tag color="gold">{defaultRules.length} 条</Tag>
          </Space>
        }
        open={defaultDrawerOpen}
        onClose={() => setDefaultDrawerOpen(false)}
        width={800}
        extra={
          <Space>
            <Tooltip title="将所有默认规则导入到系统（已存在的自动跳过）">
              <Button
                type="primary"
                icon={<ThunderboltOutlined />}
                loading={loadingDefaults}
                onClick={handleLoadDefaults}
                style={{ background: '#f0b72f', borderColor: '#f0b72f', color: '#000' }}
              >
                一键加载全部（{newCount} 条新规则）
              </Button>
            </Tooltip>
          </Space>
        }
      >
        {/* 类别统计 */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: '#8b949e', fontSize: 12, marginBottom: 8 }}>覆盖攻击类型</div>
          <Space wrap>
            {Object.entries(categoryCounts).map(([cat, count]) => (
              <Tag key={cat} color={CATEGORY_COLORS[cat] || 'default'}>
                {cat} × {count}
              </Tag>
            ))}
          </Space>
        </div>

        {newCount > 0 && (
          <Alert
            style={{ marginBottom: 12 }}
            type="info"
            showIcon
            message={`当前系统中有 ${newCount} 条默认规则尚未导入`}
          />
        )}

        <Table
          dataSource={defaultRules.map((r, i) => ({
            ...r,
            key: i,
            _exists: existingKeywords.has(r.keyword),
          }))}
          columns={[
            ...defaultColumns,
            {
              title: '状态',
              key: 'status',
              width: 80,
              render: (_: any, record: any) => record._exists
                ? <Tag color="green" style={{ fontSize: 11 }}>已导入</Tag>
                : <Tag style={{ fontSize: 11 }}>未导入</Tag>,
            },
          ]}
          loading={defaultLoading}
          pagination={false}
          size="small"
          rowClassName={(r: any) => r._exists ? 'rule-exists' : ''}
        />
      </Drawer>
    </div>
  )
}
