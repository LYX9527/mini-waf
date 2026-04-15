import {
  Table, Button, Tag, Tabs, Form, Input, Select, Switch, Tooltip,
  Modal, Space, Badge, Alert, Upload, Card, Typography,
  Popconfirm, Progress, Drawer
} from 'antd'
import {
  LockOutlined, PlusOutlined, DeleteOutlined, ReloadOutlined,
  UploadOutlined, CopyOutlined, CheckCircleOutlined,
  WarningOutlined, CloseCircleOutlined, ThunderboltOutlined,
  SafetyCertificateOutlined, GlobalOutlined, InfoCircleOutlined,
  UserOutlined, StarOutlined, StarFilled, KeyOutlined,
} from '@ant-design/icons'
import { useEffect, useState, useRef } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

const { Text } = Typography

// ─── Interfaces ───────────────────────────────────────────────────────────────

interface CertItem {
  domain: string
  issuer: string
  not_before: string
  not_after: string
  days_remaining: number
  status: 'valid' | 'expiring' | 'expired'
  auto_renew: boolean
  acme_method: string
}

interface AcmeAccount {
  id: number
  name: string
  email: string
  acme_server: string
  is_default: boolean
  status: string
  note: string
  created_at: string
}

interface DnsCredential {
  id: number
  name: string
  provider: string
  note: string
  created_at: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  valid:    { color: '#3fb950', icon: <CheckCircleOutlined />, label: '有效' },
  expiring: { color: '#f0b72f', icon: <WarningOutlined />,     label: '即将到期' },
  expired:  { color: '#f85149', icon: <CloseCircleOutlined />, label: '已过期' },
}

const DNS_PROVIDERS = [
  { value: 'dns_cloudflare', label: 'Cloudflare DNS（支持通配符）' },
  { value: 'dns_dnspod',    label: 'DNSPod（腾讯云）DNS' },
  { value: 'dns_aliyun',    label: '阿里云 DNS' },
  { value: 'dns_he',        label: 'Hurricane Electric DNS' },
]

const DNS_PROVIDER_LABEL: Record<string, string> = {
  http01:        'HTTP-01',
  dns_cloudflare: 'Cloudflare',
  dns_dnspod:    'DNSPod',
  dns_aliyun:    '阿里云',
  dns_he:        'Hurricane Electric',
}

const DNS_CREDENTIAL_FIELDS: Record<string, { key: string; label: string; placeholder: string; hint?: string }[]> = {
  dns_cloudflare: [
    {
      key: 'CF_DNS_API_TOKEN',
      label: 'DNS API Token（DNS:Edit 权限）',
      placeholder: '仅需 Zone → DNS → Edit 权限的 API Token',
      hint: '在 Cloudflare 控制台 → My Profile → API Tokens → Create Token，选择"Edit zone DNS"模板',
    },
    {
      key: 'CF_ZONE_API_TOKEN',
      label: 'Zone API Token（Zone:Read 权限）',
      placeholder: '仅需 Zone → Zone → Read 权限的 API Token（可与 DNS Token 相同）',
      hint: '最小权限原则：与 DNS Token 分开，或使用同一个同时具有两种权限的 Token',
    },
  ],
  dns_dnspod:  [
    { key: 'DP_Id',  label: 'DNSPod ID',  placeholder: '你的 DNSPod ID' },
    { key: 'DP_Key', label: 'DNSPod Key', placeholder: '你的 DNSPod API Key' },
  ],
  dns_aliyun:  [
    { key: 'Ali_Key',    label: '阿里云 AccessKey ID',     placeholder: 'AccessKey ID' },
    { key: 'Ali_Secret', label: '阿里云 AccessKey Secret', placeholder: 'AccessKey Secret' },
  ],
  dns_he: [{ key: 'HE_Username', label: 'HE Username', placeholder: 'Hurricane Electric 账户' }],
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function SSLManagement() {
  // 证书列表
  const [certs, setCerts]         = useState<CertItem[]>([])
  const [loading, setLoading]     = useState(true)
  const [renewingDomain, setRenewingDomain] = useState<string | null>(null)

  // 申请证书 modal
  const [requestOpen, setRequestOpen] = useState(false)
  const [requesting, setRequesting]   = useState(false)
  const [requestForm]                  = Form.useForm()
  const [reqDnsCredId, setReqDnsCredId] = useState<number | null>(null)

  // 手动上传
  const [uploadOpen, setUploadOpen]   = useState(false)
  const [uploading, setUploading]     = useState(false)
  const certFileRef = useRef<File | null>(null)
  const keyFileRef  = useRef<File | null>(null)
  const [uploadDomain, setUploadDomain] = useState('')

  // Nginx 配置模板 modal
  const [templateModal, setTemplateModal] = useState<{ open: boolean; content: string; domain: string }>({ open: false, content: '', domain: '' })

  // ACME 账号
  const [accounts, setAccounts]       = useState<AcmeAccount[]>([])
  const [acctLoading, setAcctLoading] = useState(false)
  const [acctDrawer, setAcctDrawer]   = useState(false)
  const [editingAcct, setEditingAcct] = useState<AcmeAccount | null>(null)
  const [acctForm]                     = Form.useForm()

  // DNS 凭证
  const [dnsCredentials, setDnsCredentials]   = useState<DnsCredential[]>([])
  const [dnsLoading, setDnsLoading]           = useState(false)
  const [dnsDrawer, setDnsDrawer]             = useState(false)
  const [editingDns, setEditingDns]           = useState<DnsCredential | null>(null)
  const [dnsForm]                              = Form.useForm()
  const [dnsProvider, setDnsProvider]         = useState('dns_cloudflare')
  const [dnsCreds, setDnsCreds]               = useState<Record<string, string>>({})

  useEffect(() => { fetchCerts(); fetchAccounts(); fetchDnsCredentials() }, [])

  // ── 证书 ──────────────────────────────────────────────────────────────────

  const fetchCerts = async () => {
    setLoading(true)
    try { const res = await api.get('/ssl/certs'); setCerts(res.data.certs || []) }
    catch { console.error('fetch certs failed') }
    finally { setLoading(false) }
  }

  const handleDelete = async (domain: string) => {
    try { await api.delete(`/ssl/certs/${domain}`); message.success(`证书 ${domain} 已删除`); fetchCerts() }
    catch { message.error('删除失败') }
  }

  const handleRenew = async (domain: string) => {
    setRenewingDomain(domain); message.info(`正在续签 ${domain}，请稍候...`)
    try {
      const res = await api.post(`/ssl/certs/renew/${domain}`)
      res.data.status === 'success' ? message.success(res.data.message) : message.error(res.data.message)
      fetchCerts()
    } catch { message.error('续签失败') }
    finally { setRenewingDomain(null) }
  }

  const handleToggleRenew = async (domain: string, auto_renew: boolean) => {
    try { await api.post(`/ssl/certs/${domain}/toggle-renew`, { auto_renew }); message.success(auto_renew ? '已启用自动续签' : '已关闭自动续签'); fetchCerts() }
    catch { message.error('设置失败') }
  }

  const handleGetTemplate = async (domain: string) => {
    try { const res = await api.get(`/ssl/nginx-template/${domain}`); setTemplateModal({ open: true, content: res.data.template, domain }) }
    catch { message.error('获取模板失败') }
  }

  // ── 申请证书 ──────────────────────────────────────────────────────────────

  const handleRequestCert = async () => {
    try {
      const values = await requestForm.validateFields()
      setRequesting(true)
      const res = await api.post('/ssl/certs/request', {
        domain:            values.domain,
        wildcard:          values.wildcard || false,
        acme_account_id:   values.acme_account_id || undefined,
        dns_credential_id: reqDnsCredId || undefined,
      })
      if (res.data.status === 'success') {
        message.success(res.data.message)
        setRequestOpen(false); requestForm.resetFields(); setReqDnsCredId(null); fetchCerts()
      } else { message.error(res.data.message) }
    } catch { message.error('申请失败，请检查 ACME 账号配置') }
    finally { setRequesting(false) }
  }

  // ── 手动上传 ──────────────────────────────────────────────────────────────

  const handleUpload = async () => {
    if (!uploadDomain) { message.error('请输入域名'); return }
    if (!certFileRef.current) { message.error('请选择证书文件（fullchain.pem）'); return }
    if (!keyFileRef.current)  { message.error('请选择私钥文件（privkey.pem）'); return }
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('domain', uploadDomain)
      fd.append('cert', certFileRef.current)
      fd.append('key',  keyFileRef.current)
      const res = await api.post('/ssl/certs/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      if (res.data.status === 'success') {
        message.success(res.data.message)
        setUploadOpen(false); setUploadDomain(''); certFileRef.current = null; keyFileRef.current = null; fetchCerts()
      } else { message.error(res.data.message) }
    } catch { message.error('上传失败') }
    finally { setUploading(false) }
  }

  // ── ACME 账号 ─────────────────────────────────────────────────────────────

  const fetchAccounts = async () => {
    setAcctLoading(true)
    try { const res = await api.get('/ssl/acme/accounts'); setAccounts(res.data.accounts || []) }
    catch { console.error('fetch accounts failed') }
    finally { setAcctLoading(false) }
  }

  const openAcctDrawer = (acct?: AcmeAccount) => {
    setEditingAcct(acct || null)
    acctForm.resetFields()
    if (acct) {
      acctForm.setFieldsValue({ name: acct.name, email: acct.email, acme_server: acct.acme_server, is_default: acct.is_default, note: acct.note })
    } else {
      acctForm.setFieldsValue({ acme_server: 'https://acme-v02.api.letsencrypt.org/directory' })
    }
    setAcctDrawer(true)
  }

  const handleSaveAcct = async () => {
    try {
      const values = await acctForm.validateFields()
      if (editingAcct) { await api.put(`/ssl/acme/accounts/${editingAcct.id}`, values); message.success('ACME 账号已更新') }
      else { await api.post('/ssl/acme/accounts', values); message.success('ACME 账号已添加') }
      setAcctDrawer(false); fetchAccounts()
    } catch { message.error('保存失败') }
  }

  const handleDeleteAcct = async (id: number) => {
    await api.delete(`/ssl/acme/accounts/${id}`)
    message.success('账号已删除'); fetchAccounts()
  }

  const handleSetDefault = async (id: number) => {
    await api.post(`/ssl/acme/accounts/${id}/set-default`)
    message.success('已设为默认账号'); fetchAccounts()
  }

  // ── DNS 凭证 ──────────────────────────────────────────────────────────────

  const fetchDnsCredentials = async () => {
    setDnsLoading(true)
    try { const res = await api.get('/ssl/dns-credentials'); setDnsCredentials(res.data.credentials || []) }
    catch { console.error('fetch dns credentials failed') }
    finally { setDnsLoading(false) }
  }

  const openDnsDrawer = (cred?: DnsCredential) => {
    setEditingDns(cred || null)
    setDnsProvider('dns_cloudflare'); setDnsCreds({})
    dnsForm.resetFields()
    if (cred) {
      setDnsProvider(cred.provider)
      // 从后端获取凭证字段
      api.get(`/ssl/dns-credentials/${cred.id}/fields`).then(res => {
        try { setDnsCreds(JSON.parse(res.data.credentials_json || '{}')) } catch { setDnsCreds({}) }
        setDnsProvider(res.data.provider || cred.provider)
      }).catch(() => {})
      dnsForm.setFieldsValue({ name: cred.name, provider: cred.provider, note: cred.note })
    }
    setDnsDrawer(true)
  }

  const handleSaveDns = async () => {
    try {
      const values = await dnsForm.validateFields()
      const body = { ...values, credentials_json: JSON.stringify(dnsCreds) }
      if (editingDns) { await api.put(`/ssl/dns-credentials/${editingDns.id}`, body); message.success('DNS 凭证已更新') }
      else { await api.post('/ssl/dns-credentials', body); message.success('DNS 凭证已添加') }
      setDnsDrawer(false); fetchDnsCredentials()
    } catch { message.error('保存失败') }
  }

  const handleDeleteDns = async (id: number) => {
    await api.delete(`/ssl/dns-credentials/${id}`)
    message.success('DNS 凭证已删除'); fetchDnsCredentials()
  }

  // ─────────────────────────────────────────────────────────────────────────

  const certColumns = [
    {
      title: '域名', dataIndex: 'domain', key: 'domain',
      render: (d: string) => (
        <Space>
          <GlobalOutlined style={{ color: '#4493f8' }} />
          <Text style={{ color: '#c9d1d9', fontFamily: 'monospace' }}>{d}</Text>
        </Space>
      ),
    },
    {
      title: '颁发机构', dataIndex: 'issuer', key: 'issuer', ellipsis: true,
      render: (t: string) => <Text style={{ color: '#8b949e', fontSize: 12 }}>{t}</Text>,
    },
    {
      title: '到期时间', key: 'expiry',
      render: (r: CertItem) => {
        const cfg = STATUS_CONFIG[r.status]
        const pct = Math.min(100, Math.max(0, (r.days_remaining / 90) * 100))
        return (
          <div>
            <Space style={{ marginBottom: 4 }}>
              <span style={{ color: cfg.color }}>{cfg.icon}</span>
              <span style={{ color: cfg.color, fontSize: 12 }}>{cfg.label}</span>
              <Tag style={{ fontSize: 11, borderColor: cfg.color, color: cfg.color, background: 'transparent' }}>
                {r.days_remaining >= 0 ? `${r.days_remaining} 天` : '已过期'}
              </Tag>
            </Space>
            <Progress percent={Math.round(pct)} size="small" strokeColor={cfg.color} showInfo={false} style={{ margin: 0 }} />
            <div style={{ color: '#8b949e', fontSize: 11, marginTop: 2 }}>{r.not_after}</div>
          </div>
        )
      },
    },
    {
      title: '自动续签', key: 'auto_renew', width: 95,
      render: (r: CertItem) => (
        <Switch size="small" checked={r.auto_renew} onChange={(v) => handleToggleRenew(r.domain, v)} checkedChildren="开" unCheckedChildren="关" />
      ),
    },
    {
      title: '操作', key: 'action', width: 220,
      render: (r: CertItem) => (
        <Space size={6}>
          <Tooltip title="生成 Nginx SSL 配置">
            <Button size="small" icon={<SafetyCertificateOutlined />} onClick={() => handleGetTemplate(r.domain)}>配置</Button>
          </Tooltip>
          <Tooltip title="立即续签">
            <Button size="small" icon={<ReloadOutlined />} loading={renewingDomain === r.domain} onClick={() => handleRenew(r.domain)}>续签</Button>
          </Tooltip>
          <Popconfirm title={`确定删除 ${r.domain} 的证书？`} onConfirm={() => handleDelete(r.domain)} okText="删除" cancelText="取消" okType="danger">
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div>
      {/* 顶部标题栏 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <Space>
          <LockOutlined style={{ color: '#4493f8', fontSize: 20 }} />
          <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0 }}>SSL 证书管理</h2>
          <Tag color="blue">{certs.length} 张证书</Tag>
          {certs.some(c => c.status === 'expiring') && <Tag color="orange">有证书即将到期</Tag>}
          {certs.some(c => c.status === 'expired')  && <Tag color="red">有证书已过期</Tag>}
        </Space>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchCerts} loading={loading} />
          <Button icon={<UploadOutlined />} onClick={() => setUploadOpen(true)}>手动上传证书</Button>
          <Button type="primary" icon={<ThunderboltOutlined />} onClick={() => setRequestOpen(true)}>申请 Let's Encrypt</Button>
        </Space>
      </div>

      <Tabs defaultActiveKey="certs" items={[
        {
          key: 'certs',
          label: <span><SafetyCertificateOutlined />证书列表</span>,
          children: (
            <Table
              dataSource={certs.map(c => ({ ...c, key: c.domain }))}
              columns={certColumns} loading={loading} pagination={false} size="middle"
              locale={{ emptyText: "暂无 SSL 证书，点击右上角「申请 Let's Encrypt」或「手动上传证书」" }}
            />
          ),
        },
        {
          key: 'dns',
          label: (
            <span>
              <KeyOutlined />DNS 凭证
              {dnsCredentials.length > 0 && <Tag style={{ marginLeft: 6, fontSize: 10 }}>{dnsCredentials.length}</Tag>}
            </span>
          ),
          children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Alert type="info" showIcon style={{ flex: 1, marginRight: 16 }}
                  message="DNS 凭证用于让 ACME 自动向 DNS 提供商添加 TXT 验证记录，支持通配符证书。凭证安全存储在数据库，不对外暴露。" />
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openDnsDrawer()}>添加凭证</Button>
              </div>
              <Table
                dataSource={dnsCredentials.map(c => ({ ...c, key: c.id }))}
                loading={dnsLoading} pagination={false} size="middle"
                locale={{ emptyText: '暂无 DNS 凭证，点击「添加凭证」开始' }}
                columns={[
                  {
                    title: '凭证名称', dataIndex: 'name',
                    render: (n: string) => <span style={{ color: '#c9d1d9' }}>{n}</span>,
                  },
                  {
                    title: 'DNS 提供商', dataIndex: 'provider', width: 160,
                    render: (p: string) => <Tag color="blue">{DNS_PROVIDER_LABEL[p] || p}</Tag>,
                  },
                  {
                    title: '备注', dataIndex: 'note',
                    render: (n: string) => <span style={{ color: '#8b949e', fontSize: 12 }}>{n || '—'}</span>,
                  },
                  {
                    title: '创建时间', dataIndex: 'created_at', width: 170,
                    render: (t: string) => <span style={{ color: '#8b949e', fontSize: 12 }}>{t.slice(0, 19)}</span>,
                  },
                  {
                    title: '操作', width: 140,
                    render: (r: DnsCredential) => (
                      <Space size={6}>
                        <Button size="small" onClick={() => openDnsDrawer(r)}>编辑</Button>
                        <Popconfirm title={`确定删除凭证「${r.name}」？`} onConfirm={() => handleDeleteDns(r.id)} okText="删除" cancelText="取消" okType="danger">
                          <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
                        </Popconfirm>
                      </Space>
                    ),
                  },
                ]}
              />
            </div>
          ),
        },
        {
          key: 'accounts',
          label: (
            <span>
              <UserOutlined />ACME 账号
              {accounts.length > 0 && <Tag style={{ marginLeft: 6, fontSize: 10 }}>{accounts.length}</Tag>}
            </span>
          ),
          children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <span style={{ color: '#8b949e', fontSize: 13 }}>支持配置多个 ACME 账号（邮箱 + CA 服务器），申请证书时选择使用哪个账号</span>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openAcctDrawer()}>添加账号</Button>
              </div>
              <Table
                dataSource={accounts.map(a => ({ ...a, key: a.id }))}
                loading={acctLoading} pagination={false} size="middle"
                locale={{ emptyText: '暂无 ACME 账号，点击「添加账号」开始' }}
                columns={[
                  {
                    title: '账号别名', dataIndex: 'name',
                    render: (n: string, r: AcmeAccount) => (
                      <Space>
                        {r.is_default ? <StarFilled style={{ color: '#f0b72f' }} /> : <StarOutlined style={{ color: '#484f58' }} />}
                        <span style={{ color: '#c9d1d9' }}>{n}</span>
                        {r.is_default && <Tag color="gold" style={{ fontSize: 10 }}>默认</Tag>}
                      </Space>
                    ),
                  },
                  {
                    title: '邮箱', dataIndex: 'email',
                    render: (e: string) => <span style={{ color: '#8b949e', fontFamily: 'monospace' }}>{e}</span>,
                  },
                  {
                    title: 'ACME 服务器', dataIndex: 'acme_server', ellipsis: true,
                    render: (s: string) => {
                      const label = s.includes('staging') ? "Let's Encrypt 测试" : s.includes('letsencrypt') ? "Let's Encrypt 正式" : s.includes('zerossl') ? 'ZeroSSL' : s
                      return <span style={{ color: '#8b949e', fontSize: 12 }}>{label}</span>
                    },
                  },
                  {
                    title: '状态', dataIndex: 'status', width: 80,
                    render: (s: string) => <Badge status={s === 'active' ? 'success' : 'default'} text={s === 'active' ? '活跃' : '已停用'} />,
                  },
                  {
                    title: '操作', width: 220,
                    render: (r: AcmeAccount) => (
                      <Space size={6}>
                        {!r.is_default && (
                          <Tooltip title="设为默认账号">
                            <Button size="small" icon={<StarOutlined />} onClick={() => handleSetDefault(r.id)}>设为默认</Button>
                          </Tooltip>
                        )}
                        <Button size="small" onClick={() => openAcctDrawer(r)}>编辑</Button>
                        <Popconfirm title={`确定删除账号「${r.name}」？`} onConfirm={() => handleDeleteAcct(r.id)} okText="删除" cancelText="取消" okType="danger">
                          <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
                        </Popconfirm>
                      </Space>
                    ),
                  },
                ]}
              />
            </div>
          ),
        },
      ]} />

      {/* ── 申请证书 Modal ────────────────────────────────────────────────── */}
      <Modal
        title={<Space><ThunderboltOutlined style={{ color: '#4493f8' }} />申请 Let's Encrypt 免费证书</Space>}
        open={requestOpen} onOk={handleRequestCert} confirmLoading={requesting}
        onCancel={() => { setRequestOpen(false); requestForm.resetFields(); setReqDnsCredId(null) }}
        okText="开始申请" cancelText="取消" width={540}
      >
        <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="申请过程可能需要 1-3 分钟，请耐心等待" />
        <Form form={requestForm} layout="vertical" initialValues={{ wildcard: false }}>
          <Form.Item name="domain" label="域名" rules={[{ required: true, message: '请输入域名' }]}
            extra={<span style={{ color: '#8b949e', fontSize: 12 }}>如 <code>example.com</code> 或 <code>api.example.com</code></span>}>
            <Input placeholder="example.com" />
          </Form.Item>

          <Form.Item name="acme_account_id" label="ACME 用户"
            rules={[{ required: accounts.length > 0, message: '请选择 ACME 账号' }]}
            extra={accounts.length === 0
              ? <span style={{ color: '#f85149', fontSize: 12 }}>暂无 ACME 账号，请先在「ACME 账号」页面添加</span>
              : undefined}>
            <Select placeholder="选择 ACME 账号" allowClear
              options={accounts.map(a => ({
                value: a.id,
                label: (
                  <span>
                    {a.is_default && <StarFilled style={{ color: '#f0b72f', marginRight: 6 }} />}
                    {a.name} <span style={{ color: '#8b949e', fontSize: 11 }}>({a.email})</span>
                  </span>
                ),
              }))}
            />
          </Form.Item>

          <Form.Item name="dns_credential_id" label="DNS 凭证"
            extra={<span style={{ color: '#8b949e', fontSize: 12 }}>通配符证书必须选择 DNS 凭证；单域名留空则使用 HTTP-01 验证</span>}>
            <Select placeholder="留空使用 HTTP-01（单域名）" allowClear
              onChange={(v) => setReqDnsCredId(v || null)}
              options={dnsCredentials.map(c => ({
                value: c.id,
                label: <span>{c.name} <Tag color="blue" style={{ fontSize: 10 }}>{DNS_PROVIDER_LABEL[c.provider] || c.provider}</Tag></span>,
              }))}
            />
          </Form.Item>

          <Form.Item name="wildcard" valuePropName="checked" label="通配符证书"
            extra={<span style={{ color: '#8b949e', fontSize: 12 }}>通配符证书（*.example.com）需要使用 DNS 验证</span>}>
            <Switch checkedChildren="*.域名" unCheckedChildren="单域名" />
          </Form.Item>
        </Form>
      </Modal>

      {/* ── 手动上传 Modal ────────────────────────────────────────────────── */}
      <Modal
        title={<Space><UploadOutlined style={{ color: '#4493f8' }} />手动上传 SSL 证书</Space>}
        open={uploadOpen} onOk={handleUpload} confirmLoading={uploading}
        onCancel={() => { setUploadOpen(false); setUploadDomain(''); certFileRef.current = null; keyFileRef.current = null }}
        okText="上传" cancelText="取消" width={520}
      >
        <Alert type="info" showIcon style={{ marginBottom: 16 }}
          message="请上传完整证书链文件（fullchain.pem）和私钥文件（privkey.pem），支持 Let's Encrypt、ZeroSSL、商业 CA 等" />
        <Form layout="vertical">
          <Form.Item label="域名" required>
            <Input value={uploadDomain} onChange={e => setUploadDomain(e.target.value)} placeholder="example.com" />
          </Form.Item>
          <Form.Item label="证书文件（fullchain.pem）" required>
            <Upload accept=".pem,.crt,.cer" beforeUpload={(file) => { certFileRef.current = file; return false }} maxCount={1}>
              <Button icon={<UploadOutlined />}>选择证书文件</Button>
            </Upload>
          </Form.Item>
          <Form.Item label="私钥文件（privkey.pem）" required>
            <Upload accept=".pem,.key" beforeUpload={(file) => { keyFileRef.current = file; return false }} maxCount={1}>
              <Button icon={<UploadOutlined />}>选择私钥文件</Button>
            </Upload>
          </Form.Item>
          <Alert type="warning" showIcon message="私钥文件仅存储在服务器本地（600权限），不会通过 API 对外暴露" />
        </Form>
      </Modal>

      {/* ── Nginx SSL 配置模板 Modal ──────────────────────────────────────── */}
      <Modal
        title={<Space><SafetyCertificateOutlined style={{ color: '#3fb950' }} />Nginx SSL 配置 — {templateModal.domain}</Space>}
        open={templateModal.open}
        onCancel={() => setTemplateModal({ open: false, content: '', domain: '' })}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} type="primary" onClick={() => { navigator.clipboard.writeText(templateModal.content); message.success('已复制到剪贴板') }}>复制配置</Button>,
          <Button key="close" onClick={() => setTemplateModal({ open: false, content: '', domain: '' })}>关闭</Button>,
        ]}
        width={700}
      >
        <Alert type="success" showIcon style={{ marginBottom: 12 }} message="复制以下配置，粘贴到「Nginx 配置」→「主配置文件」的 http {} 块内，然后点击保存并重载" />
        <div style={{ background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: 16, fontFamily: 'monospace', fontSize: 12, color: '#c9d1d9', whiteSpace: 'pre', overflowX: 'auto', maxHeight: 400, overflowY: 'auto' }}>
          {templateModal.content}
        </div>
      </Modal>

      {/* ── ACME 账号 Drawer ─────────────────────────────────────────────── */}
      <Drawer
        title={<Space><UserOutlined style={{ color: '#4493f8' }} />{editingAcct ? `编辑账号 — ${editingAcct.name}` : '添加 ACME 账号'}</Space>}
        open={acctDrawer} onClose={() => setAcctDrawer(false)} width={480}
        footer={<Space style={{ float: 'right' }}>
          <Button onClick={() => setAcctDrawer(false)}>取消</Button>
          <Button type="primary" onClick={handleSaveAcct}>{editingAcct ? '保存修改' : '创建账号'}</Button>
        </Space>}
      >
        <Form form={acctForm} layout="vertical">
          <Form.Item name="name" label="账号别名" rules={[{ required: true, message: '请输入别名' }]}>
            <Input placeholder="如「生产环境 Let's Encrypt」" />
          </Form.Item>
          <Form.Item name="email" label="联系邮箱" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
            <Input placeholder="admin@example.com" />
          </Form.Item>
          <Form.Item name="acme_server" label="ACME 服务器">
            <Select options={[
              { value: 'https://acme-v02.api.letsencrypt.org/directory', label: "Let's Encrypt 正式版" },
              { value: 'https://acme-staging-v02.api.letsencrypt.org/directory', label: "Let's Encrypt 测试版 (Staging)" },
              { value: 'https://acme.zerossl.com/v2/DV90', label: 'ZeroSSL' },
            ]} />
          </Form.Item>
          <Form.Item name="is_default" valuePropName="checked" label="设为默认账号">
            <Switch checkedChildren="默认" unCheckedChildren="非默认" />
          </Form.Item>
          <Form.Item name="note" label="备注">
            <Input.TextArea rows={2} placeholder="可选备注，如用途或所属客户" />
          </Form.Item>
        </Form>
      </Drawer>

      {/* ── DNS 凭证 Drawer ───────────────────────────────────────────────── */}
      <Drawer
        title={<Space><KeyOutlined style={{ color: '#4493f8' }} />{editingDns ? `编辑凭证 — ${editingDns.name}` : '添加 DNS 凭证'}</Space>}
        open={dnsDrawer} onClose={() => setDnsDrawer(false)} width={520}
        footer={<Space style={{ float: 'right' }}>
          <Button onClick={() => setDnsDrawer(false)}>取消</Button>
          <Button type="primary" onClick={handleSaveDns}>{editingDns ? '保存修改' : '创建凭证'}</Button>
        </Space>}
      >
        <Form form={dnsForm} layout="vertical">
          <Form.Item name="name" label="凭证别名" rules={[{ required: true, message: '请输入别名' }]}>
            <Input placeholder="如「生产环境 Cloudflare」" />
          </Form.Item>
          <Form.Item name="provider" label="DNS 提供商" rules={[{ required: true, message: '请选择提供商' }]}>
            <Select options={DNS_PROVIDERS} onChange={(v) => { setDnsProvider(v); setDnsCreds({}) }} />
          </Form.Item>

          {DNS_CREDENTIAL_FIELDS[dnsProvider]?.length > 0 && (
            <Card size="small" style={{ marginBottom: 16, background: 'rgba(0,240,255,0.04)', borderColor: 'rgba(0,240,255,0.12)' }}>
              <div style={{ color: '#8b949e', fontSize: 12, marginBottom: 10 }}>
                <InfoCircleOutlined style={{ marginRight: 6 }} />DNS 凭证（安全存储在数据库，不对外暴露）
              </div>
              {DNS_CREDENTIAL_FIELDS[dnsProvider].map(field => (
                <Form.Item key={field.key} label={field.label} style={{ marginBottom: 10 }}
                  extra={field.hint ? <span style={{ color: '#8b949e', fontSize: 11 }}>{field.hint}</span> : undefined}>
                  <Input.Password
                    value={dnsCreds[field.key] || ''}
                    placeholder={field.placeholder}
                    onChange={e => setDnsCreds(prev => ({ ...prev, [field.key]: e.target.value }))}
                  />
                </Form.Item>
              ))}
            </Card>
          )}

          <Form.Item name="note" label="备注">
            <Input.TextArea rows={2} placeholder="可选备注，如用途或对应域名范围" />
          </Form.Item>
        </Form>
      </Drawer>
    </div>
  )
}
