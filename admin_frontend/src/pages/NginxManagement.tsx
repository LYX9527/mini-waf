import { Table, Button, Modal, Form, Input, InputNumber, Popconfirm, Tag, Tabs, Switch, Spin, Space, AutoComplete } from 'antd'
import { PlusOutlined, DeleteOutlined, EditOutlined, CheckCircleOutlined, SaveOutlined, MinusCircleOutlined } from '@ant-design/icons'
import Editor from '@monaco-editor/react'
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
  return (
    <div style={{
      border: '1px solid #30363d',
      borderRadius: 6,
      overflow: 'hidden',
    }}>
      <Editor
        height={height}
        defaultLanguage="nginx"
        theme="vs-dark"
        value={value}
        onChange={(val) => onChange?.(val || '')}
        beforeMount={handleEditorWillMount}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
          scrollBeyondLastLine: false,
          automaticLayout: true,
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

const PRESET_KEYS = [
  { value: 'listen' },
  { value: 'server_name' },
  { value: 'proxy_pass' },
  { value: 'root' },
  { value: 'index' },
  { value: 'try_files' },
  { value: 'return' },
  { value: 'rewrite' },
  { value: 'ssl_certificate' },
  { value: 'ssl_certificate_key' },
  { value: 'access_log' },
  { value: 'error_log' },
];

const handleEditorWillMount = (monaco: any) => {
  // 防止在 React StrictMode 或 HMR 时重复注册导致报错
  if (monaco.languages.getLanguages().some((l: any) => l.id === 'nginx')) {
    return;
  }

  monaco.languages.register({ id: 'nginx' });

  monaco.languages.setMonarchTokensProvider('nginx', {
    keywords: PRESET_KEYS.map(k => k.value).concat([
      'server', 'location', 'events', 'http', 'worker_processes', 
      'worker_connections', 'client_max_body_size', 'upstream', 
      'log_format', 'sendfile', 'keepalive_timeout'
    ]),
    tokenizer: {
      root: [
        [/[a-zA-Z_]\w*/, {
          cases: {
            '@keywords': 'keyword',
            '@default': 'identifier'
          }
        }],
        [/#.*/, 'comment'],
        [/"([^"\\]|\\.)*$/, 'string.invalid'],
        [/"/, 'string', '@string'],
        [/'([^'\\]|\\.)*$/, 'string.invalid'],
        [/'/, 'string', '@string2'],
        [/\d+/, 'number'],
        [/[{}()\[\]]/, '@brackets'],
        [/[;,.]/, 'delimiter']
      ],
      string: [
        [/[^\\"]+/, 'string'],
        [/\\./, 'string.escape.invalid'],
        [/"/, 'string', '@pop']
      ],
      string2: [
        [/[^\\']+/, 'string'],
        [/\\./, 'string.escape.invalid'],
        [/'/, 'string', '@pop']
      ]
    }
  });

  monaco.languages.registerCompletionItemProvider('nginx', {
    provideCompletionItems: (model: any, position: any) => {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };
      
      const suggestions = PRESET_KEYS.map(k => ({
        label: k.value,
        kind: monaco.languages.CompletionItemKind.Keyword,
        insertText: k.value,
        range: range
      })).concat(['server', 'location', 'events', 'http'].map(k => ({
        label: k,
        kind: monaco.languages.CompletionItemKind.Keyword,
        insertText: k,
        range: range
      })));
      return { suggestions };
    }
  });
};

const generateRawContent = (directives: { key: string; value: string }[]) => {
  let content = "server {\n";
  for (const d of directives) {
    if (!d || !d.key) continue;
    content += `    ${d.key} ${d.value};\n`;
  }
  content += "}\n";
  return content;
}

const parseDirectives = (raw: string) => {
  const lines = raw.split('\n');
  const directives = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line === 'server {' || line === '}') continue;
    const match = line.match(/^([a-zA-Z0-9_]+)\s+(.+);$/);
    if (match) {
      directives.push({ key: match[1], value: match[2] });
    }
  }
  return directives.length > 0 ? directives : [{ key: 'listen', value: '8090' }];
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
    form.setFieldsValue({ directives: [{ key: 'listen', value: '8090' }] })
    setModalOpen(true)
  }

  const openEditModal = (record: NginxConfig) => {
    setRawContent(record.raw_content || '')
    const directives = parseDirectives(record.raw_content || '')
    form.setFieldsValue({ directives })
    setEditingFilename(record.filename)
    setAdvancedMode(false)
    setModalOpen(true)
  }

  const handleSubmit = async () => {
    try {
      let finalRaw = rawContent;
      let port = 80;

      if (!advancedMode) {
        const values = await form.validateFields();
        finalRaw = generateRawContent(values.directives || []);
        const listenDir = (values.directives || []).find((d: any) => d && d.key === 'listen');
        port = listenDir ? parseInt(listenDir.value, 10) : 80;
      } else {
        const parsed = parseDirectives(rawContent);
        const listenDir = parsed.find((d: any) => d && d.key === 'listen');
        port = listenDir ? parseInt(listenDir.value, 10) : 80;
      }

      if (editingFilename !== null) {
        await api.put('/nginx/configs', { old_filename: editingFilename, listen_port: port, raw_content: finalRaw })
      } else {
        await api.post('/nginx/configs', { listen_port: port, raw_content: finalRaw })
      }

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
    if (checked) {
      // 转高级模式：同步表单内容到 rawContent
      const values = form.getFieldsValue();
      setRawContent(generateRawContent(values.directives || []));
    } else {
      // 转普通模式：从 rawContent 解析到表单
      form.setFieldsValue({ directives: parseDirectives(rawContent) });
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
        <Form form={form} layout="vertical" initialValues={{ directives: [{ key: 'listen', value: '8090' }] }}>
          <div style={{ marginBottom: 12, color: '#8b949e', fontSize: 13 }}>
            配置将会生成为独立的随机文件存储，防止命名冲突。
          </div>
          {!advancedMode ? (
            <Form.List name="directives">
              {(fields, { add, remove }) => (
                <>
                  {fields.map(({ key, name, ...restField }) => (
                    <Space key={key} style={{ display: 'flex', marginBottom: 8 }} align="baseline">
                      <Form.Item
                        {...restField}
                        name={[name, 'key']}
                        rules={[{ required: true, message: '请输入指令键' }]}
                      >
                        <AutoComplete
                          options={PRESET_KEYS}
                          placeholder="例如: proxy_pass"
                          style={{ width: 180 }}
                          filterOption={(inputValue, option) =>
                            option!.value.toUpperCase().indexOf(inputValue.toUpperCase()) !== -1
                          }
                        />
                      </Form.Item>
                      <Form.Item
                        {...restField}
                        name={[name, 'value']}
                        rules={[{ required: true, message: '请输入指令值' }]}
                      >
                        <Input placeholder="参数值" style={{ width: 300 }} />
                      </Form.Item>
                      <MinusCircleOutlined onClick={() => remove(name)} style={{ color: '#f85149' }} />
                    </Space>
                  ))}
                  <Form.Item>
                    <Button type="dashed" onClick={() => add()} block icon={<PlusOutlined />}>
                      添加指令
                    </Button>
                  </Form.Item>
                </>
              )}
            </Form.List>
          ) : (
            <div style={{ marginBottom: 16 }}>
              <div style={{ marginBottom: 8, color: '#c9d1d9', fontSize: 13 }}>
                Nginx Server Block 配置
              </div>
              <div style={{ border: '1px solid #30363d', borderRadius: 6, overflow: 'hidden' }}>
                <Editor height={380} defaultLanguage="nginx" theme="vs-dark" value={rawContent} onChange={(v) => setRawContent(v || '')} beforeMount={handleEditorWillMount} options={{ minimap: { enabled: false }, fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace", fontSize: 13 }} />
              </div>
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
