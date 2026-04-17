import { Table, Input, DatePicker, Tag, Space, Tooltip } from 'antd'
import { EnvironmentOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'

interface LogItem {
  ip_address: string
  request_path: string
  method: string
  status_code: number
  is_blocked: boolean
  matched_rule: string | null
  country: string | null
  city: string | null
  created_at: string
}

export default function AccessLogs() {
  const [logs, setLogs] = useState<LogItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [filters, setFilters] = useState<{ ip?: string; path?: string; start?: string; end?: string }>({})

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: pageSize }
      if (filters.ip) params.ip = filters.ip
      if (filters.path) params.path = filters.path
      if (filters.start) params.start = filters.start
      if (filters.end) params.end = filters.end

      const res = await api.get('/logs/access', { params })
      setLogs(res.data.data || [])
      setTotal(res.data.total || 0)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchLogs() }, [page, filters])

  const statusColor = (code: number) => {
    if (code >= 200 && code < 300) return 'green'
    if (code >= 300 && code < 400) return 'blue'
    if (code >= 400 && code < 500) return 'orange'
    return 'red'
  }

  const columns = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
    },
    {
      title: 'IP',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 260,
      render: (ip: string, record: LogItem) => (
        <Tooltip title={
          <div>
            <div style={{ borderBottom: '1px solid rgba(255,255,255,0.2)', paddingBottom: 4, marginBottom: 4 }}>{ip}</div>
            <div>{[record.country, record.city].filter(Boolean).join(' · ') || '未知'}</div>
          </div>
        }>
          <Tag color="blue" style={{ margin: 0, height: 'auto', padding: '2px 7px', whiteSpace: 'normal', wordBreak: 'break-all', lineHeight: 1.5 }}>
            {ip}
          </Tag>
        </Tooltip>
      ),
    },
    {
      title: '来源',
      key: 'geo',
      width: 160,
      render: (_: any, record: LogItem) => {
        const parts = [record.country, record.city].filter(Boolean)
        return parts.length ? (
          <span style={{ color: '#8b949e' }}>
            <EnvironmentOutlined style={{ marginRight: 4, color: '#1668dc' }} />
            {parts.join(' · ')}
          </span>
        ) : (
          <span style={{ color: '#484f58' }}>-</span>
        )
      }
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (m: string) => <Tag>{m}</Tag>,
    },
    {
      title: '路径',
      dataIndex: 'request_path',
      key: 'request_path',
      ellipsis: true,
    },
    {
      title: '状态码',
      dataIndex: 'status_code',
      key: 'status_code',
      width: 90,
      render: (code: number) => <Tag color={statusColor(code)}>{code}</Tag>,
    },
    {
      title: '拦截',
      dataIndex: 'is_blocked',
      key: 'is_blocked',
      width: 80,
      render: (blocked: boolean) =>
        blocked ? <Tag color="red">拦截</Tag> : <Tag color="green">放行</Tag>,
    },
    {
      title: '规则',
      dataIndex: 'matched_rule',
      key: 'matched_rule',
      render: (rule: string | null) => (rule ? <Tag color="orange">{rule}</Tag> : '-'),
    },
  ]

  return (
    <div>
      <h2 style={{ color: '#c9d1d9', fontWeight: 600, marginBottom: 16 }}>访问日志</h2>

      <Space style={{ marginBottom: 16 }} wrap>
        <Input
          placeholder="筛选 IP"
          style={{ width: 160 }}
          allowClear
          onPressEnter={(e) => setFilters({ ...filters, ip: (e.target as HTMLInputElement).value || undefined })}
        />
        <Input
          placeholder="筛选路径"
          style={{ width: 200 }}
          allowClear
          onPressEnter={(e) => setFilters({ ...filters, path: (e.target as HTMLInputElement).value || undefined })}
        />
        <DatePicker.RangePicker
          showTime
          onChange={(dates) => {
            setFilters({
              ...filters,
              start: dates?.[0]?.format('YYYY-MM-DD HH:mm:ss'),
              end: dates?.[1]?.format('YYYY-MM-DD HH:mm:ss'),
            })
          }}
        />
      </Space>

      <Table
        dataSource={logs}
        columns={columns}
        rowKey={(r, i) => `${r.ip_address}-${r.created_at}-${i}`}
        loading={loading}
        pagination={{
          current: page,
          pageSize,
          total,
          onChange: setPage,
          showTotal: (t) => `共 ${t} 条`,
        }}
      />
    </div>
  )
}
