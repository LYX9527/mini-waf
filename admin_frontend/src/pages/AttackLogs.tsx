import { Table, Input, DatePicker, Tag, Space } from 'antd'
import { useEffect, useState } from 'react'
import api from '../api/client'
import dayjs from 'dayjs'

interface LogItem {
  ip_address: string
  request_path: string
  matched_rule: string
  created_at: string
}

export default function AttackLogs() {
  const [logs, setLogs] = useState<LogItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [filters, setFilters] = useState<{ ip?: string; path?: string; rule?: string; start?: string; end?: string }>({})

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: pageSize }
      if (filters.ip) params.ip = filters.ip
      if (filters.path) params.path = filters.path
      if (filters.rule) params.rule = filters.rule
      if (filters.start) params.start = filters.start
      if (filters.end) params.end = filters.end

      const res = await api.get('/logs/attacks', { params })
      setLogs(res.data.data || [])
      setTotal(res.data.total || 0)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchLogs() }, [page, filters])

  const columns = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
    },
    {
      title: 'IP 地址',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 140,
      render: (ip: string) => <Tag color="orange">{ip}</Tag>,
    },
    {
      title: '请求路径',
      dataIndex: 'request_path',
      key: 'request_path',
      ellipsis: true,
    },
    {
      title: '匹配规则',
      dataIndex: 'matched_rule',
      key: 'matched_rule',
      render: (rule: string) => <Tag color="red">{rule}</Tag>,
    },
  ]

  return (
    <div>
      <h2 style={{ color: '#c9d1d9', fontWeight: 600, marginBottom: 16 }}>防护日志</h2>

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
        <Input
          placeholder="筛选规则"
          style={{ width: 160 }}
          allowClear
          onPressEnter={(e) => setFilters({ ...filters, rule: (e.target as HTMLInputElement).value || undefined })}
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
