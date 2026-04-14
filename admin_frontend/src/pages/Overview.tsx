import { Card, Col, Row, Statistic, Spin } from 'antd'
import {
  ThunderboltOutlined,
  SafetyOutlined,
  ApiOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons'
import { Line, Column } from '@ant-design/charts'
import { useEffect, useState } from 'react'
import api from '../api/client'

interface RealtimeStats {
  total_requests: number
  blocked_attacks: number
  active_connections: number
  uptime_seconds: number
}

interface TodayStats {
  hours: number[]
  requests: number[]
  blocked: number[]
}

interface TopItem {
  ip?: string
  rule?: string
  count: number
}

export default function Overview() {
  const [realtime, setRealtime] = useState<RealtimeStats | null>(null)
  const [today, setToday] = useState<TodayStats | null>(null)
  const [topIps, setTopIps] = useState<TopItem[]>([])
  const [topRules, setTopRules] = useState<TopItem[]>([])
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    try {
      const [rt, td, ips, rules] = await Promise.all([
        api.get('/stats/realtime'),
        api.get('/stats/today'),
        api.get('/stats/top-ips'),
        api.get('/stats/top-rules'),
      ])
      setRealtime(rt.data)
      setToday(td.data)
      setTopIps(ips.data.data)
      setTopRules(rules.data.data)
    } catch (e) {
      console.error('Failed to fetch stats:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const timer = setInterval(fetchData, 10000)
    return () => clearInterval(timer)
  }, [])

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    return `${h}h ${m}m`
  }

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: 100 }}>
        <Spin size="large" />
      </div>
    )
  }

  const trendData =
    today?.hours.flatMap((h, i) => [
      { hour: `${h}:00`, type: '请求', value: today.requests[i] },
      { hour: `${h}:00`, type: '拦截', value: today.blocked[i] },
    ]) || []

  return (
    <div>
      <h2 style={{ color: '#c9d1d9', marginBottom: 24, fontWeight: 600 }}>总览面板</h2>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card style={{ borderColor: '#21262d' }}>
            <Statistic
              title={<span style={{ color: '#8b949e' }}>今日总请求</span>}
              value={realtime?.total_requests || 0}
              prefix={<ApiOutlined style={{ color: '#1668dc' }} />}
              valueStyle={{ color: '#1668dc' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card style={{ borderColor: '#21262d' }}>
            <Statistic
              title={<span style={{ color: '#8b949e' }}>今日拦截攻击</span>}
              value={realtime?.blocked_attacks || 0}
              prefix={<SafetyOutlined style={{ color: '#f5222d' }} />}
              valueStyle={{ color: '#f5222d' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card style={{ borderColor: '#21262d' }}>
            <Statistic
              title={<span style={{ color: '#8b949e' }}>活跃连接</span>}
              value={realtime?.active_connections || 0}
              prefix={<ThunderboltOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card style={{ borderColor: '#21262d' }}>
            <Statistic
              title={<span style={{ color: '#8b949e' }}>运行时间</span>}
              value={formatUptime(realtime?.uptime_seconds || 0)}
              prefix={<ClockCircleOutlined style={{ color: '#faad14' }} />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 趋势图 */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col span={24}>
          <Card title="今日流量趋势" style={{ borderColor: '#21262d' }}>
            <Line
              data={trendData}
              xField="hour"
              yField="value"
              colorField="type"
              height={300}
              theme="dark"
              style={{ lineWidth: 2 }}
              color={['#1668dc', '#f5222d']}
              point={{ size: 3 }}
              legend={{
                itemName: { style: { fill: '#c9d1d9', fontSize: 13 } },
              }}
              axis={{
                x: { label: { style: { fill: '#8b949e' } } },
                y: { label: { style: { fill: '#8b949e' } } },
              }}
            />
          </Card>
        </Col>
      </Row>

      {/* Top N */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={12}>
          <Card title="Top 5 攻击来源 IP" style={{ borderColor: '#21262d' }}>
            <Column
              data={topIps.map((item) => ({
                ip: item.ip || 'unknown',
                count: item.count,
              }))}
              theme="dark"
              xField="ip"
              yField="count"
              height={250}
              color="#f5222d"
              axis={{
                x: { label: { style: { fill: '#8b949e' } } },
                y: { label: { style: { fill: '#8b949e' } } },
              }}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Top 5 触发规则" style={{ borderColor: '#21262d' }}>
            <Column
              data={topRules.map((item) => ({
                rule: item.rule || 'unknown',
                count: item.count,
              }))}
              xField="rule"
              yField="count"
              height={250}
              theme="dark"
              color="#faad14"
              axis={{
                x: { label: { style: { fill: '#8b949e' } } },
                y: { label: { style: { fill: '#8b949e' } } },
              }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
