import { Card, Col, Row, Statistic, Spin } from 'antd'
import {
  ThunderboltOutlined,
  SafetyOutlined,
  ApiOutlined,
  ClockCircleOutlined,
  GlobalOutlined,
  UserOutlined,
  WarningOutlined,
  StopOutlined,
  DashboardOutlined,
} from '@ant-design/icons'
import { Line, Column, Pie } from '@ant-design/charts'
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps'
import { useEffect, useState, useCallback } from 'react'
import api from '../api/client'

interface OverviewStats {
  total_requests: number
  unique_ips: number
  unique_visitors: number
  blocked_attacks: number
  err_4xx: number
  err_4xx_rate: number
  err_5xx: number
  err_5xx_rate: number
  qps: number
}

interface TodayStats {
  hours: number[]
  requests: number[]
  blocked: number[]
}

interface StatusItem {
  status_code: number
  count: number
}

interface RefererItem {
  referer: string
  full: string
  count: number
}

interface IpGeoItem {
  ip: string
  count: number
  lat?: number
  lng?: number
  country?: string
  city?: string
}

interface TopItem {
  ip?: string
  rule?: string
  count: number
}

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const STATUS_LABELS: Record<number, string> = {
  200: '200 OK',
  403: '403 禁止',
  404: '404 未找到',
  405: '405 方法不允许',
  502: '502 网关错误',
}

export default function Overview() {
  const [overview, setOverview] = useState<OverviewStats | null>(null)
  const [today, setToday] = useState<TodayStats | null>(null)
  const [topIps, setTopIps] = useState<TopItem[]>([])
  const [topRules, setTopRules] = useState<TopItem[]>([])
  const [statusDist, setStatusDist] = useState<StatusItem[]>([])
  const [topReferers, setTopReferers] = useState<RefererItem[]>([])
  const [ipGeoData, setIpGeoData] = useState<IpGeoItem[]>([])
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const [ov, td, ips, rules, status, referers, geo] = await Promise.all([
        api.get('/stats/overview'),
        api.get('/stats/today'),
        api.get('/stats/top-ips'),
        api.get('/stats/top-rules'),
        api.get('/stats/status-distribution'),
        api.get('/stats/top-referers'),
        api.get('/stats/ip-geo'),
      ])
      setOverview(ov.data)
      setToday(td.data)
      setTopIps(ips.data.data)
      setTopRules(rules.data.data)
      setStatusDist(status.data.data)
      setTopReferers(referers.data.data)
      setIpGeoData(geo.data.data)
    } catch (e) {
      console.error('Failed to fetch stats:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const timer = setInterval(fetchData, 10000)
    return () => clearInterval(timer)
  }, [fetchData])



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

  const pieData = statusDist.map((d) => ({
    type: STATUS_LABELS[d.status_code] || (d.status_code ? d.status_code.toString() : '未知'),
    value: d.count,
  }))

  const geoMarkers = ipGeoData.filter((d) => d.lat && d.lng)

  const statCards = [
    { title: '今日请求', value: overview?.total_requests || 0, icon: <ApiOutlined />, color: '#1668dc' },
    { title: '独立 IP', value: overview?.unique_ips || 0, icon: <GlobalOutlined />, color: '#13c2c2' },
    { title: '独立访客', value: overview?.unique_visitors || 0, icon: <UserOutlined />, color: '#722ed1' },
    { title: '拦截攻击', value: overview?.blocked_attacks || 0, icon: <SafetyOutlined />, color: '#f5222d' },
    { title: '4xx 错误', value: overview?.err_4xx || 0, icon: <WarningOutlined />, color: '#fa8c16' },
    { title: '4xx 错误率', value: `${overview?.err_4xx_rate || 0}%`, icon: <WarningOutlined />, color: '#faad14' },
    { title: '5xx 错误', value: overview?.err_5xx || 0, icon: <StopOutlined />, color: '#f5222d' },
    { title: '5xx 错误率', value: `${overview?.err_5xx_rate || 0}%`, icon: <StopOutlined />, color: '#eb2f96' },
    { title: '实时 QPS', value: overview?.qps || 0, icon: <DashboardOutlined />, color: '#52c41a' },
  ]

  return (
    <div>
      <h2 style={{ color: '#c9d1d9', marginBottom: 24, fontWeight: 600 }}>总览面板</h2>

      {/* 统计卡片行 */}
      <Row gutter={[12, 12]}>
        {statCards.map((card) => (
          <Col xs={12} sm={8} lg={8} xl={8} key={card.title}>
            <Card size="small" style={{ borderColor: '#21262d' }}>
              <Statistic
                title={<span style={{ color: '#8b949e', fontSize: 12 }}>{card.title}</span>}
                value={card.value}
                prefix={<span style={{ color: card.color, marginRight: 4 }}>{card.icon}</span>}
                valueStyle={{ color: card.color, fontSize: 20 }}
              />
            </Card>
          </Col>
        ))}
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

      {/* 地图 + 状态分布 */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={14}>
          <Card title="IP 来源世界地图" style={{ borderColor: '#21262d' }}>
            <div style={{ height: 320, overflow: 'hidden', borderRadius: 4 }}>
              <ComposableMap
                projectionConfig={{ rotate: [-10, 0, 0] }}
                style={{ width: '100%', height: '100%' }}
              >
                <ZoomableGroup center={[0, 20]} zoom={1}>
                  <Geographies geography={GEO_URL}>
                    {({ geographies }) =>
                      geographies.map((geo) => (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          fill="#161b22"
                          stroke="#30363d"
                          strokeWidth={0.5}
                          style={{
                            default: { outline: 'none' },
                            hover: { fill: '#21262d', outline: 'none' },
                          }}
                        />
                      ))
                    }
                  </Geographies>
                  {geoMarkers.map((item) => (
                    <Marker key={item.ip} coordinates={[item.lng!, item.lat!]}>
                      <circle
                        r={Math.max(3, Math.min(10, Math.sqrt(item.count) * 2))}
                        fill="#f5222d80"
                        stroke="#f5222d"
                        strokeWidth={1}
                      >
                        <animate
                          attributeName="r"
                          values={`${Math.max(3, Math.min(10, Math.sqrt(item.count) * 2))};${Math.max(5, Math.min(14, Math.sqrt(item.count) * 2.5))};${Math.max(3, Math.min(10, Math.sqrt(item.count) * 2))}`}
                          dur="2s"
                          repeatCount="indefinite"
                        />
                      </circle>
                      <title>{item.ip} ({item.city || item.country || '未知'}) - {item.count} 次请求</title>
                    </Marker>
                  ))}
                </ZoomableGroup>
              </ComposableMap>
            </div>
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card title="响应状态分布" style={{ borderColor: '#21262d' }}>
            <Pie
              data={pieData}
              angleField="value"
              colorField="type"
              height={320}
              theme="dark"
              radius={0.8}
              innerRadius={0.5}
              label={{
                text: 'type',
                position: 'spider',
                style: { fill: '#c9d1d9', fontSize: 12 },
              }}
              tooltip={{
                title: 'type',
              }}
              legend={{
                color: { itemName: { style: { fill: '#c9d1d9', fontSize: 12 } } },
              }}
              statistic={{
                title: { style: { color: '#8b949e' }, content: '总计' },
                content: { style: { color: '#c9d1d9', fontSize: 20 } },
              }}
              color={['#52c41a', '#f5222d', '#fa8c16', '#faad14', '#eb2f96']}
            />
          </Card>
        </Col>
      </Row>

      {/* Referer + Top IPs */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={12}>
          <Card title="Top 10 Referer 来源" style={{ borderColor: '#21262d' }}>
            <Column
              data={topReferers.map((item) => ({
                referer: item.referer.length > 30 ? item.referer.slice(0, 30) + '...' : item.referer,
                count: item.count,
              }))}
              xField="referer"
              yField="count"
              colorField="referer"
              height={280}
              theme="dark"
              style={{ radiusTopLeft: 4, radiusTopRight: 4 }}
              axis={{
                x: {
                  label: {
                    style: { fill: '#8b949e' },
                    autoRotate: true,
                    autoHide: true,
                  },
                },
                y: { label: { style: { fill: '#8b949e' } } },
              }}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Top 5 攻击来源 IP" style={{ borderColor: '#21262d' }}>
            <Column
              data={topIps.map((item) => ({
                ip: item.ip || '未知',
                count: item.count,
              }))}
              xField="ip"
              yField="count"
              colorField="ip"
              height={280}
              theme="dark"
              style={{ radiusTopLeft: 4, radiusTopRight: 4 }}
              axis={{
                x: { label: { style: { fill: '#8b949e' } } },
                y: { label: { style: { fill: '#8b949e' } } },
              }}
            />
          </Card>
        </Col>
      </Row>

      {/* Top Rules */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col span={24}>
          <Card title="Top 5 触发规则" style={{ borderColor: '#21262d' }}>
            <Column
              data={topRules.map((item) => ({
                rule: item.rule || '未知',
                count: item.count,
              }))}
              xField="rule"
              yField="count"
              colorField="rule"
              height={250}
              theme="dark"
              style={{ radiusTopLeft: 4, radiusTopRight: 4 }}
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
