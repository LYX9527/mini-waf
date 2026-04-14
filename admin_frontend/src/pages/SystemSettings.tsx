import { Card, Form, InputNumber, Button, message, Spin, Descriptions, Divider } from 'antd'
import { SaveOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'

interface SettingItem {
  value: string
  description: string | null
}

interface SettingsMap {
  [key: string]: SettingItem
}

const settingLabels: { [key: string]: string } = {
  rate_limit_threshold: '限流阈值（每窗口期最大请求数）',
  rate_limit_window_secs: '限流窗口（秒）',
  penalty_ban_score: '封禁惩罚分阈值',
  penalty_attack_score: '单次攻击惩罚分',
  penalty_ttl_secs: '惩罚分过期时间（秒）',
  token_ttl_secs: '通行令牌有效期（秒）',
  captcha_ttl_secs: '验证码有效期（秒）',
}

export default function SystemSettings() {
  const [settings, setSettings] = useState<SettingsMap>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()

  const fetchSettings = async () => {
    try {
      const res = await api.get('/settings')
      const data = res.data.settings || {}
      setSettings(data)
      // 填充表单
      const formValues: any = {}
      for (const [key, val] of Object.entries(data)) {
        formValues[key] = parseInt((val as SettingItem).value, 10)
      }
      form.setFieldsValue(formValues)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchSettings() }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const values = form.getFieldsValue()
      // 转为字符串
      const settingsPayload: any = {}
      for (const [key, val] of Object.entries(values)) {
        if (val !== undefined && val !== null) {
          settingsPayload[key] = String(val)
        }
      }
      await api.put('/settings', { settings: settingsPayload })
      message.success('设置已更新')
      fetchSettings()
    } catch (e: any) {
      message.error(e.response?.data?.message || '保存失败')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 100 }}><Spin size="large" /></div>
  }

  return (
    <div>
      <h2 style={{ color: '#c9d1d9', fontWeight: 600, marginBottom: 24 }}>系统设置</h2>

      <Card style={{ borderColor: '#21262d' }}>
        <Form form={form} layout="vertical">
          {Object.entries(settings).map(([key, item]) => (
            <Form.Item
              key={key}
              name={key}
              label={
                <span style={{ color: '#c9d1d9' }}>
                  {settingLabels[key] || item.description || key}
                </span>
              }
              extra={<span style={{ color: '#484f58' }}>当前值: {item.value}</span>}
            >
              <InputNumber min={1} style={{ width: 200 }} />
            </Form.Item>
          ))}

          <Divider />

          <Button
            type="primary"
            icon={<SaveOutlined />}
            loading={saving}
            onClick={handleSave}
          >
            保存设置
          </Button>
        </Form>
      </Card>
    </div>
  )
}
