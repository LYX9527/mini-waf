import { Card, Form, InputNumber, Button, Spin, Input, Divider, Select } from 'antd'
import { SaveOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

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
  trust_upstream_proxy: '信任上游代理头 (如配置了 Cloudflare 等 CDN)',
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
        if (key === 'custom_block_page') {
          formValues[key] = (val as SettingItem).value
        } else if (key === 'geo_blocked_countries') {
          const v = (val as SettingItem).value
          formValues[key] = v ? v.split(',').filter(Boolean) : []
        } else if (key === 'trust_upstream_proxy') {
          formValues[key] = (val as SettingItem).value === '1' || (val as SettingItem).value.toLowerCase() === 'true'
        } else {
          formValues[key] = parseInt((val as SettingItem).value, 10)
        }
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
        if (key === 'geo_blocked_countries' && Array.isArray(val)) {
          settingsPayload[key] = val.join(',')
        } else if (key === 'trust_upstream_proxy') {
          settingsPayload[key] = val ? '1' : '0'
        } else if (val !== undefined && val !== null) {
          settingsPayload[key] = String(val)
        }
      }
      await api.put('/settings', { settings: settingsPayload })
      message.success('设置已更新')
      fetchSettings()
    } catch {
      // 拦截器已处理
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
              {key === 'trust_upstream_proxy' ? (
                <Select
                  style={{ width: 300 }}
                  options={[
                    { label: '关闭 (强校验直连物理网卡 IP)', value: false },
                    { label: '开启 (信任 CF-Connecting-IP 等头)', value: true },
                  ]}
                />
              ) : key === 'custom_block_page' ? (
                <Input.TextArea rows={6} style={{ width: '100%', fontFamily: 'monospace' }} />
              ) : key === 'geo_blocked_countries' ? (
                <Select
                  mode="multiple"
                  allowClear
                  placeholder="可多选，下拉选择要封禁的国家/地区"
                  style={{ width: '100%' }}
                  options={[
// ==========================================
                    // ⭐ 常见国家与地区（按日常业务与攻击溯源常见度排序）
                    // ==========================================
                    { label: '中国 (CN)', value: 'CN' },
                    { label: '美国 (US)', value: 'US' },
                    { label: '俄罗斯 (RU)', value: 'RU' },
                    { label: '日本 (JP)', value: 'JP' },
                    { label: '韩国 (KR)', value: 'KR' },
                    { label: '中国香港 (HK)', value: 'HK' },
                    { label: '中国台湾 (TW)', value: 'TW' },
                    { label: '中国澳门 (MO)', value: 'MO' },
                    { label: '英国 (GB)', value: 'GB' },
                    { label: '法国 (FR)', value: 'FR' },
                    { label: '德国 (DE)', value: 'DE' },
                    { label: '伊朗 (IR)', value: 'IR' },
                    { label: '朝鲜 (KP)', value: 'KP' },
                    { label: '印度 (IN)', value: 'IN' },
                    { label: '巴西 (BR)', value: 'BR' },
                    { label: '新加坡 (SG)', value: 'SG' },
                    { label: '澳大利亚 (AU)', value: 'AU' },
                    { label: '加拿大 (CA)', value: 'CA' },
                    { label: '意大利 (IT)', value: 'IT' },
                    { label: '西班牙 (ES)', value: 'ES' },
                    { label: '荷兰 (NL)', value: 'NL' },
                    { label: '越南 (VN)', value: 'VN' },
                    { label: '菲律宾 (PH)', value: 'PH' },
                    { label: '泰国 (TH)', value: 'TH' },
                    { label: '印度尼西亚 (ID)', value: 'ID' },
                    { label: '马来西亚 (MY)', value: 'MY' },

                    // ==========================================
                    // 🌍 亚洲其他 (Asia)
                    // ==========================================
                    { label: '阿富汗 (AF)', value: 'AF' },
                    { label: '阿联酋 (AE)', value: 'AE' },
                    { label: '阿曼 (OM)', value: 'OM' },
                    { label: '阿塞拜疆 (AZ)', value: 'AZ' },
                    { label: '巴基斯坦 (PK)', value: 'PK' },
                    { label: '巴勒斯坦 (PS)', value: 'PS' },
                    { label: '巴林 (BH)', value: 'BH' },
                    { label: '不丹 (BT)', value: 'BT' },
                    { label: '东帝汶 (TL)', value: 'TL' },
                    { label: '格鲁吉亚 (GE)', value: 'GE' },
                    { label: '哈萨克斯坦 (KZ)', value: 'KZ' },
                    { label: '吉尔吉斯斯坦 (KG)', value: 'KG' },
                    { label: '柬埔寨 (KH)', value: 'KH' },
                    { label: '卡塔尔 (QA)', value: 'QA' },
                    { label: '科威特 (KW)', value: 'KW' },
                    { label: '老挝 (LA)', value: 'LA' },
                    { label: '黎巴嫩 (LB)', value: 'LB' },
                    { label: '马尔代夫 (MV)', value: 'MV' },
                    { label: '蒙古 (MN)', value: 'MN' },
                    { label: '孟加拉国 (BD)', value: 'BD' },
                    { label: '缅甸 (MM)', value: 'MM' },
                    { label: '尼泊尔 (NP)', value: 'NP' },
                    { label: '沙特阿拉伯 (SA)', value: 'SA' },
                    { label: '斯里兰卡 (LK)', value: 'LK' },
                    { label: '塔吉克斯坦 (TJ)', value: 'TJ' },
                    { label: '土耳其 (TR)', value: 'TR' },
                    { label: '土库曼斯坦 (TM)', value: 'TM' },
                    { label: '文莱 (BN)', value: 'BN' },
                    { label: '乌兹别克斯坦 (UZ)', value: 'UZ' },
                    { label: '叙利亚 (SY)', value: 'SY' },
                    { label: '亚美尼亚 (AM)', value: 'AM' },
                    { label: '也门 (YE)', value: 'YE' },
                    { label: '伊拉克 (IQ)', value: 'IQ' },
                    { label: '以色列 (IL)', value: 'IL' },
                    { label: '约旦 (JO)', value: 'JO' },

                    // ==========================================
                    // 🌍 欧洲 (Europe)
                    // ==========================================
                    { label: '阿尔巴尼亚 (AL)', value: 'AL' },
                    { label: '爱尔兰 (IE)', value: 'IE' },
                    { label: '爱沙尼亚 (EE)', value: 'EE' },
                    { label: '安道尔 (AD)', value: 'AD' },
                    { label: '奥地利 (AT)', value: 'AT' },
                    { label: '白俄罗斯 (BY)', value: 'BY' },
                    { label: '保加利亚 (BG)', value: 'BG' },
                    { label: '北马其顿 (MK)', value: 'MK' },
                    { label: '比利时 (BE)', value: 'BE' },
                    { label: '冰岛 (IS)', value: 'IS' },
                    { label: '波兰 (PL)', value: 'PL' },
                    { label: '波黑 (BA)', value: 'BA' },
                    { label: '丹麦 (DK)', value: 'DK' },
                    { label: '梵蒂冈 (VA)', value: 'VA' },
                    { label: '芬兰 (FI)', value: 'FI' },
                    { label: '黑山 (ME)', value: 'ME' },
                    { label: '捷克 (CZ)', value: 'CZ' },
                    { label: '克罗地亚 (HR)', value: 'HR' },
                    { label: '拉脱维亚 (LV)', value: 'LV' },
                    { label: '立陶宛 (LT)', value: 'LT' },
                    { label: '列支敦士登 (LI)', value: 'LI' },
                    { label: '卢森堡 (LU)', value: 'LU' },
                    { label: '罗马尼亚 (RO)', value: 'RO' },
                    { label: '马耳他 (MT)', value: 'MT' },
                    { label: '摩尔多瓦 (MD)', value: 'MD' },
                    { label: '摩纳哥 (MC)', value: 'MC' },
                    { label: '挪威 (NO)', value: 'NO' },
                    { label: '葡萄牙 (PT)', value: 'PT' },
                    { label: '瑞典 (SE)', value: 'SE' },
                    { label: '瑞士 (CH)', value: 'CH' },
                    { label: '塞尔维亚 (RS)', value: 'RS' },
                    { label: '塞浦路斯 (CY)', value: 'CY' },
                    { label: '圣马力诺 (SM)', value: 'SM' },
                    { label: '斯洛伐克 (SK)', value: 'SK' },
                    { label: '斯洛文尼亚 (SI)', value: 'SI' },
                    { label: '乌克兰 (UA)', value: 'UA' },
                    { label: '希腊 (GR)', value: 'GR' },
                    { label: '匈牙利 (HU)', value: 'HU' },

                    // ==========================================
                    // 🌍 美洲 (Americas)
                    // ==========================================
                    { label: '阿根廷 (AR)', value: 'AR' },
                    { label: '安提瓜和巴布达 (AG)', value: 'AG' },
                    { label: '巴巴多斯 (BB)', value: 'BB' },
                    { label: '巴哈马 (BS)', value: 'BS' },
                    { label: '巴拉圭 (PY)', value: 'PY' },
                    { label: '巴拿马 (PA)', value: 'PA' },
                    { label: '伯利兹 (BZ)', value: 'BZ' },
                    { label: '玻利维亚 (BO)', value: 'BO' },
                    { label: '大洋洲 (OCEANIA)', value: 'OCEANIA' },
                    { label: '多米尼加 (DO)', value: 'DO' },
                    { label: '多米尼克 (DM)', value: 'DM' },
                    { label: '厄瓜多尔 (EC)', value: 'EC' },
                    { label: '哥伦比亚 (CO)', value: 'CO' },
                    { label: '哥斯达黎加 (CR)', value: 'CR' },
                    { label: '格林纳达 (GD)', value: 'GD' },
                    { label: '古巴 (CU)', value: 'CU' },
                    { label: '圭亚那 (GY)', value: 'GY' },
                    { label: '海地 (HT)', value: 'HT' },
                    { label: '洪都拉斯 (HN)', value: 'HN' },
                    { label: '秘鲁 (PE)', value: 'PE' },
                    { label: '墨西哥 (MX)', value: 'MX' },
                    { label: '尼加拉瓜 (NI)', value: 'NI' },
                    { label: '萨尔瓦多 (SV)', value: 'SV' },
                    { label: '圣基茨和尼维斯 (KN)', value: 'KN' },
                    { label: '圣卢西亚 (LC)', value: 'LC' },
                    { label: '圣文森特和格林纳丁斯 (VC)', value: 'VC' },
                    { label: '苏里南 (SR)', value: 'SR' },
                    { label: '特立尼达和多巴哥 (TT)', value: 'TT' },
                    { label: '危地马拉 (GT)', value: 'GT' },
                    { label: '委内瑞拉 (VE)', value: 'VE' },
                    { label: '乌拉圭 (UY)', value: 'UY' },
                    { label: '牙买加 (JM)', value: 'JM' },
                    { label: '智利 (CL)', value: 'CL' },

                    // ==========================================
                    // 🌍 非洲 (Africa)
                    // ==========================================
                    { label: '阿尔及利亚 (DZ)', value: 'DZ' },
                    { label: '埃及 (EG)', value: 'EG' },
                    { label: '埃塞俄比亚 (ET)', value: 'ET' },
                    { label: '安哥拉 (AO)', value: 'AO' },
                    { label: '贝宁 (BJ)', value: 'BJ' },
                    { label: '博茨瓦纳 (BW)', value: 'BW' },
                    { label: '布基纳法索 (BF)', value: 'BF' },
                    { label: '布隆迪 (BI)', value: 'BI' },
                    { label: '赤道几内亚 (GQ)', value: 'GQ' },
                    { label: '多哥 (TG)', value: 'TG' },
                    { label: '厄立特里亚 (ER)', value: 'ER' },
                    { label: '佛得角 (CV)', value: 'CV' },
                    { label: '冈比亚 (GM)', value: 'GM' },
                    { label: '刚果（布） (CG)', value: 'CG' },
                    { label: '刚果（金） (CD)', value: 'CD' },
                    { label: '吉布提 (DJ)', value: 'DJ' },
                    { label: '几内亚 (GN)', value: 'GN' },
                    { label: '几内亚比绍 (GW)', value: 'GW' },
                    { label: '加纳 (GH)', value: 'GH' },
                    { label: '加蓬 (GA)', value: 'GA' },
                    { label: '津巴布韦 (ZW)', value: 'ZW' },
                    { label: '喀麦隆 (CM)', value: 'CM' },
                    { label: '科摩罗 (KM)', value: 'KM' },
                    { label: '科特迪瓦 (CI)', value: 'CI' },
                    { label: '肯尼亚 (KE)', value: 'KE' },
                    { label: '莱索托 (LS)', value: 'LS' },
                    { label: '利比里亚 (LR)', value: 'LR' },
                    { label: '利比亚 (LY)', value: 'LY' },
                    { label: '卢旺达 (RW)', value: 'RW' },
                    { label: '马达加斯加 (MG)', value: 'MG' },
                    { label: '马拉维 (MW)', value: 'MW' },
                    { label: '马里 (ML)', value: 'ML' },
                    { label: '毛里求斯 (MU)', value: 'MU' },
                    { label: '毛里塔尼亚 (MR)', value: 'MR' },
                    { label: '摩洛哥 (MA)', value: 'MA' },
                    { label: '莫桑比克 (MZ)', value: 'MZ' },
                    { label: '纳米比亚 (NA)', value: 'NA' },
                    { label: '南非 (ZA)', value: 'ZA' },
                    { label: '南苏丹 (SS)', value: 'SS' },
                    { label: '尼日尔 (NE)', value: 'NE' },
                    { label: '尼日利亚 (NG)', value: 'NG' },
                    { label: '塞拉利昂 (SL)', value: 'SL' },
                    { label: '塞内加尔 (SN)', value: 'SN' },
                    { label: '塞舌尔 (SC)', value: 'SC' },
                    { label: '圣多美和普林西比 (ST)', value: 'ST' },
                    { label: '斯威士兰 (SZ)', value: 'SZ' },
                    { label: '苏丹 (SD)', value: 'SD' },
                    { label: '索马里 (SO)', value: 'SO' },
                    { label: '坦桑尼亚 (TZ)', value: 'TZ' },
                    { label: '突尼斯 (TN)', value: 'TN' },
                    { label: '乌干达 (UG)', value: 'UG' },
                    { label: '赞比亚 (ZM)', value: 'ZM' },
                    { label: '乍得 (TD)', value: 'TD' },
                    { label: '中非 (CF)', value: 'CF' },

                    // ==========================================
                    // 🌍 大洋洲及其他 (Oceania & Others)
                    // ==========================================
                    { label: '巴布亚新几内亚 (PG)', value: 'PG' },
                    { label: '斐济 (FJ)', value: 'FJ' },
                    { label: '基里巴斯 (KI)', value: 'KI' },
                    { label: '马绍尔群岛 (MH)', value: 'MH' },
                    { label: '密克罗尼西亚 (FM)', value: 'FM' },
                    { label: '瑙鲁 (NR)', value: 'NR' },
                    { label: '纽埃 (NU)', value: 'NU' },
                    { label: '帕劳 (PW)', value: 'PW' },
                    { label: '萨摩亚 (WS)', value: 'WS' },
                    { label: '汤加 (TO)', value: 'TO' },
                    { label: '图瓦卢 (TV)', value: 'TV' },
                    { label: '瓦努阿图 (VU)', value: 'VU' },
                    { label: '新西兰 (NZ)', value: 'NZ' },
                    { label: '所罗门群岛 (SB)', value: 'SB' },

                    // 特殊保留代码 (用于无法识别的 IP)
                    { label: '未知局域网/保留地址 (ZZ)', value: 'ZZ' }
                  ]}
                />
              ) : (
                <InputNumber min={1} style={{ width: 200 }} />
              )}
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
