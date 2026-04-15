import { Table, Tabs, Button, Modal, Form, Input, Tag, Popconfirm } from 'antd'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons'
import { useEffect, useState, useCallback } from 'react'
import api from '../api/client'
import message from '../utils/messageApi'

interface IpItem {
  ip_address: string
  reason: string | null
  created_at: string | null
}

export default function IPLists() {
  const [blacklist, setBlacklist] = useState<IpItem[]>([])
  const [whitelist, setWhitelist] = useState<IpItem[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('blacklist')
  const [form] = Form.useForm()

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [bl, wl] = await Promise.all([
        api.get('/ip-lists/blacklist'),
        api.get('/ip-lists/whitelist'),
      ])
      setBlacklist(bl.data.data || [])
      setWhitelist(wl.data.data || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  const handleAdd = async () => {
    try {
      const values = await form.validateFields()
      const endpoint = activeTab === 'blacklist' ? '/ip-lists/blacklist' : '/ip-lists/whitelist'
      await api.post(endpoint, values)
      message.success('添加成功')
      setModalOpen(false)
      form.resetFields()
      fetchData()
    } catch {
      // 拦截器已处理
    }
  }

  const handleDelete = async (ip: string, type: string) => {
    try {
      await api.delete(`/ip-lists/${type}/${ip}`)
      message.success('删除成功')
      fetchData()
    } catch {
      // 拦截器已处理
    }
  }

  const columns = (type: string) => [
    {
      title: 'IP 地址',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (ip: string) => <Tag color={type === 'blacklist' ? 'red' : 'green'}>{ip}</Tag>,
    },
    {
      title: '原因',
      dataIndex: 'reason',
      key: 'reason',
      render: (reason: string | null) => reason || '-',
    },
    {
      title: '添加时间',
      dataIndex: 'created_at',
      key: 'created_at',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: IpItem) => (
        <Popconfirm title="确定删除？" onConfirm={() => handleDelete(record.ip_address, type)}>
          <Button type="link" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0 }}>黑白名单</h2>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setModalOpen(true)}
        >
          添加 IP
        </Button>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'blacklist',
            label: `黑名单 (${blacklist.length})`,
            children: (
              <Table
                dataSource={blacklist}
                columns={columns('blacklist')}
                rowKey="ip_address"
                loading={loading}
                pagination={false}
              />
            ),
          },
          {
            key: 'whitelist',
            label: `白名单 (${whitelist.length})`,
            children: (
              <Table
                dataSource={whitelist}
                columns={columns('whitelist')}
                rowKey="ip_address"
                loading={loading}
                pagination={false}
              />
            ),
          },
        ]}
      />

      <Modal
        title={`添加到${activeTab === 'blacklist' ? '黑名单' : '白名单'}`}
        open={modalOpen}
        onOk={handleAdd}
        onCancel={() => { setModalOpen(false); form.resetFields() }}
        okText="添加"
        cancelText="取消"
      >
        <Form form={form} layout="vertical">
          <Form.Item name="ip_address" label="IP 地址" rules={[{ required: true, message: '请输入 IP 地址' }]}>
            <Input placeholder="192.168.1.100" />
          </Form.Item>
          <Form.Item name="reason" label="原因（可选）">
            <Input placeholder="备注原因" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
