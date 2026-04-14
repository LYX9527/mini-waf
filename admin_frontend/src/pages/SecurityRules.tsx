import { Table, Button, Modal, Form, Input, Tag, Popconfirm, message } from 'antd'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'

export default function SecurityRules() {
  const [rules, setRules] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [form] = Form.useForm()

  const fetchRules = async () => {
    try {
      const res = await api.get('/rules')
      setRules(res.data.rules || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchRules() }, [])

  const handleAdd = async () => {
    try {
      const values = await form.validateFields()
      await api.post('/rules', { rule: values.rule })
      message.success('规则添加成功')
      setModalOpen(false)
      form.resetFields()
      fetchRules()
    } catch (e: any) {
      message.error(e.response?.data?.message || '添加失败')
    }
  }

  const columns = [
    {
      title: '#',
      key: 'index',
      width: 60,
      render: (_: any, __: any, index: number) => index + 1,
    },
    {
      title: '关键词规则',
      dataIndex: 'keyword',
      key: 'keyword',
      render: (keyword: string) => <Tag color="red">{keyword}</Tag>,
    },
    {
      title: '类型',
      key: 'type',
      render: () => <Tag color="orange">关键词匹配</Tag>,
    },
    {
      title: '状态',
      key: 'status',
      render: () => <Tag color="green">启用</Tag>,
    },
  ]

  const tableData = rules.map((keyword, i) => ({ keyword, key: i }))

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ color: '#c9d1d9', fontWeight: 600, margin: 0 }}>安全规则</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
          添加规则
        </Button>
      </div>

      <Table
        dataSource={tableData}
        columns={columns}
        loading={loading}
        pagination={false}
      />

      <Modal
        title="添加安全规则"
        open={modalOpen}
        onOk={handleAdd}
        onCancel={() => { setModalOpen(false); form.resetFields() }}
        okText="添加"
        cancelText="取消"
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="rule"
            label="关键词"
            rules={[{ required: true, message: '请输入关键词' }]}
            extra="当请求路径或查询参数中包含此关键词时，将被拦截"
          >
            <Input placeholder="如: ../ 、 OR 1=1 、 <script" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
