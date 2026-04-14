import { Table, Button, Modal, Form, Input, Select, Tag, Popconfirm, message } from 'antd'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import api from '../api/client'

export default function SecurityRules() {
  const [rules, setRules] = useState<any[]>([])
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
      await api.post('/rules', { 
        rule: values.rule,
        target_field: values.target_field || 'URL',
        match_type: values.match_type || 'Contains'
      })
      message.success('规则添加成功')
      setModalOpen(false)
      form.resetFields()
      fetchRules()
    } catch (e: any) {
      message.error(e.response?.data?.message || '添加失败')
    }
  }

  const handleDelete = async (rule: string) => {
    try {
      await api.delete('/rules', { data: { rule } })
      message.success('规则已删除')
      fetchRules()
    } catch (e: any) {
      message.error(e.response?.data?.message || '删除失败')
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
      title: '目标区',
      dataIndex: 'target_field',
      key: 'target_field',
      render: (text: string) => <Tag color="blue">{text || 'URL'}</Tag>,
    },
    {
      title: '类型',
      dataIndex: 'match_type',
      key: 'match_type',
      render: (text: string) => <Tag color={text === 'Regex' ? 'purple' : 'orange'}>{text || 'Contains'}</Tag>,
    },
    {
      title: '状态',
      key: 'status',
      render: () => <Tag color="green">启用</Tag>,
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => (
        <Popconfirm title="确定删除此规则？" onConfirm={() => handleDelete(record.keyword)}>
          <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ]

  const tableData = rules.map((r, i) => ({ ...r, key: i }))

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
          <Form.Item name="target_field" label="匹配目标" initialValue="URL">
            <Select>
              <Select.Option value="URL">URL/Query</Select.Option>
              <Select.Option value="Header">所有 Headers</Select.Option>
              <Select.Option value="User-Agent">User-Agent</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="match_type" label="匹配模式" initialValue="Contains">
            <Select>
              <Select.Option value="Contains">部分包含 (Contains)</Select.Option>
              <Select.Option value="Exact">完全相等 (Exact)</Select.Option>
              <Select.Option value="Regex">正则表达式 (Regex)</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="rule"
            label="规则内容/正则表达式"
            rules={[{ required: true, message: '请输入内容' }]}
            extra="根据选择的匹配模式，输入关键词或合理的正则"
          >
            <Input placeholder="如: ../ 、 OR 1=1 、 ^curl/" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
