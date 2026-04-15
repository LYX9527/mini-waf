import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { Spin, App as AntApp } from 'antd'
import MainLayout from './components/Layout'
import api from './api/client'
import { setMessageApi } from './utils/messageApi'

const Overview = lazy(() => import('./pages/Overview'))
const SiteManagement = lazy(() => import('./pages/SiteManagement'))
const NginxManagement = lazy(() => import('./pages/NginxManagement'))
const AttackLogs = lazy(() => import('./pages/AttackLogs'))
const AccessLogs = lazy(() => import('./pages/AccessLogs'))
const IPLists = lazy(() => import('./pages/IPLists'))
const SecurityRules = lazy(() => import('./pages/SecurityRules'))
const SystemSettings = lazy(() => import('./pages/SystemSettings'))
const Login = lazy(() => import('./pages/Login'))
const SystemInit = lazy(() => import('./pages/SystemInit'))

const Loading = () => (
  <div style={{ textAlign: 'center', padding: 100 }}>
    <Spin size="large" />
  </div>
)

// 判断是否需要初始化
const Sentinel = ({ children }: { children: JSX.Element }) => {
  const navigate = useNavigate()

  useEffect(() => {
    // 每次进入系统时先检查是否需要初始化
    api.get('/auth/check-init').then(res => {
      if (res.data.need_init) {
        navigate('/system-init', { replace: true })
      }
    }).catch(() => {})
  }, [navigate])

  return children
}

// 需要认证的高阶封装
const PrivateRoute = ({ children }: { children: JSX.Element }) => {
  const token = localStorage.getItem('mini_waf_token')
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return children
}

function AppContent() {
  const { message } = AntApp.useApp()

  useEffect(() => {
    setMessageApi(message)
  }, [message])

  return (
    <BrowserRouter>
      <Sentinel>
        <Routes>
          <Route path="/login" element={<Suspense fallback={<Loading />}><Login /></Suspense>} />
          <Route path="/system-init" element={<Suspense fallback={<Loading />}><SystemInit /></Suspense>} />
          
          <Route path="/" element={<PrivateRoute><MainLayout /></PrivateRoute>}>
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<Suspense fallback={<Loading />}><Overview /></Suspense>} />
            <Route path="sites" element={<Suspense fallback={<Loading />}><SiteManagement /></Suspense>} />
            <Route path="nginx" element={<Suspense fallback={<Loading />}><NginxManagement /></Suspense>} />
            <Route path="logs/attacks" element={<Suspense fallback={<Loading />}><AttackLogs /></Suspense>} />
            <Route path="logs/access" element={<Suspense fallback={<Loading />}><AccessLogs /></Suspense>} />
            <Route path="ip-lists" element={<Suspense fallback={<Loading />}><IPLists /></Suspense>} />
            <Route path="rules" element={<Suspense fallback={<Loading />}><SecurityRules /></Suspense>} />
            <Route path="settings" element={<Suspense fallback={<Loading />}><SystemSettings /></Suspense>} />
          </Route>
        </Routes>
      </Sentinel>
    </BrowserRouter>
  )
}

export default function App() {
  return <AppContent />
}
