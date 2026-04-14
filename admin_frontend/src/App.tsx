import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Spin } from 'antd'
import MainLayout from './components/Layout'

const Overview = lazy(() => import('./pages/Overview'))
const SiteManagement = lazy(() => import('./pages/SiteManagement'))
const AttackLogs = lazy(() => import('./pages/AttackLogs'))
const AccessLogs = lazy(() => import('./pages/AccessLogs'))
const IPLists = lazy(() => import('./pages/IPLists'))
const SecurityRules = lazy(() => import('./pages/SecurityRules'))
const SystemSettings = lazy(() => import('./pages/SystemSettings'))

const Loading = () => (
  <div style={{ textAlign: 'center', padding: 100 }}>
    <Spin size="large" />
  </div>
)

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Suspense fallback={<Loading />}><Overview /></Suspense>} />
          <Route path="sites" element={<Suspense fallback={<Loading />}><SiteManagement /></Suspense>} />
          <Route path="logs/attacks" element={<Suspense fallback={<Loading />}><AttackLogs /></Suspense>} />
          <Route path="logs/access" element={<Suspense fallback={<Loading />}><AccessLogs /></Suspense>} />
          <Route path="ip-lists" element={<Suspense fallback={<Loading />}><IPLists /></Suspense>} />
          <Route path="rules" element={<Suspense fallback={<Loading />}><SecurityRules /></Suspense>} />
          <Route path="settings" element={<Suspense fallback={<Loading />}><SystemSettings /></Suspense>} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
