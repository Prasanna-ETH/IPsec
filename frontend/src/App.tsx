import React, { useState, useEffect } from 'react';
import { AppShell } from './components/layout/AppShell';
import { NavRoute } from './components/layout/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { CaptureCenterPage } from './pages/CaptureCenterPage';
import { TunnelsPage } from './pages/TunnelsPage';
import { TunnelInvestigationPage } from './pages/TunnelInvestigationPage';
import { FindingsPage } from './pages/FindingsPage';
import { TrafficIntelligencePage } from './pages/TrafficIntelligencePage';
import { EvidenceExplorerPage } from './pages/EvidenceExplorerPage';
import { ComparePage } from './pages/ComparePage';
import { ReportsPage } from './pages/ReportsPage';
import { StandardsPage } from './pages/StandardsPage';
import { SystemPage } from './pages/SystemPage';
import { api } from './services/api';

export function App() {
  const [currentRoute, setCurrentRoute] = useState<NavRoute>('overview');
  const [selectedTunnelId, setSelectedTunnelId] = useState<string | null>(null);
  const [openFindingsCount, setOpenFindingsCount] = useState(0);

  useEffect(() => {
    loadFindingsCount();
  }, [currentRoute]);

  const loadFindingsCount = async () => {
    try {
      const findings = await api.getFindings();
      setOpenFindingsCount(findings.length);
    } catch {
      // ignore
    }
  };

  const handleNavigate = (route: string, param?: string) => {
    if (route === 'tunnels' && param) {
      setSelectedTunnelId(param);
      setCurrentRoute('tunnels');
    } else {
      setSelectedTunnelId(null);
      setCurrentRoute(route as NavRoute);
    }
  };

  const handleBackToTunnels = () => {
    setSelectedTunnelId(null);
    setCurrentRoute('tunnels');
  };

  const renderContent = () => {
    switch (currentRoute) {
      case 'overview':
        return <OverviewPage onNavigate={handleNavigate} />;
      case 'captures':
        return <CaptureCenterPage onNavigate={handleNavigate} />;
      case 'tunnels':
        if (selectedTunnelId) {
          return (
            <TunnelInvestigationPage
              tunnelId={selectedTunnelId}
              onBack={handleBackToTunnels}
              onNavigate={handleNavigate}
            />
          );
        }
        return <TunnelsPage onNavigate={handleNavigate} />;
      case 'findings':
        return <FindingsPage onNavigate={handleNavigate} />;
      case 'intelligence':
        return <TrafficIntelligencePage onNavigate={handleNavigate} />;
      case 'evidence':
        return <EvidenceExplorerPage onNavigate={handleNavigate} />;
      case 'compare':
        return <ComparePage onNavigate={handleNavigate} />;
      case 'reports':
        return <ReportsPage onNavigate={handleNavigate} />;
      case 'standards':
        return <StandardsPage onNavigate={handleNavigate} />;
      case 'system':
        return <SystemPage onNavigate={handleNavigate} />;
      default:
        return <OverviewPage onNavigate={handleNavigate} />;
    }
  };

  return (
    <AppShell
      currentRoute={currentRoute}
      onRouteChange={(r) => {
        setSelectedTunnelId(null);
        setCurrentRoute(r);
      }}
      openFindingsCount={openFindingsCount}
    >
      {renderContent()}
    </AppShell>
  );
}

export default App;
