import React from 'react';
import { Header } from './Header';
import { Sidebar, NavRoute } from './Sidebar';

interface Props {
  currentRoute: NavRoute;
  onRouteChange: (route: NavRoute) => void;
  openFindingsCount?: number;
  children: React.ReactNode;
}

export const AppShell: React.FC<Props> = ({
  currentRoute,
  onRouteChange,
  openFindingsCount,
  children
}) => {
  return (
    <div className="h-screen bg-[#F4F6F9] flex flex-col antialiased overflow-hidden">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentRoute={currentRoute}
          onRouteChange={onRouteChange}
          openFindingsCount={openFindingsCount}
        />
        <main className="flex-1 overflow-y-auto p-6 max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
};
