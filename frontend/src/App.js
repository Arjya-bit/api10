import { useEffect, useState } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, NavLink, useLocation } from "react-router-dom";
import axios from "axios";
import { Toaster } from "sonner";
import {
  Shield,
  LayoutDashboard,
  Bug,
  Activity,
  Network,
  BarChart3,
  FileText,
  Settings,
  Bell,
  Search,
  ChevronRight,
  Menu,
  X
} from "lucide-react";

// Pages
import Dashboard from "@/pages/Dashboard";
import Vulnerabilities from "@/pages/Vulnerabilities";
import RealTimeMonitor from "@/pages/RealTimeMonitor";
import AttackSurface from "@/pages/AttackSurface";
import Metrics from "@/pages/Metrics";
import Reports from "@/pages/Reports";
import SettingsPage from "@/pages/Settings";
import ThreatIntel from "@/pages/ThreatIntel";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Sidebar component
const Sidebar = ({ isOpen, setIsOpen }) => {
  const location = useLocation();
  
  const navItems = [
    { path: "/", icon: LayoutDashboard, label: "Dashboard" },
    { path: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
    { path: "/monitor", icon: Activity, label: "Real-time Monitor" },
    { path: "/attack-surface", icon: Network, label: "Attack Surface" },
    { path: "/metrics", icon: BarChart3, label: "Metrics" },
    { path: "/reports", icon: FileText, label: "Reports" },
    { path: "/settings", icon: Settings, label: "Settings" },
  ];

  return (
    <aside
      className={`fixed top-0 left-0 h-full w-64 sidebar z-50 transform transition-transform duration-300 lg:translate-x-0 ${
        isOpen ? "translate-x-0" : "-translate-x-full"
      }`}
      data-testid="sidebar"
    >
      <div className="p-6 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-sm">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h1 className="font-mono text-lg font-bold tracking-wider text-foreground">API GUARDIAN</h1>
            <span className="text-xs text-muted-foreground">Security Platform</span>
          </div>
        </div>
      </div>

      <nav className="p-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? "active" : ""}`
            }
            data-testid={`nav-${item.label.toLowerCase().replace(/\s+/g, "-")}`}
            onClick={() => setIsOpen(false)}
          >
            <item.icon className="w-5 h-5" />
            <span>{item.label}</span>
            {location.pathname === item.path && (
              <ChevronRight className="w-4 h-4 ml-auto" />
            )}
          </NavLink>
        ))}
      </nav>

      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-border">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="w-2 h-2 rounded-full bg-low pulse-dot" />
          <span>System Online</span>
        </div>
      </div>
    </aside>
  );
};

// TopBar component
const TopBar = ({ alertCount, onMenuClick }) => {
  return (
    <header className="sticky top-0 z-40 h-16 bg-card/80 backdrop-blur-md border-b border-border" data-testid="topbar">
      <div className="flex items-center justify-between h-full px-4 lg:px-6">
        <div className="flex items-center gap-4">
          <button
            className="lg:hidden p-2 hover:bg-muted rounded-sm"
            onClick={onMenuClick}
            data-testid="menu-toggle"
          >
            <Menu className="w-5 h-5" />
          </button>
          
          <div className="relative hidden sm:block">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search vulnerabilities, endpoints..."
              className="w-80 h-10 pl-10 pr-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
              data-testid="search-input"
            />
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button
            className="relative p-2 hover:bg-muted rounded-sm"
            data-testid="notifications-btn"
          >
            <Bell className="w-5 h-5" />
            {alertCount > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 flex items-center justify-center bg-critical text-xs font-bold rounded-full">
                {alertCount}
              </span>
            )}
          </button>
          
          <div className="w-8 h-8 rounded-sm bg-primary/20 flex items-center justify-center" data-testid="user-avatar">
            <span className="font-mono text-sm text-primary font-bold">AG</span>
          </div>
        </div>
      </div>
    </header>
  );
};

// Main Layout
const MainLayout = ({ children, alertCount }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background">
      <Sidebar isOpen={sidebarOpen} setIsOpen={setSidebarOpen} />
      
      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      
      <div className="lg:ml-64">
        <TopBar alertCount={alertCount} onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
        <main className="p-4 lg:p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

function App() {
  const [alertCount, setAlertCount] = useState(0);
  const [seeded, setSeeded] = useState(false);

  useEffect(() => {
    // Seed data on first load
    const seedData = async () => {
      try {
        await axios.post(`${API}/seed`);
        setSeeded(true);
      } catch (e) {
        console.error("Error seeding data:", e);
      }
    };

    // Fetch alert count
    const fetchAlertCount = async () => {
      try {
        const response = await axios.get(`${API}/dashboard/stats`);
        setAlertCount(response.data.unacknowledged_alerts || 0);
      } catch (e) {
        console.error("Error fetching alert count:", e);
      }
    };

    seedData().then(() => fetchAlertCount());
  }, []);

  return (
    <BrowserRouter>
      <Toaster position="top-right" theme="dark" richColors />
      <Routes>
        <Route
          path="/*"
          element={
            <MainLayout alertCount={alertCount}>
              <Routes>
                <Route index element={<Dashboard />} />
                <Route path="vulnerabilities" element={<Vulnerabilities />} />
                <Route path="monitor" element={<RealTimeMonitor />} />
                <Route path="attack-surface" element={<AttackSurface />} />
                <Route path="metrics" element={<Metrics />} />
                <Route path="reports" element={<Reports />} />
                <Route path="settings" element={<SettingsPage />} />
              </Routes>
            </MainLayout>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
