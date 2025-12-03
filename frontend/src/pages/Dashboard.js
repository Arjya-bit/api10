import { useEffect, useState } from "react";
import axios from "axios";
import {
  Shield,
  Bug,
  Activity,
  Network,
  AlertTriangle,
  CheckCircle2,
  Clock,
  TrendingUp,
  TrendingDown,
  ArrowRight
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

// Stat Card Component
const StatCard = ({ title, value, icon: Icon, trend, trendValue, color, onClick }) => (
  <div
    className="stat-card card-hover cursor-pointer"
    onClick={onClick}
    data-testid={`stat-${title.toLowerCase().replace(/\s+/g, "-")}`}
  >
    <div className="flex items-start justify-between">
      <div>
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
          {title}
        </p>
        <p className={`text-3xl font-mono font-bold ${color || "text-foreground"}`}>
          {value}
        </p>
        {trend && (
          <div className="flex items-center gap-1 mt-2">
            {trend === "up" ? (
              <TrendingUp className="w-4 h-4 text-critical" />
            ) : (
              <TrendingDown className="w-4 h-4 text-low" />
            )}
            <span className={`text-xs font-mono ${trend === "up" ? "text-critical" : "text-low"}`}>
              {trendValue}
            </span>
          </div>
        )}
      </div>
      <div className={`p-3 rounded-sm ${color ? `bg-${color.replace("text-", "")}/10` : "bg-primary/10"}`}>
        <Icon className={`w-6 h-6 ${color || "text-primary"}`} />
      </div>
    </div>
  </div>
);

// Security Score Gauge
const SecurityScore = ({ score }) => {
  const getColor = (s) => {
    if (s >= 80) return "#00FF94";
    if (s >= 60) return "#F1C40F";
    if (s >= 40) return "#FF9F1C";
    return "#FF2A6D";
  };

  return (
    <div className="stat-card" data-testid="security-score">
      <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
        Security Score
      </p>
      <div className="flex items-center justify-center">
        <div className="relative w-32 h-32">
          <svg className="w-full h-full transform -rotate-90">
            <circle
              cx="64"
              cy="64"
              r="56"
              stroke="currentColor"
              strokeWidth="8"
              fill="none"
              className="text-muted"
            />
            <circle
              cx="64"
              cy="64"
              r="56"
              stroke={getColor(score)}
              strokeWidth="8"
              fill="none"
              strokeDasharray={`${(score / 100) * 352} 352`}
              strokeLinecap="round"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-3xl font-mono font-bold" style={{ color: getColor(score) }}>
              {score}
            </span>
          </div>
        </div>
      </div>
      <p className="text-center text-sm text-muted-foreground mt-4">
        {score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical"}
      </p>
    </div>
  );
};

// Recent Vulnerabilities List
const RecentVulnerabilities = ({ vulnerabilities }) => (
  <div className="stat-card col-span-12 lg:col-span-6" data-testid="recent-vulnerabilities">
    <div className="flex items-center justify-between mb-4">
      <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
        Recent Vulnerabilities
      </p>
      <Link
        to="/vulnerabilities"
        className="text-xs text-primary hover:underline flex items-center gap-1"
        data-testid="view-all-vulns"
      >
        View All <ArrowRight className="w-3 h-3" />
      </Link>
    </div>
    <div className="space-y-3">
      {vulnerabilities.slice(0, 5).map((vuln, idx) => (
        <div
          key={idx}
          className="flex items-center justify-between p-3 bg-background rounded-sm border border-border hover:border-primary/30 transition-colors"
          data-testid={`vuln-item-${idx}`}
        >
          <div className="flex items-center gap-3">
            <span className={`severity-badge severity-${vuln.severity}`}>
              {vuln.severity}
            </span>
            <div>
              <p className="text-sm font-medium">{vuln.title}</p>
              <p className="text-xs text-muted-foreground font-mono">{vuln.endpoint}</p>
            </div>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {vuln.method}
          </span>
        </div>
      ))}
    </div>
  </div>
);

// Active Scans Widget
const ActiveScans = ({ scans }) => (
  <div className="stat-card col-span-12 lg:col-span-6" data-testid="active-scans">
    <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
      Active Scans
    </p>
    <div className="space-y-3">
      {scans.map((scan, idx) => (
        <div
          key={idx}
          className="p-3 bg-background rounded-sm border border-border"
          data-testid={`scan-item-${idx}`}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className={`status-dot status-${scan.status}`} />
              <span className="text-sm font-medium">{scan.name}</span>
            </div>
            <span className="text-xs font-mono text-muted-foreground">
              {scan.progress}%
            </span>
          </div>
          <div className="w-full h-1 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full progress-bar transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-muted-foreground font-mono">
              {scan.target_url}
            </span>
            <span className="text-xs text-muted-foreground">
              {scan.findings_count} findings
            </span>
          </div>
        </div>
      ))}
    </div>
  </div>
);

// Vulnerability Trend Chart
const VulnerabilityTrendChart = ({ data }) => (
  <div className="stat-card col-span-12 lg:col-span-8" data-testid="vuln-trend-chart">
    <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
      Vulnerability Trend (7 Days)
    </p>
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF2A6D" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#FF2A6D" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="highGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF9F1C" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#FF9F1C" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="date"
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
            tickFormatter={(val) => val.split("-")[2]}
          />
          <YAxis
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0A0A0A",
              border: "1px solid #27272A",
              borderRadius: "4px",
              fontFamily: "JetBrains Mono",
              fontSize: "12px"
            }}
          />
          <Area
            type="monotone"
            dataKey="critical"
            stroke="#FF2A6D"
            fill="url(#criticalGradient)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="high"
            stroke="#FF9F1C"
            fill="url(#highGradient)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </div>
);

// Category Distribution
const CategoryDistribution = ({ data }) => {
  const COLORS = ["#FF2A6D", "#FF9F1C", "#F1C40F", "#00FF94", "#5865F2"];

  return (
    <div className="stat-card col-span-12 lg:col-span-4" data-testid="category-distribution">
      <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
        By Category
      </p>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={40}
              outerRadius={70}
              paddingAngle={2}
              dataKey="count"
              nameKey="category"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "#0A0A0A",
                border: "1px solid #27272A",
                borderRadius: "4px",
                fontFamily: "JetBrains Mono",
                fontSize: "12px"
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="space-y-2 mt-2">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: COLORS[idx % COLORS.length] }}
              />
              <span className="text-muted-foreground">{item.category}</span>
            </div>
            <span className="font-mono">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [scans, setScans] = useState([]);
  const [trends, setTrends] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, vulnsRes, scansRes, trendsRes] = await Promise.all([
          axios.get(`${API}/dashboard/stats`),
          axios.get(`${API}/vulnerabilities?limit=5`),
          axios.get(`${API}/scans?limit=3`),
          axios.get(`${API}/metrics/trends`)
        ]);

        setStats(statsRes.data);
        setVulnerabilities(vulnsRes.data);
        setScans(scansRes.data);
        setTrends(trendsRes.data);
      } catch (e) {
        console.error("Error fetching dashboard data:", e);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Shield className="w-12 h-12 text-primary mx-auto mb-4 animate-pulse" />
          <p className="text-muted-foreground font-mono text-sm">Loading security data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="dashboard-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Security overview and real-time monitoring</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="dashboard-grid">
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Total Vulnerabilities"
            value={stats?.vulnerabilities?.total || 0}
            icon={Bug}
            trend="up"
            trendValue="+3 this week"
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Critical Issues"
            value={stats?.vulnerabilities?.critical || 0}
            icon={AlertTriangle}
            color="text-critical"
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Active Scans"
            value={stats?.scans?.running || 0}
            icon={Activity}
            color="text-primary"
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <SecurityScore score={stats?.security_score || 0} />
        </div>
      </div>

      {/* Secondary Stats */}
      <div className="dashboard-grid">
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="High Severity"
            value={stats?.vulnerabilities?.high || 0}
            icon={AlertTriangle}
            color="text-high"
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Open Issues"
            value={stats?.vulnerabilities?.open || 0}
            icon={Clock}
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Resolved"
            value={stats?.vulnerabilities?.resolved || 0}
            icon={CheckCircle2}
            color="text-low"
          />
        </div>
        <div className="col-span-6 md:col-span-3">
          <StatCard
            title="Endpoints"
            value={stats?.endpoints || 0}
            icon={Network}
          />
        </div>
      </div>

      {/* Charts Row */}
      <div className="dashboard-grid">
        <VulnerabilityTrendChart data={trends?.daily_vulnerabilities || []} />
        <CategoryDistribution data={trends?.category_distribution || []} />
      </div>

      {/* Lists Row */}
      <div className="dashboard-grid">
        <RecentVulnerabilities vulnerabilities={vulnerabilities} />
        <ActiveScans scans={scans} />
      </div>
    </div>
  );
}
