import { useEffect, useState } from "react";
import axios from "axios";
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Activity
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const ChartCard = ({ title, children, className = "" }) => (
  <div className={`chart-container p-4 ${className}`}>
    <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-4">
      {title}
    </p>
    {children}
  </div>
);

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-card border border-border rounded-sm p-3">
        <p className="font-mono text-xs text-muted-foreground mb-1">{label}</p>
        {payload.map((entry, index) => (
          <p
            key={index}
            className="font-mono text-sm"
            style={{ color: entry.color }}
          >
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

const VulnerabilityTrendChart = ({ data }) => (
  <ChartCard title="Vulnerability Trend (7 Days)" className="col-span-12 lg:col-span-8">
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="criticalArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF2A6D" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#FF2A6D" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="highArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF9F1C" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#FF9F1C" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="mediumArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#F1C40F" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#F1C40F" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="lowArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00FF94" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#00FF94" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="date"
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
            tickFormatter={(val) => val.split("-").slice(1).join("/")}
          />
          <YAxis
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="critical"
            name="Critical"
            stroke="#FF2A6D"
            fill="url(#criticalArea)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="high"
            name="High"
            stroke="#FF9F1C"
            fill="url(#highArea)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="medium"
            name="Medium"
            stroke="#F1C40F"
            fill="url(#mediumArea)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="low"
            name="Low"
            stroke="#00FF94"
            fill="url(#lowArea)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </ChartCard>
);

const ScanActivityChart = ({ data }) => (
  <ChartCard title="Scan Activity" className="col-span-12 lg:col-span-4">
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
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
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="scans" name="Scans" fill="#00FF94" radius={[2, 2, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  </ChartCard>
);

const CategoryDistributionChart = ({ data }) => {
  const COLORS = ["#FF2A6D", "#FF9F1C", "#F1C40F", "#00FF94", "#5865F2"];

  return (
    <ChartCard title="Vulnerabilities by Category" className="col-span-12 md:col-span-6">
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              paddingAngle={2}
              dataKey="count"
              nameKey="category"
              label={({ category, percent }) => `${(percent * 100).toFixed(0)}%`}
              labelLine={false}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value) => <span className="text-xs text-muted-foreground">{value}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </ChartCard>
  );
};

const FindingsOverTimeChart = ({ data }) => (
  <ChartCard title="Findings Over Time" className="col-span-12 md:col-span-6">
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <XAxis
            dataKey="date"
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
            tickFormatter={(val) => val.split("-").slice(1).join("/")}
          />
          <YAxis
            tick={{ fill: "#71717A", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#27272A" }}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="findings"
            name="Findings"
            stroke="#5865F2"
            strokeWidth={2}
            dot={{ fill: "#5865F2", strokeWidth: 0, r: 4 }}
            activeDot={{ fill: "#5865F2", strokeWidth: 0, r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  </ChartCard>
);

const MetricCard = ({ title, value, change, trend, icon: Icon }) => (
  <div className="stat-card">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
          {title}
        </p>
        <p className="text-3xl font-mono font-bold">{value}</p>
        {change !== undefined && (
          <div className="flex items-center gap-1 mt-2">
            {trend === "up" ? (
              <TrendingUp className="w-4 h-4 text-critical" />
            ) : trend === "down" ? (
              <TrendingDown className="w-4 h-4 text-low" />
            ) : null}
            <span className={`text-xs font-mono ${trend === "up" ? "text-critical" : "text-low"}`}>
              {change > 0 ? "+" : ""}{change}%
            </span>
          </div>
        )}
      </div>
      {Icon && (
        <div className="p-3 bg-primary/10 rounded-sm">
          <Icon className="w-6 h-6 text-primary" />
        </div>
      )}
    </div>
  </div>
);

export default function Metrics() {
  const [trends, setTrends] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [trendsRes, statsRes] = await Promise.all([
          axios.get(`${API}/metrics/trends`),
          axios.get(`${API}/dashboard/stats`)
        ]);
        setTrends(trendsRes.data);
        setStats(statsRes.data);
      } catch (e) {
        console.error("Error fetching metrics:", e);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <BarChart3 className="w-12 h-12 text-primary animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="metrics-page">
      <div>
        <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Metrics</h1>
        <p className="text-sm text-muted-foreground mt-1">Security analytics and trends</p>
      </div>

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Total Scans"
          value={stats?.scans?.total || 0}
          change={12}
          trend="up"
          icon={Activity}
        />
        <MetricCard
          title="Total Findings"
          value={stats?.vulnerabilities?.total || 0}
          change={-8}
          trend="down"
        />
        <MetricCard
          title="Critical Issues"
          value={stats?.vulnerabilities?.critical || 0}
          change={5}
          trend="up"
        />
        <MetricCard
          title="Security Score"
          value={stats?.security_score || 0}
          change={-3}
          trend="down"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-12 gap-4 md:gap-6">
        <VulnerabilityTrendChart data={trends?.daily_vulnerabilities || []} />
        <ScanActivityChart data={trends?.scan_activity || []} />
        <CategoryDistributionChart data={trends?.category_distribution || []} />
        <FindingsOverTimeChart data={trends?.scan_activity || []} />
      </div>
    </div>
  );
}
