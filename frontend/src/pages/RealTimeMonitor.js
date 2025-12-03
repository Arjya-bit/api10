import { useEffect, useState, useRef } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  Activity,
  Bell,
  CheckCircle,
  AlertTriangle,
  Shield,
  Zap,
  Lock,
  RefreshCw
} from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const AlertIcon = ({ type }) => {
  const icons = {
    vulnerability: AlertTriangle,
    anomaly: Zap,
    rate_limit: Shield,
    auth_failure: Lock,
    injection: AlertTriangle
  };
  const Icon = icons[type] || AlertTriangle;
  return <Icon className="w-5 h-5" />;
};

const AlertCard = ({ alert, onAcknowledge }) => {
  const severityColors = {
    critical: "border-l-critical bg-critical/5",
    high: "border-l-high bg-high/5",
    medium: "border-l-medium bg-medium/5",
    low: "border-l-low bg-low/5",
    info: "border-l-info bg-info/5"
  };

  const severityTextColors = {
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
    info: "text-info"
  };

  return (
    <div
      className={`alert-item p-4 border border-border border-l-4 ${severityColors[alert.severity]} rounded-sm mb-3`}
      data-testid={`alert-${alert.id}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-sm bg-background ${severityTextColors[alert.severity]}`}>
            <AlertIcon type={alert.alert_type} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-sm">{alert.title}</h3>
              <span className={`text-xs font-mono uppercase ${severityTextColors[alert.severity]}`}>
                {alert.severity}
              </span>
            </div>
            <p className="text-sm text-muted-foreground mt-1">{alert.message}</p>
            {alert.endpoint && (
              <code className="text-xs font-mono text-primary mt-2 block">
                {alert.endpoint}
              </code>
            )}
            <div className="flex items-center gap-4 mt-2">
              <span className="text-xs text-muted-foreground">
                Source: {alert.source}
              </span>
              <span className="text-xs text-muted-foreground">
                {new Date(alert.created_at).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
        
        {!alert.acknowledged && (
          <button
            onClick={() => onAcknowledge(alert.id)}
            className="p-2 hover:bg-muted rounded-sm transition-colors"
            data-testid={`ack-${alert.id}`}
          >
            <CheckCircle className="w-5 h-5 text-muted-foreground hover:text-primary" />
          </button>
        )}
      </div>
    </div>
  );
};

const LiveIndicator = ({ isLive }) => (
  <div className="flex items-center gap-2">
    <div className={`w-2 h-2 rounded-full ${isLive ? "bg-low pulse-dot" : "bg-muted"}`} />
    <span className="text-xs font-mono text-muted-foreground">
      {isLive ? "LIVE" : "PAUSED"}
    </span>
  </div>
);

const StatsWidget = ({ alerts }) => {
  const unacked = alerts.filter(a => !a.acknowledged).length;
  const critical = alerts.filter(a => a.severity === "critical").length;
  const high = alerts.filter(a => a.severity === "high").length;

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="stat-card">
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Unacknowledged</p>
        <p className="text-2xl font-mono font-bold text-foreground mt-1">{unacked}</p>
      </div>
      <div className="stat-card">
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Critical</p>
        <p className="text-2xl font-mono font-bold text-critical mt-1">{critical}</p>
      </div>
      <div className="stat-card">
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">High</p>
        <p className="text-2xl font-mono font-bold text-high mt-1">{high}</p>
      </div>
    </div>
  );
};

export default function RealTimeMonitor() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isLive, setIsLive] = useState(true);
  const [filter, setFilter] = useState("all");
  const intervalRef = useRef(null);

  const fetchAlerts = async () => {
    try {
      const response = await axios.get(`${API}/alerts`);
      setAlerts(response.data);
    } catch (e) {
      console.error("Error fetching alerts:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();

    if (isLive) {
      intervalRef.current = setInterval(fetchAlerts, 5000);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isLive]);

  const handleAcknowledge = async (alertId) => {
    try {
      await axios.patch(`${API}/alerts/${alertId}/acknowledge`);
      setAlerts(alerts.map(a => 
        a.id === alertId ? { ...a, acknowledged: true } : a
      ));
      toast.success("Alert acknowledged");
    } catch (e) {
      toast.error("Failed to acknowledge alert");
    }
  };

  const filteredAlerts = alerts.filter(a => {
    if (filter === "unacked") return !a.acknowledged;
    if (filter === "critical") return a.severity === "critical";
    if (filter === "high") return a.severity === "high";
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Activity className="w-12 h-12 text-primary animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="realtime-monitor-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Real-Time Monitor</h1>
          <p className="text-sm text-muted-foreground mt-1">Live security alerts and events</p>
        </div>
        <div className="flex items-center gap-4">
          <LiveIndicator isLive={isLive} />
          <button
            onClick={() => setIsLive(!isLive)}
            className={`px-4 py-2 rounded-sm font-mono text-xs uppercase tracking-wider transition-colors ${
              isLive
                ? "bg-primary/10 text-primary border border-primary"
                : "bg-muted text-muted-foreground border border-border"
            }`}
            data-testid="toggle-live"
          >
            {isLive ? "Pause" : "Resume"}
          </button>
          <button
            onClick={fetchAlerts}
            className="p-2 hover:bg-muted rounded-sm"
            data-testid="refresh-alerts"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
        </div>
      </div>

      <StatsWidget alerts={alerts} />

      {/* Filters */}
      <div className="flex items-center gap-2">
        {["all", "unacked", "critical", "high"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-4 py-2 rounded-sm font-mono text-xs uppercase tracking-wider transition-colors ${
              filter === f
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:bg-muted/80"
            }`}
            data-testid={`filter-${f}`}
          >
            {f === "unacked" ? "Unacknowledged" : f}
          </button>
        ))}
      </div>

      {/* Alert Feed */}
      <div className="space-y-0" data-testid="alert-feed">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onAcknowledge={handleAcknowledge}
            />
          ))
        ) : (
          <div className="text-center py-12">
            <Bell className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">No alerts to display</p>
          </div>
        )}
      </div>
    </div>
  );
}
