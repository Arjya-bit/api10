import { useEffect, useState } from "react";
import axios from "axios";
import {
  Network,
  Shield,
  AlertTriangle,
  Lock,
  Unlock,
  ExternalLink
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const RiskIndicator = ({ score }) => {
  const getColor = (s) => {
    if (s >= 8) return "#FF2A6D";
    if (s >= 6) return "#FF9F1C";
    if (s >= 4) return "#F1C40F";
    return "#00FF94";
  };

  return (
    <div className="flex items-center gap-2">
      <div
        className="w-2 h-2 rounded-full"
        style={{ backgroundColor: getColor(score) }}
      />
      <span className="font-mono text-sm" style={{ color: getColor(score) }}>
        {score.toFixed(1)}
      </span>
    </div>
  );
};

const EndpointNode = ({ endpoint, onClick }) => {
  const getRiskColor = (score) => {
    if (score >= 8) return "border-critical bg-critical/10";
    if (score >= 6) return "border-high bg-high/10";
    if (score >= 4) return "border-medium bg-medium/10";
    return "border-low bg-low/10";
  };

  const getMethodColor = (method) => {
    const colors = {
      GET: "text-info",
      POST: "text-low",
      PUT: "text-medium",
      PATCH: "text-high",
      DELETE: "text-critical"
    };
    return colors[method] || "text-muted-foreground";
  };

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={`endpoint-node p-4 border rounded-sm cursor-pointer ${getRiskColor(endpoint.risk_score)}`}
            onClick={() => onClick(endpoint)}
            data-testid={`endpoint-${endpoint.id}`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className={`font-mono text-xs font-bold ${getMethodColor(endpoint.method)}`}>
                {endpoint.method}
              </span>
              <RiskIndicator score={endpoint.risk_score} />
            </div>
            <code className="text-sm font-mono text-foreground block truncate">
              {endpoint.path}
            </code>
            <div className="flex items-center gap-2 mt-2">
              {endpoint.auth_required ? (
                <Lock className="w-3 h-3 text-medium" />
              ) : (
                <Unlock className="w-3 h-3 text-muted-foreground" />
              )}
              {endpoint.vulnerabilities_count > 0 && (
                <span className="flex items-center gap-1 text-xs text-critical">
                  <AlertTriangle className="w-3 h-3" />
                  {endpoint.vulnerabilities_count}
                </span>
              )}
            </div>
          </div>
        </TooltipTrigger>
        <TooltipContent className="bg-card border-border">
          <p className="font-mono text-xs">{endpoint.description || "No description"}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};

const EndpointDetail = ({ endpoint, onClose }) => {
  if (!endpoint) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-card border-l border-border p-6 z-50 overflow-y-auto">
      <div className="flex items-center justify-between mb-6">
        <h3 className="font-mono text-lg font-bold">Endpoint Details</h3>
        <button
          onClick={onClose}
          className="p-2 hover:bg-muted rounded-sm"
          data-testid="close-detail"
        >
          <span className="text-xl">&times;</span>
        </button>
      </div>

      <div className="space-y-6">
        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Path
          </p>
          <code className="text-sm font-mono text-primary bg-primary/10 px-2 py-1 rounded block">
            {endpoint.method} {endpoint.path}
          </code>
        </div>

        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Risk Score
          </p>
          <RiskIndicator score={endpoint.risk_score} />
        </div>

        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Authentication
          </p>
          <div className="flex items-center gap-2">
            {endpoint.auth_required ? (
              <>
                <Lock className="w-4 h-4 text-medium" />
                <span className="text-sm">Required</span>
              </>
            ) : (
              <>
                <Unlock className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">Not Required</span>
              </>
            )}
          </div>
        </div>

        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Description
          </p>
          <p className="text-sm text-foreground/80">
            {endpoint.description || "No description available"}
          </p>
        </div>

        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Vulnerabilities
          </p>
          <p className="text-sm">
            {endpoint.vulnerabilities_count > 0 ? (
              <span className="text-critical">
                {endpoint.vulnerabilities_count} vulnerability(s) found
              </span>
            ) : (
              <span className="text-low">No vulnerabilities detected</span>
            )}
          </p>
        </div>

        {endpoint.tags && endpoint.tags.length > 0 && (
          <div>
            <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
              Tags
            </p>
            <div className="flex flex-wrap gap-2">
              {endpoint.tags.map((tag, idx) => (
                <span
                  key={idx}
                  className="px-2 py-1 bg-muted rounded-sm text-xs font-mono"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Status
          </p>
          <span className={`px-2 py-1 rounded-sm text-xs font-mono ${
            endpoint.status === "active" 
              ? "bg-low/10 text-low" 
              : "bg-muted text-muted-foreground"
          }`}>
            {endpoint.status}
          </span>
        </div>
      </div>
    </div>
  );
};

const LegendItem = ({ color, label }) => (
  <div className="flex items-center gap-2">
    <div className={`w-3 h-3 rounded-sm ${color}`} />
    <span className="text-xs text-muted-foreground">{label}</span>
  </div>
);

export default function AttackSurface() {
  const [endpoints, setEndpoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [groupBy, setGroupBy] = useState("risk");

  useEffect(() => {
    const fetchEndpoints = async () => {
      try {
        const response = await axios.get(`${API}/endpoints`);
        setEndpoints(response.data);
      } catch (e) {
        console.error("Error fetching endpoints:", e);
      } finally {
        setLoading(false);
      }
    };

    fetchEndpoints();
  }, []);

  const groupedEndpoints = () => {
    if (groupBy === "risk") {
      return {
        "Critical Risk (8+)": endpoints.filter(e => e.risk_score >= 8),
        "High Risk (6-8)": endpoints.filter(e => e.risk_score >= 6 && e.risk_score < 8),
        "Medium Risk (4-6)": endpoints.filter(e => e.risk_score >= 4 && e.risk_score < 6),
        "Low Risk (<4)": endpoints.filter(e => e.risk_score < 4)
      };
    }
    if (groupBy === "method") {
      const methods = [...new Set(endpoints.map(e => e.method))];
      return methods.reduce((acc, method) => {
        acc[method] = endpoints.filter(e => e.method === method);
        return acc;
      }, {});
    }
    if (groupBy === "auth") {
      return {
        "Authentication Required": endpoints.filter(e => e.auth_required),
        "Public Endpoints": endpoints.filter(e => !e.auth_required)
      };
    }
    return { "All Endpoints": endpoints };
  };

  const stats = {
    total: endpoints.length,
    critical: endpoints.filter(e => e.risk_score >= 8).length,
    vulnerable: endpoints.filter(e => e.vulnerabilities_count > 0).length,
    public: endpoints.filter(e => !e.auth_required).length
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Network className="w-12 h-12 text-primary animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="attack-surface-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Attack Surface</h1>
          <p className="text-sm text-muted-foreground mt-1">API endpoint mapping and risk assessment</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card">
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Total Endpoints</p>
          <p className="text-2xl font-mono font-bold">{stats.total}</p>
        </div>
        <div className="stat-card">
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Critical Risk</p>
          <p className="text-2xl font-mono font-bold text-critical">{stats.critical}</p>
        </div>
        <div className="stat-card">
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">With Vulnerabilities</p>
          <p className="text-2xl font-mono font-bold text-high">{stats.vulnerable}</p>
        </div>
        <div className="stat-card">
          <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Public Endpoints</p>
          <p className="text-2xl font-mono font-bold text-medium">{stats.public}</p>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-mono">GROUP BY:</span>
          {["risk", "method", "auth"].map((g) => (
            <button
              key={g}
              onClick={() => setGroupBy(g)}
              className={`px-3 py-1 rounded-sm font-mono text-xs uppercase ${
                groupBy === g
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
              data-testid={`group-${g}`}
            >
              {g}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <LegendItem color="bg-critical" label="Critical" />
          <LegendItem color="bg-high" label="High" />
          <LegendItem color="bg-medium" label="Medium" />
          <LegendItem color="bg-low" label="Low" />
        </div>
      </div>

      {/* Endpoint Grid */}
      <div className="space-y-6">
        {Object.entries(groupedEndpoints()).map(([group, eps]) => (
          eps.length > 0 && (
            <div key={group}>
              <h3 className="text-sm font-mono uppercase tracking-widest text-muted-foreground mb-3">
                {group} ({eps.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {eps.map((endpoint) => (
                  <EndpointNode
                    key={endpoint.id}
                    endpoint={endpoint}
                    onClick={setSelectedEndpoint}
                  />
                ))}
              </div>
            </div>
          )
        ))}
      </div>

      {/* Detail Panel */}
      {selectedEndpoint && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => setSelectedEndpoint(null)}
          />
          <EndpointDetail
            endpoint={selectedEndpoint}
            onClose={() => setSelectedEndpoint(null)}
          />
        </>
      )}
    </div>
  );
}
