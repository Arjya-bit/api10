import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  Bug,
  Filter,
  Search,
  ChevronDown,
  ExternalLink,
  CheckCircle2,
  Clock,
  XCircle,
  AlertTriangle
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SeverityBadge = ({ severity }) => {
  const colors = {
    critical: "border-critical text-critical bg-critical/10",
    high: "border-high text-high bg-high/10",
    medium: "border-medium text-medium bg-medium/10",
    low: "border-low text-low bg-low/10",
    info: "border-info text-info bg-info/10"
  };

  return (
    <span className={`severity-badge ${colors[severity] || colors.info}`}>
      {severity}
    </span>
  );
};

const StatusBadge = ({ status }) => {
  const config = {
    open: { icon: AlertTriangle, color: "text-critical", bg: "bg-critical/10" },
    in_progress: { icon: Clock, color: "text-medium", bg: "bg-medium/10" },
    resolved: { icon: CheckCircle2, color: "text-low", bg: "bg-low/10" },
    false_positive: { icon: XCircle, color: "text-muted-foreground", bg: "bg-muted/50" }
  };

  const { icon: Icon, color, bg } = config[status] || config.open;

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-sm text-xs font-mono ${color} ${bg}`}>
      <Icon className="w-3 h-3" />
      {status.replace("_", " ")}
    </span>
  );
};

const VulnerabilityRow = ({ vuln, onSelect, onStatusChange }) => (
  <tr
    className="border-b border-border hover:bg-muted/30 cursor-pointer transition-colors"
    onClick={() => onSelect(vuln)}
    data-testid={`vuln-row-${vuln.id}`}
  >
    <td className="p-4">
      <SeverityBadge severity={vuln.severity} />
    </td>
    <td className="p-4">
      <div>
        <p className="font-medium text-sm">{vuln.title}</p>
        <p className="text-xs text-muted-foreground mt-1 line-clamp-1">
          {vuln.description}
        </p>
      </div>
    </td>
    <td className="p-4 font-mono text-xs text-muted-foreground">
      {vuln.endpoint}
    </td>
    <td className="p-4">
      <span className="inline-block px-2 py-1 bg-muted rounded-sm text-xs font-mono">
        {vuln.method}
      </span>
    </td>
    <td className="p-4 text-sm text-muted-foreground">
      {vuln.category}
    </td>
    <td className="p-4">
      <StatusBadge status={vuln.status} />
    </td>
    <td className="p-4">
      {vuln.cvss_score && (
        <span className="font-mono text-sm">
          {vuln.cvss_score.toFixed(1)}
        </span>
      )}
    </td>
  </tr>
);

const VulnerabilityDetail = ({ vuln, onClose, onStatusChange }) => {
  if (!vuln) return null;

  const handleStatusChange = async (newStatus) => {
    try {
      await axios.patch(`${API}/vulnerabilities/${vuln.id}?status=${newStatus}`);
      onStatusChange(vuln.id, newStatus);
      toast.success(`Status updated to ${newStatus}`);
    } catch (e) {
      toast.error("Failed to update status");
    }
  };

  return (
    <Dialog open={!!vuln} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl bg-card border-border">
        <DialogHeader>
          <div className="flex items-start justify-between">
            <div>
              <SeverityBadge severity={vuln.severity} />
              <DialogTitle className="mt-3 text-lg font-mono">
                {vuln.title}
              </DialogTitle>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-6 mt-4">
          <div>
            <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
              Description
            </h4>
            <p className="text-sm text-foreground/80">{vuln.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
                Endpoint
              </h4>
              <code className="text-sm font-mono text-primary bg-primary/10 px-2 py-1 rounded">
                {vuln.method} {vuln.endpoint}
              </code>
            </div>
            <div>
              <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
                Category
              </h4>
              <p className="text-sm">{vuln.category}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {vuln.cwe_id && (
              <div>
                <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  CWE ID
                </h4>
                <a
                  href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace("CWE-", "")}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-info hover:underline flex items-center gap-1"
                >
                  {vuln.cwe_id} <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}
            {vuln.cvss_score && (
              <div>
                <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  CVSS Score
                </h4>
                <p className="text-sm font-mono font-bold text-critical">
                  {vuln.cvss_score.toFixed(1)}
                </p>
              </div>
            )}
          </div>

          {vuln.recommendation && (
            <div>
              <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
                Recommendation
              </h4>
              <p className="text-sm text-foreground/80 p-3 bg-muted/30 rounded border border-border">
                {vuln.recommendation}
              </p>
            </div>
          )}

          <div>
            <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-2">
              Status
            </h4>
            <Select defaultValue={vuln.status} onValueChange={handleStatusChange}>
              <SelectTrigger className="w-48 bg-background" data-testid="status-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [filters, setFilters] = useState({
    severity: "all",
    status: "all",
    search: ""
  });

  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  const fetchVulnerabilities = async () => {
    try {
      const response = await axios.get(`${API}/vulnerabilities`);
      setVulnerabilities(response.data);
    } catch (e) {
      toast.error("Failed to fetch vulnerabilities");
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = (id, newStatus) => {
    setVulnerabilities(vulns =>
      vulns.map(v => v.id === id ? { ...v, status: newStatus } : v)
    );
    setSelectedVuln(prev => prev ? { ...prev, status: newStatus } : null);
  };

  const filteredVulns = vulnerabilities.filter(v => {
    if (filters.severity !== "all" && v.severity !== filters.severity) return false;
    if (filters.status !== "all" && v.status !== filters.status) return false;
    if (filters.search) {
      const search = filters.search.toLowerCase();
      return (
        v.title.toLowerCase().includes(search) ||
        v.endpoint.toLowerCase().includes(search) ||
        v.description.toLowerCase().includes(search)
      );
    }
    return true;
  });

  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === "critical").length,
    high: vulnerabilities.filter(v => v.severity === "high").length,
    medium: vulnerabilities.filter(v => v.severity === "medium").length,
    low: vulnerabilities.filter(v => v.severity === "low").length
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Bug className="w-12 h-12 text-primary animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="vulnerabilities-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Vulnerabilities</h1>
          <p className="text-sm text-muted-foreground mt-1">Track and manage security findings</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(severityCounts).map(([severity, count]) => (
          <div
            key={severity}
            className={`stat-card cursor-pointer ${
              filters.severity === severity ? "border-primary" : ""
            }`}
            onClick={() => setFilters(f => ({ ...f, severity: f.severity === severity ? "all" : severity }))}
            data-testid={`filter-${severity}`}
          >
            <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              {severity}
            </p>
            <p className={`text-2xl font-mono font-bold text-${severity}`}>
              {count}
            </p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            className="w-full h-10 pl-10 pr-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
            data-testid="search-vulnerabilities"
          />
        </div>

        <Select
          value={filters.severity}
          onValueChange={(v) => setFilters(f => ({ ...f, severity: v }))}
        >
          <SelectTrigger className="w-40 bg-background" data-testid="severity-filter">
            <Filter className="w-4 h-4 mr-2" />
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border">
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={filters.status}
          onValueChange={(v) => setFilters(f => ({ ...f, status: v }))}
        >
          <SelectTrigger className="w-40 bg-background" data-testid="status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="in_progress">In Progress</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full data-table">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Severity</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Vulnerability</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Endpoint</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Method</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Category</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">Status</th>
                <th className="p-4 text-left text-xs font-mono uppercase tracking-widest text-muted-foreground">CVSS</th>
              </tr>
            </thead>
            <tbody>
              {filteredVulns.map((vuln) => (
                <VulnerabilityRow
                  key={vuln.id}
                  vuln={vuln}
                  onSelect={setSelectedVuln}
                  onStatusChange={handleStatusChange}
                />
              ))}
            </tbody>
          </table>
        </div>

        {filteredVulns.length === 0 && (
          <div className="p-12 text-center">
            <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">No vulnerabilities found</p>
          </div>
        )}
      </div>

      <VulnerabilityDetail
        vuln={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
}
