import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  Globe,
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Hash,
  Link2,
  Server,
  RefreshCw,
  History,
  ExternalLink,
  Loader2
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const ThreatLevelBadge = ({ level }) => {
  const config = {
    malicious: { icon: AlertTriangle, color: "text-critical", bg: "bg-critical/10", border: "border-critical" },
    suspicious: { icon: AlertTriangle, color: "text-high", bg: "bg-high/10", border: "border-high" },
    clean: { icon: CheckCircle, color: "text-low", bg: "bg-low/10", border: "border-low" },
    unknown: { icon: HelpCircle, color: "text-muted-foreground", bg: "bg-muted/50", border: "border-muted" }
  };

  const { icon: Icon, color, bg, border } = config[level] || config.unknown;

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-mono uppercase ${color} ${bg} border ${border}`}>
      <Icon className="w-3.5 h-3.5" />
      {level}
    </span>
  );
};

const AnalysisTypeIcon = ({ type }) => {
  const icons = {
    ip: Server,
    url: Link2,
    hash: Hash
  };
  const Icon = icons[type] || Globe;
  return <Icon className="w-4 h-4" />;
};

const StatCard = ({ title, value, icon: Icon, color }) => (
  <div className="stat-card">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-xs font-mono uppercase tracking-widest text-muted-foreground">{title}</p>
        <p className={`text-2xl font-mono font-bold mt-1 ${color || "text-foreground"}`}>{value}</p>
      </div>
      <div className={`p-3 rounded-sm ${color ? `${color.replace("text-", "bg-")}/10` : "bg-primary/10"}`}>
        <Icon className={`w-5 h-5 ${color || "text-primary"}`} />
      </div>
    </div>
  </div>
);

const IPAnalysisResult = ({ data }) => (
  <div className="space-y-4">
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <Server className="w-5 h-5 text-primary" />
        <code className="text-lg font-mono">{data.ip_address}</code>
      </div>
      <ThreatLevelBadge level={data.threat_level} />
    </div>

    <div className="grid grid-cols-2 gap-4">
      {/* VirusTotal Results */}
      <div className="p-4 bg-muted/30 rounded-sm border border-border">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-4 h-4 text-info" />
          <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">VirusTotal</h4>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <span className="text-xs text-muted-foreground">Malicious</span>
            <p className="text-lg font-mono font-bold text-critical">{data.vt_malicious}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Suspicious</span>
            <p className="text-lg font-mono font-bold text-high">{data.vt_suspicious}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Harmless</span>
            <p className="text-lg font-mono font-bold text-low">{data.vt_harmless}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Undetected</span>
            <p className="text-lg font-mono font-bold text-muted-foreground">{data.vt_undetected}</p>
          </div>
        </div>
        {data.vt_country && (
          <div className="mt-3 pt-3 border-t border-border">
            <span className="text-xs text-muted-foreground">Country: </span>
            <span className="text-sm font-mono">{data.vt_country}</span>
            {data.vt_as_owner && (
              <span className="text-xs text-muted-foreground ml-3">ASN: {data.vt_as_owner}</span>
            )}
          </div>
        )}
      </div>

      {/* AbuseIPDB Results */}
      <div className="p-4 bg-muted/30 rounded-sm border border-border">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-4 h-4 text-high" />
          <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">AbuseIPDB</h4>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">Abuse Confidence Score</span>
            <span className={`text-lg font-mono font-bold ${
              data.abuse_confidence_score >= 80 ? "text-critical" :
              data.abuse_confidence_score >= 50 ? "text-high" :
              data.abuse_confidence_score >= 25 ? "text-medium" : "text-low"
            }`}>{data.abuse_confidence_score}%</span>
          </div>
          <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
            <div 
              className={`h-full transition-all ${
                data.abuse_confidence_score >= 80 ? "bg-critical" :
                data.abuse_confidence_score >= 50 ? "bg-high" :
                data.abuse_confidence_score >= 25 ? "bg-medium" : "bg-low"
              }`}
              style={{ width: `${data.abuse_confidence_score}%` }}
            />
          </div>
          <div className="grid grid-cols-2 gap-2 mt-3">
            <div>
              <span className="text-xs text-muted-foreground">Total Reports</span>
              <p className="font-mono">{data.abuse_total_reports}</p>
            </div>
            {data.abuse_isp && (
              <div>
                <span className="text-xs text-muted-foreground">ISP</span>
                <p className="font-mono text-sm truncate">{data.abuse_isp}</p>
              </div>
            )}
          </div>
          <div className="flex items-center gap-3 mt-2">
            {data.abuse_is_tor && (
              <span className="px-2 py-1 bg-critical/10 text-critical text-xs rounded-sm font-mono">TOR</span>
            )}
            {data.abuse_is_whitelisted && (
              <span className="px-2 py-1 bg-low/10 text-low text-xs rounded-sm font-mono">WHITELISTED</span>
            )}
            {data.abuse_usage_type && (
              <span className="px-2 py-1 bg-info/10 text-info text-xs rounded-sm font-mono">{data.abuse_usage_type}</span>
            )}
          </div>
        </div>
      </div>
    </div>
  </div>
);

const URLAnalysisResult = ({ data }) => (
  <div className="space-y-4">
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <Link2 className="w-5 h-5 text-primary" />
        <code className="text-sm font-mono break-all">{data.url}</code>
      </div>
      <ThreatLevelBadge level={data.threat_level} />
    </div>

    <div className="p-4 bg-muted/30 rounded-sm border border-border">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="w-4 h-4 text-info" />
        <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">VirusTotal Analysis</h4>
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div>
          <span className="text-xs text-muted-foreground">Malicious</span>
          <p className="text-2xl font-mono font-bold text-critical">{data.vt_malicious}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Suspicious</span>
          <p className="text-2xl font-mono font-bold text-high">{data.vt_suspicious}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Harmless</span>
          <p className="text-2xl font-mono font-bold text-low">{data.vt_harmless}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Undetected</span>
          <p className="text-2xl font-mono font-bold text-muted-foreground">{data.vt_undetected}</p>
        </div>
      </div>
      {data.vt_last_http_response_code && (
        <div className="mt-3 pt-3 border-t border-border">
          <span className="text-xs text-muted-foreground">HTTP Response: </span>
          <span className="font-mono">{data.vt_last_http_response_code}</span>
        </div>
      )}
    </div>
  </div>
);

const HashAnalysisResult = ({ data }) => (
  <div className="space-y-4">
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <Hash className="w-5 h-5 text-primary" />
        <div>
          <code className="text-sm font-mono break-all">{data.file_hash}</code>
          <span className="ml-2 px-2 py-0.5 bg-muted text-xs rounded-sm font-mono uppercase">{data.hash_type}</span>
        </div>
      </div>
      <ThreatLevelBadge level={data.threat_level} />
    </div>

    <div className="p-4 bg-muted/30 rounded-sm border border-border">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="w-4 h-4 text-info" />
        <h4 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">VirusTotal Analysis</h4>
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div>
          <span className="text-xs text-muted-foreground">Malicious</span>
          <p className="text-2xl font-mono font-bold text-critical">{data.vt_malicious}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Suspicious</span>
          <p className="text-2xl font-mono font-bold text-high">{data.vt_suspicious}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Harmless</span>
          <p className="text-2xl font-mono font-bold text-low">{data.vt_harmless}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Undetected</span>
          <p className="text-2xl font-mono font-bold text-muted-foreground">{data.vt_undetected}</p>
        </div>
      </div>
      {(data.vt_file_type || data.vt_file_size) && (
        <div className="mt-3 pt-3 border-t border-border flex gap-6">
          {data.vt_file_type && (
            <div>
              <span className="text-xs text-muted-foreground">File Type: </span>
              <span className="font-mono text-sm">{data.vt_file_type}</span>
            </div>
          )}
          {data.vt_file_size && (
            <div>
              <span className="text-xs text-muted-foreground">Size: </span>
              <span className="font-mono text-sm">{(data.vt_file_size / 1024).toFixed(2)} KB</span>
            </div>
          )}
        </div>
      )}
      {data.vt_tags && data.vt_tags.length > 0 && (
        <div className="mt-3 pt-3 border-t border-border">
          <span className="text-xs text-muted-foreground">Tags: </span>
          <div className="flex flex-wrap gap-1 mt-1">
            {data.vt_tags.map((tag, idx) => (
              <span key={idx} className="px-2 py-0.5 bg-muted text-xs rounded-sm font-mono">{tag}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  </div>
);

const HistoryItem = ({ item, onClick }) => (
  <div 
    className="flex items-center justify-between p-3 bg-background rounded-sm border border-border hover:border-primary/30 cursor-pointer transition-colors"
    onClick={() => onClick(item)}
    data-testid={`history-${item.id}`}
  >
    <div className="flex items-center gap-3">
      <AnalysisTypeIcon type={item.type || item.analysis_type} />
      <div>
        <code className="text-sm font-mono truncate max-w-xs block">
          {item.ip_address || item.url || item.file_hash}
        </code>
        <span className="text-xs text-muted-foreground">
          {new Date(item.analyzed_at).toLocaleString()}
        </span>
      </div>
    </div>
    <ThreatLevelBadge level={item.threat_level} />
  </div>
);

export default function ThreatIntel() {
  const [searchValue, setSearchValue] = useState("");
  const [analysisType, setAnalysisType] = useState("ip");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetchHistory();
    fetchStats();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API}/analysis/history?limit=20`);
      setHistory(response.data);
    } catch (e) {
      console.error("Error fetching history:", e);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/analysis/stats`);
      setStats(response.data);
    } catch (e) {
      console.error("Error fetching stats:", e);
    }
  };

  const handleAnalyze = async () => {
    console.log("handleAnalyze called, searchValue:", searchValue);
    if (!searchValue.trim()) {
      toast.error("Please enter a value to analyze");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      let endpoint = "";
      switch (analysisType) {
        case "ip":
          endpoint = `/analysis/ip?ip_address=${encodeURIComponent(searchValue)}`;
          break;
        case "url":
          endpoint = `/analysis/url?url=${encodeURIComponent(searchValue)}`;
          break;
        case "hash":
          endpoint = `/analysis/hash?file_hash=${encodeURIComponent(searchValue)}`;
          break;
        default:
          throw new Error("Invalid analysis type");
      }

      const response = await axios.post(`${API}${endpoint}`);
      setResult({ type: analysisType, data: response.data });
      toast.success("Analysis complete");
      fetchHistory();
      fetchStats();
    } catch (e) {
      console.error("Analysis error:", e);
      toast.error(e.response?.data?.detail || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const handleHistoryClick = (item) => {
    const type = item.type || item.analysis_type;
    setResult({ type, data: item });
    setAnalysisType(type);
    setSearchValue(item.ip_address || item.url || item.file_hash);
  };

  return (
    <div className="space-y-6" data-testid="threat-intel-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Threat Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1">Analyze IPs, URLs, and file hashes with VirusTotal & AbuseIPDB</p>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard 
            title="Total Analyses" 
            value={stats.total_analyses} 
            icon={Globe}
          />
          <StatCard 
            title="IP Analyses" 
            value={stats.by_type?.ip || 0} 
            icon={Server}
          />
          <StatCard 
            title="Malicious Found" 
            value={stats.threats?.malicious || 0} 
            icon={AlertTriangle}
            color="text-critical"
          />
          <StatCard 
            title="Suspicious Found" 
            value={stats.threats?.suspicious || 0} 
            icon={AlertTriangle}
            color="text-high"
          />
        </div>
      )}

      {/* Integration Status */}
      {stats?.integrations && (
        <div className="flex items-center gap-4 p-3 bg-muted/30 rounded-sm border border-border">
          <span className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Integrations:</span>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${stats.integrations.virustotal ? "bg-low" : "bg-critical"}`} />
            <span className="text-sm">VirusTotal</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${stats.integrations.abuseipdb ? "bg-low" : "bg-critical"}`} />
            <span className="text-sm">AbuseIPDB</span>
          </div>
        </div>
      )}

      {/* Search Section */}
      <div className="stat-card">
        <div className="flex flex-col md:flex-row gap-4">
          <Select value={analysisType} onValueChange={setAnalysisType}>
            <SelectTrigger className="w-full md:w-40 bg-background" data-testid="analysis-type-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-card border-border">
              <SelectItem value="ip">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4" />
                  <span>IP Address</span>
                </div>
              </SelectItem>
              <SelectItem value="url">
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4" />
                  <span>URL</span>
                </div>
              </SelectItem>
              <SelectItem value="hash">
                <div className="flex items-center gap-2">
                  <Hash className="w-4 h-4" />
                  <span>File Hash</span>
                </div>
              </SelectItem>
            </SelectContent>
          </Select>

          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder={
                analysisType === "ip" ? "Enter IP address (e.g., 8.8.8.8)" :
                analysisType === "url" ? "Enter URL (e.g., https://example.com)" :
                "Enter file hash (MD5, SHA1, or SHA256)"
              }
              className="w-full h-10 pl-10 pr-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
              value={searchValue}
              onChange={(e) => {
                console.log("Input changed:", e.target.value);
                setSearchValue(e.target.value);
              }}
              onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
              data-testid="search-input"
            />
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="flex items-center justify-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-sm uppercase tracking-wider hover:bg-primary/90 disabled:opacity-50 transition-colors"
            data-testid="analyze-btn"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Analyze
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results Section */}
      {result && (
        <div className="stat-card" data-testid="analysis-result">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Analysis Result
            </h3>
            <a
              href={
                result.type === "ip" ? `https://www.virustotal.com/gui/ip-address/${result.data.ip_address}` :
                result.type === "url" ? `https://www.virustotal.com/gui/url/${btoa(result.data.url)}` :
                `https://www.virustotal.com/gui/file/${result.data.file_hash}`
              }
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-xs text-info hover:underline"
            >
              View on VirusTotal <ExternalLink className="w-3 h-3" />
            </a>
          </div>
          
          {result.type === "ip" && <IPAnalysisResult data={result.data} />}
          {result.type === "url" && <URLAnalysisResult data={result.data} />}
          {result.type === "hash" && <HashAnalysisResult data={result.data} />}
        </div>
      )}

      {/* History Section */}
      <div className="stat-card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Recent Analyses
            </h3>
          </div>
          <button
            onClick={fetchHistory}
            className="p-2 hover:bg-muted rounded-sm"
            data-testid="refresh-history"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        
        <div className="space-y-2" data-testid="history-list">
          {history.length > 0 ? (
            history.map((item, idx) => (
              <HistoryItem key={idx} item={item} onClick={handleHistoryClick} />
            ))
          ) : (
            <div className="text-center py-8">
              <Globe className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No analyses yet. Start by analyzing an IP, URL, or hash above.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
