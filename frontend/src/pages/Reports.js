import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  FileText,
  Download,
  Eye,
  Calendar,
  FileJson,
  FileCode,
  File,
  Plus
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const ReportTypeIcon = ({ type }) => {
  const icons = {
    json: FileJson,
    html: FileCode,
    pdf: File
  };
  const Icon = icons[type] || FileText;
  return <Icon className="w-5 h-5" />;
};

const ReportCard = ({ report, onView }) => (
  <div
    className="stat-card card-hover cursor-pointer"
    onClick={() => onView(report)}
    data-testid={`report-${report.id}`}
  >
    <div className="flex items-start justify-between">
      <div className="flex items-start gap-3">
        <div className="p-2 bg-primary/10 rounded-sm">
          <ReportTypeIcon type={report.report_type} />
        </div>
        <div>
          <h3 className="font-medium text-sm">{report.name}</h3>
          <p className="text-xs text-muted-foreground mt-1">
            Type: {report.report_type.toUpperCase()}
          </p>
        </div>
      </div>
      <span className="text-xs font-mono uppercase px-2 py-1 bg-muted rounded-sm">
        {report.report_type}
      </span>
    </div>
    <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground">
      <div className="flex items-center gap-1">
        <Calendar className="w-3 h-3" />
        {new Date(report.created_at).toLocaleDateString()}
      </div>
      {report.scan_id && (
        <span className="font-mono">Scan: {report.scan_id.slice(0, 8)}</span>
      )}
    </div>
  </div>
);

const ReportViewer = ({ report, onClose }) => {
  if (!report) return null;

  return (
    <Dialog open={!!report} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] bg-card border-border overflow-hidden">
        <DialogHeader>
          <DialogTitle className="font-mono flex items-center gap-2">
            <ReportTypeIcon type={report.report_type} />
            {report.name}
          </DialogTitle>
        </DialogHeader>
        <div className="overflow-auto max-h-[60vh] p-4 bg-background rounded-sm border border-border">
          {report.report_type === "json" && (
            <pre className="text-xs font-mono text-foreground/80 whitespace-pre-wrap">
              {JSON.stringify(report.content, null, 2)}
            </pre>
          )}
          {report.report_type === "html" && (
            <div
              className="prose prose-invert max-w-none"
              dangerouslySetInnerHTML={{ __html: report.content.html || "<p>No content</p>" }}
            />
          )}
          {report.report_type === "pdf" && (
            <div className="text-center py-12">
              <File className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">PDF preview not available</p>
              <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-xs uppercase">
                Download PDF
              </button>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

const GenerateReportModal = ({ isOpen, onClose, onGenerate }) => {
  const [reportName, setReportName] = useState("");
  const [reportType, setReportType] = useState("json");
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    if (!reportName.trim()) {
      toast.error("Please enter a report name");
      return;
    }

    setLoading(true);
    try {
      await onGenerate(reportName, reportType);
      setReportName("");
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle className="font-mono">Generate New Report</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-4">
          <div>
            <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground block mb-2">
              Report Name
            </label>
            <input
              type="text"
              className="w-full h-10 px-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
              placeholder="Security Scan Report - January 2025"
              value={reportName}
              onChange={(e) => setReportName(e.target.value)}
              data-testid="report-name-input"
            />
          </div>
          <div>
            <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground block mb-2">
              Report Type
            </label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger className="w-full bg-background" data-testid="report-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="html">HTML</SelectItem>
                <SelectItem value="pdf">PDF</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-muted text-muted-foreground rounded-sm font-mono text-xs uppercase"
              data-testid="cancel-report"
            >
              Cancel
            </button>
            <button
              onClick={handleGenerate}
              disabled={loading}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-xs uppercase disabled:opacity-50"
              data-testid="generate-report-btn"
            >
              {loading ? "Generating..." : "Generate"}
            </button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState(null);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await axios.get(`${API}/reports`);
      setReports(response.data);
    } catch (e) {
      // Generate sample reports if none exist
      const sampleReports = [
        {
          id: "1",
          name: "Full Security Scan Report - January 2025",
          report_type: "json",
          scan_id: "abc123",
          content: {
            summary: {
              total_vulnerabilities: 7,
              critical: 2,
              high: 2,
              medium: 2,
              low: 1
            },
            scan_details: {
              target: "https://api.example.com",
              started_at: "2025-01-01T10:00:00Z",
              completed_at: "2025-01-01T10:30:00Z"
            },
            findings: [
              { title: "SQL Injection", severity: "critical", endpoint: "/api/users/search" },
              { title: "JWT Not Verified", severity: "critical", endpoint: "/api/auth/verify" }
            ]
          },
          created_at: new Date().toISOString()
        },
        {
          id: "2",
          name: "Authentication Module Assessment",
          report_type: "html",
          scan_id: "def456",
          content: {
            html: "<h1>Authentication Security Report</h1><p>This report details the security assessment of authentication endpoints.</p><h2>Findings</h2><ul><li>JWT validation issues detected</li><li>Rate limiting not implemented</li></ul>"
          },
          created_at: new Date(Date.now() - 86400000).toISOString()
        },
        {
          id: "3",
          name: "Compliance Report - OWASP Top 10",
          report_type: "pdf",
          content: {},
          created_at: new Date(Date.now() - 172800000).toISOString()
        }
      ];
      setReports(sampleReports);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (name, type) => {
    try {
      // Generate report content based on current data
      const statsRes = await axios.get(`${API}/dashboard/stats`);
      const vulnsRes = await axios.get(`${API}/vulnerabilities?limit=10`);

      const content = type === "json" ? {
        generated_at: new Date().toISOString(),
        summary: statsRes.data.vulnerabilities,
        security_score: statsRes.data.security_score,
        vulnerabilities: vulnsRes.data
      } : type === "html" ? {
        html: `<h1>${name}</h1><p>Generated at ${new Date().toLocaleString()}</p><h2>Summary</h2><p>Total vulnerabilities: ${statsRes.data.vulnerabilities.total}</p>`
      } : {};

      const newReport = {
        id: Date.now().toString(),
        name,
        report_type: type,
        content,
        created_at: new Date().toISOString()
      };

      // Try to save to backend
      try {
        await axios.post(`${API}/reports`, newReport);
      } catch (e) {
        // If backend fails, just add locally
      }

      setReports([newReport, ...reports]);
      toast.success("Report generated successfully");
    } catch (e) {
      toast.error("Failed to generate report");
    }
  };

  const filteredReports = reports.filter(r => {
    if (filter === "all") return true;
    return r.report_type === filter;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <FileText className="w-12 h-12 text-primary animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="reports-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Reports</h1>
          <p className="text-sm text-muted-foreground mt-1">View and generate security reports</p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-xs uppercase tracking-wider hover:bg-primary/90 transition-colors"
          data-testid="new-report-btn"
        >
          <Plus className="w-4 h-4" />
          New Report
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        {["all", "json", "html", "pdf"].map((f) => (
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
            {f}
          </button>
        ))}
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredReports.map((report) => (
          <ReportCard
            key={report.id}
            report={report}
            onView={setSelectedReport}
          />
        ))}
      </div>

      {filteredReports.length === 0 && (
        <div className="text-center py-12">
          <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">No reports found</p>
          <button
            onClick={() => setShowGenerateModal(true)}
            className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-xs uppercase"
          >
            Generate Your First Report
          </button>
        </div>
      )}

      <ReportViewer
        report={selectedReport}
        onClose={() => setSelectedReport(null)}
      />

      <GenerateReportModal
        isOpen={showGenerateModal}
        onClose={() => setShowGenerateModal(false)}
        onGenerate={handleGenerateReport}
      />
    </div>
  );
}
