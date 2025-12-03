import { useState } from "react";
import { toast } from "sonner";
import {
  Settings,
  Shield,
  Bell,
  Database,
  Key,
  Globe,
  Sliders,
  Save
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const SettingSection = ({ title, icon: Icon, children }) => (
  <div className="stat-card">
    <div className="flex items-center gap-3 mb-4 pb-4 border-b border-border">
      <div className="p-2 bg-primary/10 rounded-sm">
        <Icon className="w-5 h-5 text-primary" />
      </div>
      <h2 className="font-mono text-sm font-bold uppercase tracking-wider">{title}</h2>
    </div>
    <div className="space-y-4">
      {children}
    </div>
  </div>
);

const SettingRow = ({ label, description, children }) => (
  <div className="flex items-center justify-between py-2">
    <div>
      <p className="text-sm font-medium">{label}</p>
      {description && (
        <p className="text-xs text-muted-foreground mt-1">{description}</p>
      )}
    </div>
    {children}
  </div>
);

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    // Scanning
    autoScan: true,
    scanInterval: "daily",
    maxConcurrentScans: 3,
    
    // Notifications
    emailAlerts: true,
    slackAlerts: false,
    criticalOnly: false,
    
    // Security
    enableRateLimit: true,
    requestTimeout: 30,
    maxRetries: 3,
    
    // Integration
    apiEndpoint: "https://api.example.com",
    webhookUrl: ""
  });

  const handleSave = () => {
    toast.success("Settings saved successfully");
  };

  return (
    <div className="space-y-6" data-testid="settings-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-wider uppercase">Settings</h1>
          <p className="text-sm text-muted-foreground mt-1">Configure APIGuardian preferences</p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-sm font-mono text-xs uppercase tracking-wider hover:bg-primary/90 transition-colors"
          data-testid="save-settings"
        >
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scanning Settings */}
        <SettingSection title="Scanning" icon={Shield}>
          <SettingRow
            label="Automatic Scanning"
            description="Enable automatic scheduled scans"
          >
            <Switch
              checked={settings.autoScan}
              onCheckedChange={(checked) => setSettings({ ...settings, autoScan: checked })}
              data-testid="auto-scan-toggle"
            />
          </SettingRow>
          
          <SettingRow
            label="Scan Interval"
            description="How often to run automatic scans"
          >
            <Select
              value={settings.scanInterval}
              onValueChange={(value) => setSettings({ ...settings, scanInterval: value })}
            >
              <SelectTrigger className="w-32 bg-background" data-testid="scan-interval">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="hourly">Hourly</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </SettingRow>
          
          <SettingRow
            label="Max Concurrent Scans"
            description="Maximum number of parallel scans"
          >
            <input
              type="number"
              min="1"
              max="10"
              className="w-20 h-9 px-3 bg-background border border-input rounded-sm font-mono text-sm text-center focus:outline-none focus:border-primary"
              value={settings.maxConcurrentScans}
              onChange={(e) => setSettings({ ...settings, maxConcurrentScans: parseInt(e.target.value) || 1 })}
              data-testid="max-scans"
            />
          </SettingRow>
        </SettingSection>

        {/* Notification Settings */}
        <SettingSection title="Notifications" icon={Bell}>
          <SettingRow
            label="Email Alerts"
            description="Send alerts to email"
          >
            <Switch
              checked={settings.emailAlerts}
              onCheckedChange={(checked) => setSettings({ ...settings, emailAlerts: checked })}
              data-testid="email-alerts-toggle"
            />
          </SettingRow>
          
          <SettingRow
            label="Slack Integration"
            description="Send alerts to Slack channel"
          >
            <Switch
              checked={settings.slackAlerts}
              onCheckedChange={(checked) => setSettings({ ...settings, slackAlerts: checked })}
              data-testid="slack-alerts-toggle"
            />
          </SettingRow>
          
          <SettingRow
            label="Critical Only"
            description="Only notify for critical issues"
          >
            <Switch
              checked={settings.criticalOnly}
              onCheckedChange={(checked) => setSettings({ ...settings, criticalOnly: checked })}
              data-testid="critical-only-toggle"
            />
          </SettingRow>
        </SettingSection>

        {/* Security Settings */}
        <SettingSection title="Security" icon={Key}>
          <SettingRow
            label="Rate Limiting"
            description="Enable request rate limiting"
          >
            <Switch
              checked={settings.enableRateLimit}
              onCheckedChange={(checked) => setSettings({ ...settings, enableRateLimit: checked })}
              data-testid="rate-limit-toggle"
            />
          </SettingRow>
          
          <SettingRow
            label="Request Timeout (s)"
            description="Maximum time for HTTP requests"
          >
            <input
              type="number"
              min="5"
              max="120"
              className="w-20 h-9 px-3 bg-background border border-input rounded-sm font-mono text-sm text-center focus:outline-none focus:border-primary"
              value={settings.requestTimeout}
              onChange={(e) => setSettings({ ...settings, requestTimeout: parseInt(e.target.value) || 30 })}
              data-testid="request-timeout"
            />
          </SettingRow>
          
          <SettingRow
            label="Max Retries"
            description="Number of retry attempts"
          >
            <input
              type="number"
              min="0"
              max="10"
              className="w-20 h-9 px-3 bg-background border border-input rounded-sm font-mono text-sm text-center focus:outline-none focus:border-primary"
              value={settings.maxRetries}
              onChange={(e) => setSettings({ ...settings, maxRetries: parseInt(e.target.value) || 3 })}
              data-testid="max-retries"
            />
          </SettingRow>
        </SettingSection>

        {/* Integration Settings */}
        <SettingSection title="Integration" icon={Globe}>
          <div>
            <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground block mb-2">
              Target API Endpoint
            </label>
            <input
              type="url"
              className="w-full h-10 px-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
              value={settings.apiEndpoint}
              onChange={(e) => setSettings({ ...settings, apiEndpoint: e.target.value })}
              placeholder="https://api.example.com"
              data-testid="api-endpoint"
            />
          </div>
          
          <div>
            <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground block mb-2">
              Webhook URL (Optional)
            </label>
            <input
              type="url"
              className="w-full h-10 px-4 bg-background border border-input rounded-sm font-mono text-sm focus:outline-none focus:border-primary"
              value={settings.webhookUrl}
              onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
              placeholder="https://hooks.example.com/webhook"
              data-testid="webhook-url"
            />
          </div>
        </SettingSection>
      </div>

      {/* Danger Zone */}
      <div className="stat-card border-critical/30">
        <div className="flex items-center gap-3 mb-4 pb-4 border-b border-border">
          <div className="p-2 bg-critical/10 rounded-sm">
            <Settings className="w-5 h-5 text-critical" />
          </div>
          <h2 className="font-mono text-sm font-bold uppercase tracking-wider text-critical">Danger Zone</h2>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Reset All Data</p>
            <p className="text-xs text-muted-foreground mt-1">
              This will delete all scans, vulnerabilities, and reports. This action cannot be undone.
            </p>
          </div>
          <button
            className="px-4 py-2 bg-critical/10 text-critical border border-critical rounded-sm font-mono text-xs uppercase hover:bg-critical hover:text-white transition-colors"
            onClick={() => toast.error("Data reset is disabled in demo mode")}
            data-testid="reset-data"
          >
            Reset Data
          </button>
        </div>
      </div>
    </div>
  );
}
