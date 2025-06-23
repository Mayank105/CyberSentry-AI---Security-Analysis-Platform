export interface SecurityAlert {
  alert_id: string;
  alert_type: AlertType;
  timestamp: string;
  severity: Severity;
  source: {
    ip: string;
    domain?: string;
    user?: string;
  };
  target: {
    ip: string;
    hostname?: string;
    asset_id?: string;
  };
  details: {
    description?: string;
    attack_vector?: AttackVector | string;
    indicators?: string[];
    detection_method?: string;
  };
  status: AlertStatus;
  affected_asset?: string;
  affected_user?: string;
  category?: string;
}

export type AlertType = 
  | 'Phishing'
  | 'Malware'
  | 'Brute Force'
  | 'DDoS'
  | 'Data Exfiltration'
  | 'SQL Injection'
  | 'XSS'
  | 'Insider Threat'
  | 'Configuration Error'
  | 'Unknown';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type AttackVector = 'Email' | 'Web' | 'Network' | 'API' | 'Physical';

export type AlertStatus = 'New' | 'In Progress' | 'Resolved' | 'False Positive';

export interface AIAnalysis {
  category: string;
  risk_level: string;
  attack_pattern: string;
  impact_assessment: string;
  recommendations: string[];
  automation_possibilities: string[];
  explanation: string;
  ttps: string[];
  mitigation_steps: {
    immediate: string[];
    short_term: string[];
    long_term: string[];
  };
}