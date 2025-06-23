import type { SecurityAlert, AIAnalysis } from '../types/alerts';

const ATTACK_PATTERNS = {
  'Phishing': {
    pattern: 'Social Engineering via Email',
    ttps: [
      'T1566.001 - Spearphishing Attachment',
      'T1566.002 - Spearphishing Link',
      'T1534 - Internal Spearphishing'
    ]
  },
  'Malware': {
    pattern: 'Malicious Code Execution',
    ttps: [
      'T1204 - User Execution',
      'T1047 - Windows Management Instrumentation',
      'T1059 - Command and Scripting Interpreter'
    ]
  },
  'Brute Force Attack': {
    pattern: 'Credential Access Attempt',
    ttps: [
      'T1110 - Brute Force',
      'T1110.001 - Password Guessing',
      'T1110.002 - Password Cracking'
    ]
  },
  'Data Exfiltration': {
    pattern: 'Data Theft Operation',
    ttps: [
      'T1048 - Exfiltration Over Alternative Protocol',
      'T1567 - Exfiltration Over Web Service',
      'T1020 - Automated Exfiltration'
    ]
  }
};

const SEVERITY_RESPONSES = {
  'Critical': {
    immediate: [
      'Isolate affected systems',
      'Block malicious IPs/domains',
      'Initiate incident response plan'
    ],
    short_term: [
      'Conduct forensic analysis',
      'Review security logs',
      'Update security policies'
    ],
    long_term: [
      'Implement additional security controls',
      'Enhance monitoring capabilities',
      'Conduct security awareness training'
    ]
  },
  'High': {
    immediate: [
      'Block suspicious activity',
      'Alert security team',
      'Begin investigation'
    ],
    short_term: [
      'Update detection rules',
      'Patch vulnerable systems',
      'Review access controls'
    ],
    long_term: [
      'Enhance security monitoring',
      'Update security procedures',
      'Schedule regular audits'
    ]
  }
};

export const generateAIAnalysis = (alert: SecurityAlert): AIAnalysis => {
  const attackInfo = ATTACK_PATTERNS[alert.alert_type as keyof typeof ATTACK_PATTERNS] || {
    pattern: 'Unknown Attack Pattern',
    ttps: ['T0000 - Generic Attack Pattern']
  };

  const severityResponse = SEVERITY_RESPONSES[alert.severity as keyof typeof SEVERITY_RESPONSES] || {
    immediate: ['Monitor system activity'],
    short_term: ['Review security controls'],
    long_term: ['Update security policies']
  };

  const automationPossibilities = [
    'Automated IP blocking',
    'Automated system isolation',
    'Automated log collection',
    'Automated alert correlation'
  ].filter(() => Math.random() > 0.5);

  const analysis: AIAnalysis = {
    category: alert.category || 'Unknown',
    risk_level: alert.severity,
    attack_pattern: attackInfo.pattern,
    impact_assessment: `Potential impact on ${alert.affected_asset || 'system'} through ${alert.details.attack_vector || 'unknown'} vector`,
    recommendations: [
      ...severityResponse.immediate,
      ...severityResponse.short_term.slice(0, 2)
    ],
    automation_possibilities: automationPossibilities,
    explanation: `${alert.alert_type} detected via ${alert.details.detection_method || 'unknown method'} targeting ${alert.affected_user || 'unknown user'} through ${alert.details.attack_vector || 'unknown vector'}`,
    ttps: attackInfo.ttps,
    mitigation_steps: {
      immediate: severityResponse.immediate,
      short_term: severityResponse.short_term,
      long_term: severityResponse.long_term
    }
  };

  return analysis;
};