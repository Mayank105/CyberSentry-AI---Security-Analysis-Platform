# CyberSentry-AI---Security-Analysis-Platform
CyberSentry AI is a sophisticated cybersecurity dashboard that provides AI-powered analysis of security alerts and incidents. The platform accepts security logs in STIX-aligned JSON format and delivers comprehensive threat analysis with actionable mitigation strategies.

Key Features
AI-Powered Threat Analysis: Automated security alert analysis using MITRE ATT&CK framework
Multi-Format Support: Accepts both STIX-aligned and Bolt.io security log formats
Real-time Processing: Instant analysis and visualization of security incidents
Interactive Dashboard: Modern, responsive UI with dark cybersecurity theme
PDF Report Generation: Downloadable security analysis reports
Severity-Based Prioritization: Color-coded alert classification system
Mitigation Recommendations: Immediate, short-term, and long-term action plans

🚀 Technology Stack
Frontend
React 18 with TypeScript for type-safe component development
Vite for fast development and optimized builds
Tailwind CSS for responsive, utility-first styling
Lucide React for consistent iconography
Data Processing & Validation
AJV (Another JSON Schema Validator) for robust input validation
AJV-Formats for extended format validation (date-time, etc.)
UUID for unique identifier generation
AI & Analysis Engine
Rule-based Expert System using MITRE ATT&CK framework
Pattern Recognition for threat categorization
Severity-based Response Matrix for contextual recommendations
Document Generation
jsPDF for automated PDF report creation
Development Tools
TypeScript for enhanced code quality and developer experience
ESLint with TypeScript support for code linting
PostCSS & Autoprefixer for CSS processing
🏗️ Project Structure

src/
├── components/           # Reusable UI components
├── types/
│   └── alerts.ts        # TypeScript interfaces and types
├── utils/
│   ├── validation.ts    # Input validation and parsing logic
│   └── aiAnalysis.ts    # AI analysis engine
├── App.tsx              # Main application component
├── main.tsx             # Application entry point
└── index.css            # Global styles

🧠 AI Analysis System
How It Works
The AI system uses a rule-based expert system that:

Pattern Matching: Identifies attack patterns using predefined signatures
MITRE ATT&CK Integration: Maps threats to standardized TTPs (Tactics, Techniques, Procedures)
Severity Assessment: Evaluates threat level and impact potential
Contextual Analysis: Considers source, target, and attack vector information
Response Generation: Provides tiered mitigation strategies
Analysis Components
Attack Pattern Recognition: Categorizes threats (Phishing, Malware, Brute Force, etc.)
TTP Mapping: Links to MITRE ATT&CK framework identifiers
Impact Assessment: Evaluates potential business and technical impact
Mitigation Planning: Three-tier response strategy (Immediate/Short-term/Long-term)
Automation Suggestions: Identifies opportunities for automated response

📊 Supported Data Formats
STIX-Aligned Format

{
  "alert_id": "BOLT-20250115-001",
  "alert_type": "Phishing",
  "timestamp": "2025-01-15T14:30:00Z",
  "severity": "High",
  "source": {
    "ip": "192.168.1.100",
    "domain": "example.com",
    "user": "john.doe"
  },
  "target": {
    "ip": "10.0.0.50",
    "hostname": "workstation-1",
    "asset_id": "WS-001"
  },
  "details": {
    "description": "Suspicious phishing attempt detected",
    "attack_vector": "Email",
    "indicators": ["malicious.url", "suspicious.file"]
  },
  "status": "New"
}
Bolt.io Format (Legacy Support)

{
  "alert_id": "ALT-001",
  "alert_type": "Malware",
  "timestamp": "2025-01-15T10:30:00Z",
  "severity": "Critical",
  "source_ip": "203.0.113.45",
  "destination_ip": "192.168.1.100",
  "attack_vector": "Email",
  "detection_method": "Signature-based",
  "alert_message": "Malicious file detected",
  "status": "New"
}

🎯 Usage
Upload Security Logs: Drag and drop JSON files containing security alerts
View Analysis: Select alerts from the left panel to view AI-generated analysis
Review Recommendations: Examine immediate, short-term, and long-term mitigation steps
Download Reports: Generate PDF reports for incident documentation
Track Progress: Monitor alert status and resolution progress
🔒 Security Features
Input Validation: Comprehensive JSON schema validation
File Type Restrictions: Only accepts JSON files
Size Limitations: 5MB maximum file size
Data Sanitization: Prevents malicious input processing
Client-side Processing: No data transmitted to external servers
📈 Performance Optimizations
Lazy Loading: Components loaded on demand
Memoization: Optimized re-rendering with React hooks
Bundle Splitting: Efficient code splitting with Vite
Tree Shaking: Unused code elimination
CSS Purging: Tailwind CSS optimization

🔮 Future Enhancements
Machine Learning Integration: Advanced pattern recognition
Real-time Threat Intelligence: Live threat feed integration
Multi-tenant Support: Organization-based access control
API Integration: SIEM and security tool connectivity
Advanced Reporting: Custom report templates
Collaborative Features: Team-based incident response
📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Author
Mayank Rayabharapu

LinkedIn: www.linkedin.com/in/mayankrayabharapu 
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Built with ❤️ for the cybersecurity community

