import React, { useState } from 'react';
import { Shield, Upload, RefreshCw, X, Brain, AlertTriangle, Download, Info } from 'lucide-react';
import { parseAndValidateInput } from './utils/validation';
import { generateAIAnalysis } from './utils/aiAnalysis';
import { jsPDF } from 'jspdf';
import type { SecurityAlert, AIAnalysis } from './types/alerts';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

function App() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileUploaded, setFileUploaded] = useState(false);
  const [showFormat, setShowFormat] = useState(false);

  const validateFileType = (file: File) => {
    return file.type === 'application/json';
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    setError(null);

    if (!file) return;

    if (!validateFileType(file)) {
      setError('Invalid file type. Please upload JSON files only.');
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setError('File size exceeds 5MB limit.');
      return;
    }

    setIsAnalyzing(true);

    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const content = e.target?.result as string;
          const validatedAlerts = parseAndValidateInput(content);
          
          if (validatedAlerts.length === 0) {
            throw new Error('No valid alerts found in file');
          }

          setAlerts(validatedAlerts);
          setFileUploaded(true);
        } catch (error) {
          setError('Error processing file. Please check the file format.');
        } finally {
          setIsAnalyzing(false);
        }
      };

      reader.readAsText(file);
    } catch (error) {
      setError('Error reading file.');
      setIsAnalyzing(false);
    }
  };

  const downloadPDF = () => {
    if (!selectedAlert || !aiAnalysis) return;

    const doc = new jsPDF();
    
    // Title
    doc.setFontSize(16);
    doc.text('Security Alert Analysis Report', 20, 20);
    
    // Alert Details
    doc.setFontSize(12);
    doc.text(`Alert ID: ${selectedAlert.alert_id}`, 20, 40);
    doc.text(`Alert Type: ${selectedAlert.alert_type}`, 20, 50);
    doc.text(`Severity: ${selectedAlert.severity}`, 20, 60);
    doc.text(`Source: ${selectedAlert.source.ip}`, 20, 70);
    doc.text(`Target: ${selectedAlert.target.ip}`, 20, 80);
    
    // AI Analysis
    doc.text('AI Analysis', 20, 100);
    doc.text(`Attack Pattern: ${aiAnalysis.attack_pattern}`, 20, 110);
    doc.text(`Impact Assessment: ${aiAnalysis.impact_assessment}`, 20, 120);
    
    // Recommendations
    doc.text('Recommendations:', 20, 140);
    aiAnalysis.recommendations.forEach((rec, index) => {
      doc.text(`${index + 1}. ${rec}`, 30, 150 + (index * 10));
    });
    
    // Mitigation Steps
    doc.addPage();
    doc.text('Mitigation Steps:', 20, 20);
    doc.text('Immediate Actions:', 20, 40);
    aiAnalysis.mitigation_steps.immediate.forEach((step, index) => {
      doc.text(`- ${step}`, 30, 50 + (index * 10));
    });
    
    doc.text('Short-term Actions:', 20, 100);
    aiAnalysis.mitigation_steps.short_term.forEach((step, index) => {
      doc.text(`- ${step}`, 30, 110 + (index * 10));
    });
    
    doc.text('Long-term Actions:', 20, 160);
    aiAnalysis.mitigation_steps.long_term.forEach((step, index) => {
      doc.text(`- ${step}`, 30, 170 + (index * 10));
    });
    
    doc.save(`security-alert-${selectedAlert.alert_id}.pdf`);
  };

  const resetUpload = () => {
    setAlerts([]);
    setSelectedAlert(null);
    setAiAnalysis(null);
    setFileUploaded(false);
    setError(null);
  };

  const handleAlertSelect = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setAiAnalysis(generateAIAnalysis(alert));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-900/20 text-red-400';
      case 'High':
        return 'bg-orange-900/20 text-orange-400';
      case 'Medium':
        return 'bg-yellow-900/20 text-yellow-400';
      case 'Low':
        return 'bg-green-900/20 text-green-400';
      default:
        return 'bg-gray-900/20 text-gray-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-[#0a192f] to-black">
      <div className="min-h-screen backdrop-blur-sm">
        {!fileUploaded ? (
          <div className="flex flex-col items-center justify-center min-h-screen p-4">
            <div className="relative mb-8">
              <div className="absolute inset-0 animate-ping">
                <Shield className="h-16 w-16 text-cyan-500 opacity-50" />
              </div>
              <Shield className="h-16 w-16 text-cyan-400 relative" />
            </div>
            <div className="bg-black/40 p-8 rounded-lg border border-gray-700 backdrop-blur-sm max-w-md w-full">
              <h1 className="text-2xl font-bold text-white text-center mb-6">CyberSentry AI</h1>
              <div className="text-center mb-8">
                <p className="text-gray-300 mb-4">
                  Upload your security logs for AI-powered analysis
                </p>
                <button
                  onClick={() => setShowFormat(!showFormat)}
                  className="flex items-center mx-auto px-3 py-1 bg-cyan-900/20 text-cyan-400 rounded-lg hover:bg-cyan-900/30 transition-colors duration-200 mb-4"
                >
                  <Info className="h-4 w-4 mr-1" />
                  View Required Format
                </button>
                <div className="text-sm text-gray-400">
                  Supported format: STIX-aligned JSON
                </div>
              </div>
              <label className="relative flex flex-col items-center px-4 py-6 border-2 border-gray-700 border-dashed rounded-lg cursor-pointer hover:border-cyan-400 transition-colors duration-200">
                <Upload className="h-12 w-12 text-cyan-400 mb-2" />
                <span className="text-sm text-gray-300">Click to upload file</span>
                <span className="text-xs text-gray-400 mt-1">Max size: 5MB</span>
                <input
                  type="file"
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  onChange={handleFileUpload}
                  accept=".json"
                />
              </label>
              {error && (
                <div className="mt-4 p-4 bg-red-900/50 border border-red-700 rounded-lg">
                  <p className="text-red-400 text-sm">{error}</p>
                </div>
              )}
            </div>
            {showFormat && (
              <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
                <div className="bg-black/60 border border-cyan-900 p-6 rounded-lg max-w-2xl w-full">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-medium text-white">STIX-aligned JSON Format</h3>
                    <button
                      onClick={() => setShowFormat(false)}
                      className="text-gray-400 hover:text-white"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                  <pre className="bg-black/30 p-4 rounded text-sm text-gray-300 overflow-auto">
{`{
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
}`}
                  </pre>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="container mx-auto px-4 py-8">
            <div className="flex justify-between items-center mb-8">
              <div className="flex items-center">
                <div className="relative">
                  <div className="absolute inset-0 animate-ping">
                    <Shield className="h-8 w-8 text-cyan-500 opacity-50" />
                  </div>
                  <Shield className="h-8 w-8 text-cyan-400 relative" />
                </div>
                <h1 className="text-2xl font-bold text-white ml-3">CyberSentry AI</h1>
              </div>
              <button
                onClick={resetUpload}
                className="flex items-center px-4 py-2 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors duration-200"
              >
                <X className="h-4 w-4 mr-2" />
                Reset Upload
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="bg-black/40 rounded-lg border border-gray-700 backdrop-blur-sm p-6">
                <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                  <AlertTriangle className="h-5 w-5 text-cyan-400 mr-2" />
                  Security Alerts
                </h2>
                <div className="space-y-4">
                  {alerts.map((alert) => (
                    <div
                      key={alert.alert_id}
                      className={`p-4 rounded-lg border border-gray-700 cursor-pointer transition-all duration-200 ${
                        selectedAlert?.alert_id === alert.alert_id
                          ? 'bg-cyan-900/20 border-cyan-700'
                          : 'hover:bg-gray-800/20'
                      }`}
                      onClick={() => handleAlertSelect(alert)}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{alert.alert_type}</span>
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(
                            alert.severity
                          )}`}
                        >
                          {alert.severity}
                        </span>
                      </div>
                      <div className="text-gray-400 text-sm">
                        <p>Source: {alert.source.ip}</p>
                        <p>Target: {alert.target.ip}</p>
                        <p className="text-xs mt-1">{new Date(alert.timestamp).toLocaleString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-black/40 rounded-lg border border-gray-700 backdrop-blur-sm p-6">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-xl font-semibold text-white flex items-center">
                    <Brain className="h-5 w-5 text-cyan-400 mr-2" />
                    AI Analysis
                  </h2>
                  {selectedAlert && aiAnalysis && (
                    <button
                      onClick={downloadPDF}
                      className="flex items-center px-3 py-1 bg-cyan-900/20 text-cyan-400 rounded-lg hover:bg-cyan-900/30 transition-colors duration-200"
                    >
                      <Download className="h-4 w-4 mr-1" />
                      Download PDF
                    </button>
                  )}
                </div>
                {selectedAlert && aiAnalysis ? (
                  <div className="space-y-4">
                    <div className="p-4 bg-cyan-900/20 rounded-lg border border-cyan-700">
                      <h3 className="text-cyan-400 font-medium mb-2">{aiAnalysis.attack_pattern}</h3>
                      <p className="text-gray-300 text-sm mb-4">{aiAnalysis.explanation}</p>
                      <div className="space-y-4">
                        <div>
                          <h4 className="text-white font-medium mb-2">Impact Assessment</h4>
                          <p className="text-gray-300 text-sm">{aiAnalysis.impact_assessment}</p>
                        </div>
                        <div>
                          <h4 className="text-white font-medium mb-2">TTPs Identified</h4>
                          <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                            {aiAnalysis.ttps.map((ttp, index) => (
                              <li key={index}>{ttp}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                    <div className="p-4 bg-gray-900/40 rounded-lg border border-gray-700">
                      <h3 className="text-white font-medium mb-4">Mitigation Steps</h3>
                      <div className="space-y-4">
                        <div>
                          <h4 className="text-cyan-400 text-sm font-medium mb-2">Immediate Actions</h4>
                          <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                            {aiAnalysis.mitigation_steps.immediate.map((step, index) => (
                              <li key={index}>{step}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="text-cyan-400 text-sm font-medium mb-2">Short-term Actions</h4>
                          <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                            {aiAnalysis.mitigation_steps.short_term.map((step, index) => (
                              <li key={index}>{step}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="text-cyan-400 text-sm font-medium mb-2">Long-term Actions</h4>
                          <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                            {aiAnalysis.mitigation_steps.long_term.map((step, index) => (
                              <li key={index}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                    {aiAnalysis.automation_possibilities.length > 0 && (
                      <div className="p-4 bg-gray-900/40 rounded-lg border border-gray-700">
                        <h3 className="text-white font-medium mb-2">Automation Possibilities</h3>
                        <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                          {aiAnalysis.automation_possibilities.map((possibility, index) => (
                            <li key={index}>{possibility}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-400">
                    <Brain className="h-12 w-12 mx-auto mb-4 text-gray-600" />
                    <p>Select an alert to view AI analysis</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {isAnalyzing && (
          <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center">
            <div className="bg-black/60 border border-cyan-900 p-6 rounded-lg flex items-center">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
              <span className="ml-3 text-lg font-medium text-white">AI analyzing alerts...</span>
            </div>
          </div>
        )}

        <footer className="fixed bottom-0 w-full bg-black/40 backdrop-blur-sm border-t border-gray-800">
          <div className="container mx-auto px-4 py-3">
            <p className="text-gray-400 text-sm text-center">
              © 2025 Mayank Rayabharapu. All rights reserved.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;