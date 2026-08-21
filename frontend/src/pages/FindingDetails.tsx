import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

interface Finding {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  url: string;
  endpoint: string;
  description: string;
  technical_details: string;
  remediation: string;
  cwe: string;
  owasp_category: string;
  cvss: number;
  request: string;
  response: string;
  scanner: string;
  created_at: string;
}

export default function FindingDetails() {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const headers = {
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    };
    fetch(`/api/v1/findings/${id}`, { headers })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch');
        return res.json();
      })
      .then((data) => setFinding(data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return <div className="text-center py-10">Decrypting finding details...</div>;
  }

  if (!finding) {
    return (
      <div className="text-center py-10 text-red-400">
        Finding not found or access denied. <Link to="/" className="underline">Back to Dashboard</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <Link to="/" className="text-xs text-blue-400 hover:underline">&larr; Back to Dashboard</Link>
          <h1 className="text-2xl font-bold tracking-tight mt-1">{finding.title}</h1>
        </div>
        <span
          className={`px-3 py-1.5 rounded text-xs font-bold ${
            finding.severity === 'Critical' || finding.severity === 'High'
              ? 'bg-red-950 text-red-400 border border-red-800'
              : 'bg-gray-800 text-gray-400 border border-gray-700'
          }`}
        >
          {finding.severity} Severity
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Explanations */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h2 className="text-md font-bold mb-3">Vulnerability Description</h2>
            <p className="text-gray-300 text-sm leading-relaxed">{finding.description}</p>
          </div>

          {finding.technical_details && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h2 className="text-md font-bold mb-3">Technical Analysis</h2>
              <p className="text-gray-300 text-sm leading-relaxed">{finding.technical_details}</p>
            </div>
          )}

          {finding.remediation && (
            <div className="bg-gray-800 border border-emerald-800/40 bg-emerald-950/5 rounded-lg p-6">
              <h2 className="text-md font-bold mb-3 text-emerald-400">Remediation Guidance</h2>
              <p className="text-gray-300 text-sm leading-relaxed">{finding.remediation}</p>
            </div>
          )}

          {/* Evidence logs */}
          {(finding.request || finding.response) && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 space-y-4">
              <h2 className="text-md font-bold">Transaction Evidence</h2>
              
              {finding.request && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-400 mb-2">Raw Outbound Request</h3>
                  <pre className="bg-gray-900 border border-gray-800 rounded p-4 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {finding.request}
                  </pre>
                </div>
              )}

              {finding.response && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-400 mb-2">Raw Inbound Response</h3>
                  <pre className="bg-gray-900 border border-gray-800 rounded p-4 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {finding.response}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Col: Metadata */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 space-y-4">
            <h2 className="text-md font-bold border-b border-gray-700 pb-2">Classification</h2>
            
            <div>
              <p className="text-xs text-gray-400 font-medium">CVSS v3 Score</p>
              <p className="text-lg font-bold text-white mt-1">{finding.cvss !== null ? finding.cvss : 'N/A'}</p>
            </div>

            <div>
              <p className="text-xs text-gray-400 font-medium">CWE Identifier</p>
              <p className="text-sm font-semibold text-white mt-1">{finding.cwe || 'N/A'}</p>
            </div>

            <div>
              <p className="text-xs text-gray-400 font-medium">OWASP Classification</p>
              <p className="text-sm font-semibold text-white mt-1">{finding.owasp_category || 'N/A'}</p>
            </div>

            <div>
              <p className="text-xs text-gray-400 font-medium">Detection Source</p>
              <p className="text-sm font-semibold text-white mt-1">{finding.scanner}</p>
            </div>

            <div>
              <p className="text-xs text-gray-400 font-medium">Discovery Time</p>
              <p className="text-sm font-semibold text-white mt-1">
                {new Date(finding.created_at).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
