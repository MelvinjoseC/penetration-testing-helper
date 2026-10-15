import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

interface Finding {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
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
  const [statusVal, setStatusVal] = useState('New');
  const [severityVal, setSeverityVal] = useState('Medium');
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState('');

  useEffect(() => {
    const headers = {
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    };
    fetch(`/api/v1/findings/${id}`, { headers })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch');
        return res.json();
      })
      .then((data: Finding) => {
        setFinding(data);
        setStatusVal(data.status || 'New');
        setSeverityVal(data.severity || 'Medium');
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [id]);

  const handleTriageSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveMsg('');
    fetch(`/api/v1/findings/${id}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: statusVal,
        severity: severityVal,
      }),
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Update failed');
        setFinding(data);
        setSaveMsg('Triage status saved!');
        setTimeout(() => setSaveMsg(''), 3000);
      })
      .catch((err) => setSaveMsg(err.message))
      .finally(() => setSaving(false));
  };

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
        <div className="flex gap-2">
          <span className="px-3 py-1.5 rounded text-xs font-bold bg-blue-950 text-blue-400 border border-blue-800">
            {finding.status}
          </span>
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

        {/* Right Col: Metadata & Triage Controls */}
        <div className="lg:col-span-1 space-y-6">
          {/* Triage Controls Card */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h2 className="text-md font-bold border-b border-gray-700 pb-2 mb-4">Security Triage</h2>
            <form onSubmit={handleTriageSave} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1">Lifecycle Status</label>
                <select
                  value={statusVal}
                  onChange={(e) => setStatusVal(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs text-white"
                >
                  <option value="New">New</option>
                  <option value="Confirmed">Confirmed</option>
                  <option value="False Positive">False Positive</option>
                  <option value="Resolved">Resolved</option>
                  <option value="Risk Accepted">Risk Accepted</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1">Adjusted Severity</label>
                <select
                  value={severityVal}
                  onChange={(e) => setSeverityVal(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs text-white"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={saving}
                className="w-full bg-blue-600 hover:bg-blue-500 font-bold py-2 rounded text-xs transition"
              >
                {saving ? 'Updating...' : 'Save Triage Decisions'}
              </button>
              {saveMsg && <p className="text-xs text-center text-emerald-400 font-semibold">{saveMsg}</p>}
            </form>
          </div>

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
