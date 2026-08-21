import React, { useState, useEffect } from 'react';

interface Scope {
  id: string;
  type: string;
  pattern: string;
  is_excluded: boolean;
}

interface Asset {
  id: string;
  type: string;
  value: string;
}

interface Engagement {
  id: string;
  name: string;
  company: string;
  description: string;
  authorization_reference: string;
  is_verified: boolean;
  scopes: Scope[];
  assets: Asset[];
}

export default function Engagements() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  
  // New Engagement Form State
  const [name, setName] = useState('');
  const [company, setCompany] = useState('');
  const [desc, setDesc] = useState('');
  const [authRef, setAuthRef] = useState('');

  // Scope Form State
  const [scopeType, setScopeType] = useState('domain');
  const [scopePattern, setScopePattern] = useState('');
  const [scopeExcluded, setScopeExcluded] = useState(false);

  // Verification State
  const [verifyDomain, setVerifyDomain] = useState('');
  const [verifyMethod, setVerifyMethod] = useState('dns');
  const [manualRef, setManualRef] = useState('');
  const [verifyMessage, setVerifyMessage] = useState('');
  
  // Scan State
  const [scanTarget, setScanTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('safe');

  const headers = {
    Authorization: `Bearer ${localStorage.getItem('token')}`,
    'Content-Type': 'application/json',
  };

  const fetchEngagements = () => {
    fetch('/api/v1/engagements', { headers })
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) setEngagements(data);
      })
      .catch((err) => console.error(err));
  };

  useEffect(() => {
    fetchEngagements();
  }, []);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    fetch('/api/v1/engagements', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name,
        company,
        description: desc,
        authorization_reference: authRef,
      }),
    })
      .then((res) => res.json())
      .then(() => {
        setName('');
        setCompany('');
        setDesc('');
        setAuthRef('');
        fetchEngagements();
      });
  };

  const handleAddScope = (e: React.FormEvent, engId: string) => {
    e.preventDefault();
    fetch(`/api/v1/engagements/${engId}/scope`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        type: scopeType,
        pattern: scopePattern,
        is_excluded: scopeExcluded,
      }),
    })
      .then((res) => res.json())
      .then(() => {
        setScopePattern('');
        setScopeExcluded(false);
        fetchEngagements();
      });
  };

  const handleVerify = (e: React.FormEvent, engId: string) => {
    e.preventDefault();
    setVerifyMessage('Running validation checks...');
    fetch(`/api/v1/engagements/${engId}/verify?domain=${verifyDomain}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        method: verifyMethod,
        manual_override_reference: verifyMethod === 'manual' ? manualRef : null,
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        setVerifyMessage(data.message);
        fetchEngagements();
      })
      .catch(() => setVerifyMessage('Failed to complete validation.'));
  };

  const handleStartScan = (e: React.FormEvent, engId: string) => {
    e.preventDefault();
    fetch('/api/v1/scans', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        engagement_id: engId,
        target: scanTarget,
        profile: scanProfile,
      }),
    })
      .then((res) => {
        if (!res.ok) {
          return res.json().then((err) => {
            alert(err.detail || 'Failed to start scan.');
          });
        }
        alert('Scan successfully dispatched to queue.');
        setScanTarget('');
      });
  };

  const handleDownloadReport = (engId: string) => {
    fetch(`/api/v1/reports?engagement_id=${engId}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('token')}`,
      },
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pentest-report-${engId}.html`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      });
  };

  const activeEngagement = engagements.find((e) => e.id === selectedId);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left: Engagement Creation & List */}
      <div className="lg:col-span-1 space-y-6">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-bold mb-4 text-white">Create Engagement</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Engagement Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                placeholder="Internal Staging Assessment"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Target Company</label>
              <input
                type="text"
                value={company}
                onChange={(e) => setCompany(e.target.value)}
                required
                className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                placeholder="MyCompany Ltd"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Authorization Reference</label>
              <input
                type="text"
                value={authRef}
                onChange={(e) => setAuthRef(e.target.value)}
                required
                className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                placeholder="Written Consent Doc #123"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Description</label>
              <textarea
                value={desc}
                onChange={(e) => setDesc(e.target.value)}
                className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm h-20 focus:outline-none focus:border-blue-500"
                placeholder="Assess staging environments for header anomalies..."
              />
            </div>
            <button
              type="submit"
              className="w-full bg-blue-600 hover:bg-blue-500 font-bold py-2 rounded text-sm transition"
            >
              Add Engagement
            </button>
          </form>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-bold mb-4 text-white">Active Engagements</h2>
          {engagements.length === 0 ? (
            <p className="text-gray-400 text-sm">No engagements configured.</p>
          ) : (
            <div className="space-y-2">
              {engagements.map((e) => (
                <button
                  key={e.id}
                  onClick={() => setSelectedId(e.id)}
                  className={`w-full text-left p-3 rounded border text-sm transition ${
                    selectedId === e.id
                      ? 'bg-blue-600/20 border-blue-500 text-blue-300'
                      : 'bg-gray-900/60 border-gray-800 hover:bg-gray-900 text-gray-300'
                  }`}
                >
                  <p className="font-bold">{e.name}</p>
                  <p className="text-xs text-gray-400 mt-1">{e.company}</p>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: Selected Engagement Details */}
      <div className="lg:col-span-2">
        {activeEngagement ? (
          <div className="space-y-6">
            {/* Header info */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 flex justify-between items-center">
              <div>
                <h1 className="text-xl font-bold text-white">{activeEngagement.name}</h1>
                <p className="text-sm text-gray-400 mt-1">Company: {activeEngagement.company}</p>
                <p className="text-xs text-gray-500 mt-1">Authorization Ref: {activeEngagement.authorization_reference}</p>
              </div>
              <div className="flex flex-col items-end space-y-2">
                <span
                  className={`px-3 py-1 text-xs font-bold rounded ${
                    activeEngagement.is_verified
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                  }`}
                >
                  {activeEngagement.is_verified ? 'VERIFIED BOUNDARY' : 'UNVERIFIED BOUNDARY'}
                </span>
                <button
                  onClick={() => handleDownloadReport(activeEngagement.id)}
                  className="bg-gray-700 hover:bg-gray-600 font-bold py-1.5 px-3 rounded text-xs transition"
                >
                  Export Report
                </button>
              </div>
            </div>

            {/* Scope rules */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h2 className="text-lg font-bold mb-4">Authorized Scoping</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-semibold text-gray-400 mb-2">Scope Rules</h3>
                  {activeEngagement.scopes.length === 0 ? (
                    <p className="text-gray-500 text-xs">No scope rules defined yet.</p>
                  ) : (
                    <div className="space-y-1">
                      {activeEngagement.scopes.map((s) => (
                        <div
                          key={s.id}
                          className="flex justify-between items-center p-2 bg-gray-900 border border-gray-800 rounded text-xs"
                        >
                          <code>{s.pattern}</code>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              s.is_excluded ? 'bg-red-950 text-red-400' : 'bg-blue-950 text-blue-400'
                            }`}
                          >
                            {s.is_excluded ? 'EXCLUDED' : 'ALLOWED'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <form onSubmit={(e) => handleAddScope(e, activeEngagement.id)} className="space-y-3">
                  <h3 className="text-sm font-semibold text-gray-400">Add Target Pattern</h3>
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={scopeType}
                      onChange={(e) => setScopeType(e.target.value)}
                      className="bg-gray-900 border border-gray-700 rounded p-1.5 text-xs text-white"
                    >
                      <option value="domain">Domain</option>
                      <option value="subdomain">Subdomain wildcard</option>
                      <option value="ip">IP Address</option>
                      <option value="cidr">CIDR Range</option>
                      <option value="url">URL</option>
                    </select>
                    <select
                      value={scopeExcluded ? 'true' : 'false'}
                      onChange={(e) => setScopeExcluded(e.target.value === 'true')}
                      className="bg-gray-900 border border-gray-700 rounded p-1.5 text-xs text-white"
                    >
                      <option value="false">Allow</option>
                      <option value="true">Exclude</option>
                    </select>
                  </div>
                  <input
                    type="text"
                    value={scopePattern}
                    onChange={(e) => setScopePattern(e.target.value)}
                    required
                    className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs focus:outline-none"
                    placeholder="e.g. *.mycompany.com"
                  />
                  <button
                    type="submit"
                    className="w-full bg-gray-700 hover:bg-gray-600 font-semibold py-1.5 rounded text-xs transition"
                  >
                    Add Scoping Rule
                  </button>
                </form>
              </div>
            </div>

            {/* Target verification */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h2 className="text-lg font-bold mb-4">Ownership Verification</h2>
              <form onSubmit={(e) => handleVerify(e, activeEngagement.id)} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-400 mb-1">Target Hostname</label>
                    <input
                      type="text"
                      value={verifyDomain}
                      onChange={(e) => setVerifyDomain(e.target.value)}
                      required
                      placeholder="staging.mycompany.com"
                      className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-400 mb-1">Verification Method</label>
                    <select
                      value={verifyMethod}
                      onChange={(e) => setVerifyMethod(e.target.value)}
                      className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs"
                    >
                      <option value="dns">DNS TXT Record Check</option>
                      <option value="http">HTTP Path Well-known File</option>
                      <option value="manual">Manual Admin Override</option>
                    </select>
                  </div>
                  {verifyMethod === 'manual' && (
                    <div>
                      <label className="block text-xs font-semibold text-gray-400 mb-1">Manual Override Ticket</label>
                      <input
                        type="text"
                        value={manualRef}
                        onChange={(e) => setManualRef(e.target.value)}
                        required
                        placeholder="SecOps Ticket #456"
                        className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs"
                      />
                    </div>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <button
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-500 font-bold py-2 px-6 rounded text-xs transition"
                  >
                    Run Domain Verification
                  </button>
                  <span className="text-xs font-semibold text-yellow-500">{verifyMessage}</span>
                </div>
              </form>
            </div>

            {/* Run scans */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h2 className="text-lg font-bold mb-4">Trigger Safe Scan</h2>
              <form onSubmit={(e) => handleStartScan(e, activeEngagement.id)} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-400 mb-1">Target Endpoint / IP</label>
                    <input
                      type="text"
                      value={scanTarget}
                      onChange={(e) => setScanTarget(e.target.value)}
                      required
                      placeholder="https://staging.mycompany.com"
                      className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-400 mb-1">Testing Profile</label>
                    <select
                      value={scanProfile}
                      onChange={(e) => setScanProfile(e.target.value)}
                      className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs"
                    >
                      <option value="safe">SAFE Scan (Headers, SSL/TLS, Cookies)</option>
                      <option value="passive">PASSIVE Scan (DNS & Metadata only)</option>
                    </select>
                  </div>
                </div>
                <button
                  type="submit"
                  className="bg-emerald-600 hover:bg-emerald-500 font-bold py-2 px-6 rounded text-xs transition"
                >
                  Start Safe Assessment
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="text-center py-20 bg-gray-800/40 border border-gray-700 rounded-lg text-gray-400">
            Select an active engagement from the left panel to configure scope boundaries and run scans.
          </div>
        )}
      </div>
    </div>
  );
}
