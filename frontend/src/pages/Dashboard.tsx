import React, { useState, useEffect } from 'react';

interface Finding {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  scanner: string;
  created_at: string;
}

interface Scan {
  id: string;
  target: string;
  status: string;
  profile: string;
}

export default function Dashboard() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) return;

    const headers = { Authorization: `Bearer ${token}` };

    Promise.all([
      fetch('/api/v1/findings', { headers }).then((res) => res.json()),
      fetch('/api/v1/scans', { headers }).then((res) => res.json()),
    ])
      .then(([findingsData, scansData]) => {
        if (Array.isArray(findingsData)) setFindings(findingsData);
        if (Array.isArray(scansData)) setScans(scansData);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  const counts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } as Record<string, number>
  );

  if (loading) {
    return <div className="text-center py-10">Loading security intelligence...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security Command Center</h1>
        <p className="text-gray-400 text-sm">Real-time threat status & scan posture</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {[
          { label: 'Critical', count: counts.Critical, color: 'border-red-600 bg-red-950/20 text-red-400' },
          { label: 'High', count: counts.High, color: 'border-orange-500 bg-orange-950/20 text-orange-400' },
          { label: 'Medium', count: counts.Medium, color: 'border-gray-500 bg-gray-800/40 text-gray-300' },
          { label: 'Low', count: counts.Low, color: 'border-blue-500 bg-blue-950/20 text-blue-400' },
          { label: 'Info', count: counts.Info, color: 'border-emerald-500 bg-emerald-950/20 text-emerald-400' },
        ].map((stat) => (
          <div key={stat.label} className={`p-4 border rounded-lg shadow ${stat.color}`}>
            <p className="text-sm font-semibold">{stat.label}</p>
            <p className="text-3xl font-bold mt-2">{stat.count}</p>
          </div>
        ))}
      </div>

      {/* Grid: Scans & Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scans Status */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-bold mb-4">Background Scan Posture</h2>
          {scans.length === 0 ? (
            <p className="text-gray-400 text-sm">No scans configured yet.</p>
          ) : (
            <div className="space-y-3">
              {scans.slice(0, 5).map((scan) => (
                <div key={scan.id} className="flex justify-between items-center p-3 bg-gray-900/60 rounded border border-gray-800">
                  <div>
                    <p className="text-sm font-medium">{scan.target}</p>
                    <p className="text-xs text-gray-400">{scan.profile.toUpperCase()} profile</p>
                  </div>
                  <span
                    className={`px-2 py-1 text-xs font-semibold rounded ${
                      scan.status === 'completed'
                        ? 'bg-emerald-950/50 text-emerald-400'
                        : scan.status === 'running'
                        ? 'bg-blue-950/50 text-blue-400'
                        : 'bg-yellow-950/50 text-yellow-400'
                    }`}
                  >
                    {scan.status.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Vulnerability Discoveries */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-bold mb-4">Recent Findings</h2>
          {findings.length === 0 ? (
            <p className="text-gray-400 text-sm">No findings discovered yet.</p>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 5).map((finding) => (
                <a
                  href={`/findings/${finding.id}`}
                  key={finding.id}
                  className="block p-3 bg-gray-900/60 hover:bg-gray-900 rounded border border-gray-800 transition"
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="text-sm font-medium hover:underline">{finding.title}</p>
                      <p className="text-xs text-gray-500">Scanner: {finding.scanner}</p>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-xs font-semibold rounded ${
                        finding.severity === 'Critical' || finding.severity === 'High'
                          ? 'bg-red-950/50 text-red-400'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
