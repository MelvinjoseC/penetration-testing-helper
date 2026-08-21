import React, { useState, useEffect } from 'react';

interface Scan {
  id: string;
  engagement_id: string;
  target: string;
  profile: string;
  status: string;
  created_at: string;
}

export default function ScanDetails() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = () => {
    const headers = {
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    };
    fetch('/api/v1/scans', { headers })
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) setScans(data);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans();
    // Poll scan status every 5 seconds
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="text-center py-10">Loading scan tasks...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Scan Pipeline</h1>
          <p className="text-gray-400 text-sm">Background execution states (Polls every 5s)</p>
        </div>
        <button
          onClick={fetchScans}
          className="bg-gray-800 hover:bg-gray-700 font-semibold py-1.5 px-4 border border-gray-700 rounded text-sm transition"
        >
          Refresh Now
        </button>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-700">
          <thead className="bg-gray-900/60">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Target Host</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Scan Profile</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Start Time</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Job UUID</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700 bg-gray-800/40">
            {scans.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-10 text-center text-sm text-gray-500">
                  No scan jobs triggered. Select an engagement to launch.
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-800/50 transition">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">{scan.target}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    <span className="bg-gray-900 px-2 py-0.5 rounded text-xs border border-gray-800">
                      {scan.profile.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {new Date(scan.created_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span
                      className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                        scan.status === 'completed'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : scan.status === 'running'
                          ? 'bg-blue-950 text-blue-400 border border-blue-800'
                          : scan.status === 'failed'
                          ? 'bg-red-950 text-red-400 border border-red-800'
                          : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                      }`}
                    >
                      {scan.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-500 font-mono">{scan.id}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
