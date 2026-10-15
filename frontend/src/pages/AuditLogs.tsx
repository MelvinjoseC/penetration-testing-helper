import React, { useState, useEffect } from 'react';

interface AuditLogItem {
  id: string;
  action: string;
  target: string | null;
  ip_address: string | null;
  details: Record<string, any> | null;
  created_at: string;
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [actionFilter, setActionFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchLogs = () => {
    setLoading(true);
    const token = localStorage.getItem('token');
    const url = actionFilter
      ? `/api/v1/audit-logs?action=${encodeURIComponent(actionFilter)}&limit=100`
      : '/api/v1/audit-logs?limit=100';

    fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) setLogs(data);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchLogs();
  }, [actionFilter]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Audit Trail</h1>
          <p className="text-gray-400 text-sm">Append-only compliance log for authorized operations</p>
        </div>
        <div className="flex gap-2">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-xs text-white"
          >
            <option value="">All Event Actions</option>
            <option value="USER_LOGIN">USER_LOGIN</option>
            <option value="USER_REGISTER">USER_REGISTER</option>
            <option value="ENGAGEMENT_CREATE">ENGAGEMENT_CREATE</option>
            <option value="ENGAGEMENT_UPDATE">ENGAGEMENT_UPDATE</option>
            <option value="ENGAGEMENT_DELETE">ENGAGEMENT_DELETE</option>
            <option value="ENGAGEMENT_VERIFY">ENGAGEMENT_VERIFY</option>
            <option value="SCOPE_ADD">SCOPE_ADD</option>
            <option value="SCOPE_UPDATE">SCOPE_UPDATE</option>
            <option value="SCOPE_DELETE">SCOPE_DELETE</option>
            <option value="SCAN_START">SCAN_START</option>
            <option value="FINDING_TRIAGE">FINDING_TRIAGE</option>
          </select>
          <button
            onClick={fetchLogs}
            className="bg-gray-800 hover:bg-gray-700 font-semibold py-1.5 px-3 border border-gray-700 rounded text-xs transition"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-700">
          <thead className="bg-gray-900/60">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Timestamp</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Action</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Target Resource</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">IP Origin</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700 bg-gray-800/40">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-6 py-10 text-center text-sm text-gray-400">
                  Loading audit logs...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-10 text-center text-sm text-gray-500">
                  No audit logs found matching criteria.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} className="hover:bg-gray-800/50 transition">
                  <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-400">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-xs font-mono font-bold text-blue-400">
                    {log.action}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-300 font-mono">
                    {log.target || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-400">
                    {log.ip_address || 'Local/Internal'}
                  </td>
                  <td className="px-6 py-4 text-xs text-gray-300 font-mono max-w-xs truncate">
                    {log.details ? JSON.stringify(log.details) : '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
