import React, { useState } from 'react';
import { HashRouter, Routes, Route, Link } from 'react-router-dom';
import { Shield, LayoutDashboard, Target, ListCollapse, LogOut } from 'lucide-react';

import Dashboard from './pages/Dashboard';
import Engagements from './pages/Engagements';
import ScanDetails from './pages/ScanDetails';
import FindingDetails from './pages/FindingDetails';

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  
  // Auth Form State
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    
    const params = new URLSearchParams();
    params.append('username', email);
    params.append('password', password);

    fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Authentication failed.');
        }
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
      })
      .catch((err) => setErrorMsg(err.message));
  };

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');

    fetch('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        organization_name: orgName,
      }),
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Registration failed.');
        }
        // Auto login on success
        const params = new URLSearchParams();
        params.append('username', email);
        params.append('password', password);
        return fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params,
        });
      })
      .then((res) => res?.json())
      .then((data) => {
        if (data && data.access_token) {
          localStorage.setItem('token', data.access_token);
          setToken(data.access_token);
        }
      })
      .catch((err) => setErrorMsg(err.message));
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  const handleDevAutofill = () => {
    setIsRegister(false);
    setEmail('admin@local.test');
    setPassword('Password123!');
  };

  // Auth Gate
  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950 p-4">
        <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-lg p-8 shadow-2xl">
          <div className="flex flex-col items-center mb-6">
            <Shield className="w-12 h-12 text-blue-500 mb-2" />
            <h1 className="text-xl font-bold tracking-tight text-white">AI Penetration Testing</h1>
            <p className="text-gray-400 text-xs mt-1">Authorized internal compliance testing platform</p>
          </div>

          <form onSubmit={isRegister ? handleRegister : handleLogin} className="space-y-4">
            {isRegister && (
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1">Organization Name</label>
                <input
                  type="text"
                  required
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                  placeholder="Acme Corporation"
                />
              </div>
            )}
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Operator Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                placeholder="operator@company.com"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1">Secret Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded p-2 text-sm focus:outline-none focus:border-blue-500"
                placeholder="••••••••"
              />
            </div>

            <div className="flex gap-2">
              <button
                type="submit"
                className="flex-grow bg-blue-600 hover:bg-blue-500 font-bold py-2 rounded text-sm transition"
              >
                {isRegister ? 'Register Administrative Tenant' : 'Authenticate Operator'}
              </button>
              
              {!isRegister && (
                <button
                  type="button"
                  onClick={handleDevAutofill}
                  className="bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold py-2 px-3 rounded text-xs border border-gray-700 transition"
                  title="Autofill default developer credentials"
                >
                  Quick Dev Autofill
                </button>
              )}
            </div>
          </form>

          {errorMsg && <p className="text-xs text-red-500 text-center mt-4 font-semibold">{errorMsg}</p>}

          <div className="text-center mt-6">
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setErrorMsg('');
              }}
              className="text-xs text-gray-400 hover:text-white underline transition"
            >
              {isRegister ? 'Already registered? Authenticate' : 'Register new security tenant'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <HashRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col md:flex-row">
        {/* Sidebar Nav */}
        <aside className="w-full md:w-64 bg-gray-900 border-r border-gray-800 p-6 flex flex-col justify-between">
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <Shield className="w-8 h-8 text-blue-500" />
              <div>
                <p className="font-bold text-sm tracking-tight text-white">ORCHESTRATOR</p>
                <span className="text-[10px] bg-blue-950 text-blue-400 font-bold px-1.5 py-0.5 rounded border border-blue-900">
                  MVP VER.
                </span>
              </div>
            </div>

            <nav className="space-y-1">
              <Link
                to="/"
                className="flex items-center space-x-3 px-3 py-2 rounded text-sm font-medium hover:bg-gray-800 transition"
              >
                <LayoutDashboard className="w-4 h-4" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/engagements"
                className="flex items-center space-x-3 px-3 py-2 rounded text-sm font-medium hover:bg-gray-800 transition"
              >
                <Target className="w-4 h-4" />
                <span>Engagements</span>
              </Link>
              <Link
                to="/scans"
                className="flex items-center space-x-3 px-3 py-2 rounded text-sm font-medium hover:bg-gray-800 transition"
              >
                <ListCollapse className="w-4 h-4" />
                <span>Scan Pipeline</span>
              </Link>
            </nav>
          </div>

          <button
            onClick={handleLogout}
            className="flex items-center space-x-3 px-3 py-2 text-gray-400 hover:text-white rounded text-sm font-medium hover:bg-gray-800/60 transition mt-6"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign Out</span>
          </button>
        </aside>

        {/* Content Panel */}
        <main className="flex-1 p-6 md:p-8 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/engagements" element={<Engagements />} />
            <Route path="/scans" element={<ScanDetails />} />
            <Route path="/findings/:id" element={<FindingDetails />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
}
