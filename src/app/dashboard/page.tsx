'use client';

import { useState, useEffect } from 'react';
import CVEStatisticsGraph from '../components/CVEStatisticsGraph';
import Statistics from '../components/Statistics';
import SeverityDistributionChart from '../components/SeverityDistributionChart';
import TrendChart from '../components/TrendChart';
import TopSourcesChart from '../components/TopSourcesChart';
import LoadingSpinner from '../components/LoadingSpinner';
import CveCard from '../components/CveCard';
import SeveritySection from '../components/SeveritySection';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'trends' | 'sources' | 'severity'>('overview');
  const [stats, setStats] = useState<any>(null);
  const [cves, setCves] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeframe, setTimeframe] = useState<'7d' | '30d' | '1y'>('30d');
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
  }, [timeframe]);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError('');

    try {
      const now = new Date();
      const start = new Date(now);
      
      switch (timeframe) {
        case '7d':
          start.setDate(start.getDate() - 7);
          break;
        case '30d':
          start.setDate(start.getDate() - 30);
          break;
        case '1y':
          start.setFullYear(start.getFullYear() - 1);
          break;
      }

      const res = await fetch(`/api/cves?query=CVE-2025&startDate=${start.toISOString()}&sort=newest&startIndex=0`);
      if (!res.ok) throw new Error(`Fetch failed with status ${res.status}`);
      
      const data = await res.json();
      setStats(data.stats);
      setCves(data.results || []);
    } catch (err: any) {
      console.error('❌ Dashboard fetch error:', err);
      setError('Failed to fetch dashboard data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊', color: 'text-[#50fa7b]' },
    { id: 'trends', label: 'Trends', icon: '📈', color: 'text-[#8be9fd]' },
    { id: 'sources', label: 'Sources', icon: '🌐', color: 'text-[#ff79c6]' },
    { id: 'severity', label: 'Severity', icon: '⚠️', color: 'text-[#ffb86c]' },
  ];

  // Group CVEs by severity
  const cvesBySeverity = cves.reduce((acc: any, cve: any) => {
    const severity = cve.severity || 'UNKNOWN';
    if (!acc[severity]) acc[severity] = [];
    acc[severity].push(cve);
    return acc;
  }, { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] });

  return (
    <div className="min-h-screen bg-[#282a36] text-[#f8f8f2]">
      {/* Navigation */}
      <nav className="w-full bg-[#44475a] text-[#f8f8f2] py-4 px-6 flex justify-between items-center">
        <h1 className="text-xl font-bold text-[#50fa7b]">GlobalCVE</h1>
        <ul className="flex space-x-6 text-sm">
          <li><a href="/" className="hover:underline text-[#8be9fd]">Home</a></li>
          <li><a href="/latest" className="hover:underline text-[#ff79c6]">Latest CVEs</a></li>
          <li><a href="/dashboard" className="hover:underline text-[#bd93f9] font-bold">Dashboard</a></li>
          <li><a href="/docs" className="hover:underline text-[#f1fa8c]">API Docs</a></li>
          <li><a href="https://github.com/globalcve" className="hover:underline text-[#ffb86c]">GitHub</a></li>
        </ul>
      </nav>

      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-4xl font-bold text-[#50fa7b] mb-2">CVE Dashboard</h1>
            <p className="text-[#6272a4]">Real-time vulnerability intelligence and analytics</p>
          </div>
          
          <div className="flex items-center gap-4">
            <select
              value={timeframe}
              onChange={(e) => setTimeframe(e.target.value as any)}
              className="px-4 py-2 rounded-md bg-[#44475a] text-[#f8f8f2] border border-[#6272a4] focus:outline-none focus:ring-2 focus:ring-[#bd93f9]"
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="1y">Last Year</option>
            </select>
            
            <button
              onClick={() => fetchDashboardData()}
              disabled={loading}
              className={`px-4 py-2 rounded-md font-semibold ${
                loading ? 'bg-[#6272a4] cursor-not-allowed' : 'bg-[#50fa7b] hover:bg-[#8be9fd]'
              } text-[#282a36]`}
            >
              {loading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-2 mb-8 border-b border-[#44475a]">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-6 py-3 font-semibold transition-colors ${
                activeTab === tab.id
                  ? `${tab.color} border-b-2 border-current`
                  : 'text-[#6272a4] hover:text-[#f8f8f2]'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="mb-6 p-4 bg-[#ff5555] text-white rounded-lg">
            {error}
            <button
              onClick={() => fetchDashboardData()}
              className="ml-4 px-3 py-1 bg-[#ff6e6e] rounded hover:bg-[#ff7979]"
            >
              Retry
            </button>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-20">
            <LoadingSpinner />
          </div>
        ) : (
          <div className="space-y-8">
            {/* Overview Tab */}
            {activeTab === 'overview' && stats && (
              <div className="space-y-6">
                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h2 className="text-2xl font-bold text-[#50fa7b] mb-4">Overall Statistics</h2>
                  <Statistics stats={stats} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                    <h3 className="text-xl font-bold text-[#8be9fd] mb-4">Severity Distribution</h3>
                    <SeverityDistributionChart stats={stats} />
                  </div>

                  <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                    <h3 className="text-xl font-bold text-[#ff79c6] mb-4">Top Sources</h3>
                    <TopSourcesChart stats={stats} />
                  </div>
                </div>

                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h3 className="text-xl font-bold text-[#bd93f9] mb-4">CVE Trends Over Time</h3>
                  <CVEStatisticsGraph />
                </div>

                {/* Latest CVEs in Overview */}
                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h3 className="text-xl font-bold text-[#50fa7b] mb-4">Latest CVEs ({cves.length} total)</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {cves.slice(0, 10).map((cve: any) => (
                      <CveCard key={cve.id} {...cve} />
                    ))}
                  </div>
                  {cves.length > 10 && (
                    <div className="mt-4 text-center">
                      <a href="/latest" className="text-[#8be9fd] hover:underline">
                        View all {cves.length} CVEs →
                      </a>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Trends Tab */}
            {activeTab === 'trends' && (
              <div className="space-y-6">
                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h2 className="text-2xl font-bold text-[#8be9fd] mb-4">Vulnerability Trends</h2>
                  <CVEStatisticsGraph />
                </div>

                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h3 className="text-xl font-bold text-[#50fa7b] mb-4">Growth Analysis</h3>
                  <TrendChart stats={stats} timeframe={timeframe} />
                </div>
              </div>
            )}

            {/* Sources Tab */}
            {activeTab === 'sources' && stats && (
              <div className="space-y-6">
                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h2 className="text-2xl font-bold text-[#ff79c6] mb-4">CVE Sources Analysis</h2>
                  <TopSourcesChart stats={stats} detailed={true} />
                </div>

                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h3 className="text-xl font-bold text-[#8be9fd] mb-4">Source Coverage</h3>
                  {stats.bySources ? (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {Object.entries(stats.bySources).slice(0, 8).map(([source, count]: [string, any]) => (
                        <div key={source} className="bg-[#282a36] p-4 rounded-lg">
                          <div className="text-2xl font-bold text-[#50fa7b]">{count}</div>
                          <div className="text-sm text-[#6272a4] truncate">{source}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[#6272a4]">No source data available</p>
                  )}
                </div>
              </div>
            )}

            {/* Severity Tab */}
            {activeTab === 'severity' && stats && (
              <div className="space-y-6">
                <div className="bg-[#44475a] rounded-lg p-6 border border-[#6272a4]">
                  <h2 className="text-2xl font-bold text-[#ffb86c] mb-4">Severity Analysis</h2>
                  <SeverityDistributionChart stats={stats} detailed={true} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-[#44475a] p-6 rounded-lg border-l-4 border-[#ff5555]">
                    <div className="text-3xl font-bold text-[#ff5555]">
                      {stats.bySeverity?.CRITICAL || 0}
                    </div>
                    <div className="text-sm text-[#6272a4] mt-2">Critical Vulnerabilities</div>
                    <div className="text-xs text-[#6272a4] mt-1">
                      {stats.total ? Math.round((stats.bySeverity?.CRITICAL || 0) / stats.total * 100) : 0}% of total
                    </div>
                  </div>

                  <div className="bg-[#44475a] p-6 rounded-lg border-l-4 border-[#ffb86c]">
                    <div className="text-3xl font-bold text-[#ffb86c]">
                      {stats.bySeverity?.HIGH || 0}
                    </div>
                    <div className="text-sm text-[#6272a4] mt-2">High Severity</div>
                    <div className="text-xs text-[#6272a4] mt-1">
                      {stats.total ? Math.round((stats.bySeverity?.HIGH || 0) / stats.total * 100) : 0}% of total
                    </div>
                  </div>

                  <div className="bg-[#44475a] p-6 rounded-lg border-l-4 border-[#f1fa8c]">
                    <div className="text-3xl font-bold text-[#f1fa8c]">
                      {stats.bySeverity?.MEDIUM || 0}
                    </div>
                    <div className="text-sm text-[#6272a4] mt-2">Medium Severity</div>
                    <div className="text-xs text-[#6272a4] mt-1">
                      {stats.total ? Math.round((stats.bySeverity?.MEDIUM || 0) / stats.total * 100) : 0}% of total
                    </div>
                  </div>

                  <div className="bg-[#44475a] p-6 rounded-lg border-l-4 border-[#50fa7b]">
                    <div className="text-3xl font-bold text-[#50fa7b]">
                      {stats.bySeverity?.LOW || 0}
                    </div>
                    <div className="text-sm text-[#6272a4] mt-2">Low Severity</div>
                    <div className="text-xs text-[#6272a4] mt-1">
                      {stats.total ? Math.round((stats.bySeverity?.LOW || 0) / stats.total * 100) : 0}% of total
                    </div>
                  </div>
                </div>

                {/* CVEs by Severity */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <SeveritySection
                    title="Critical"
                    cves={cvesBySeverity.CRITICAL}
                    loading={false}
                    bgColor="bg-[#ff5555]"
                  />
                  <SeveritySection
                    title="High"
                    cves={cvesBySeverity.HIGH}
                    loading={false}
                    bgColor="bg-[#ffb86c]"
                  />
                  <SeveritySection
                    title="Medium"
                    cves={cvesBySeverity.MEDIUM}
                    loading={false}
                    bgColor="bg-[#f1fa8c]"
                    textColor="text-[#282a36]"
                  />
                  <SeveritySection
                    title="Low"
                    cves={cvesBySeverity.LOW}
                    loading={false}
                    bgColor="bg-[#50fa7b]"
                    textColor="text-[#282a36]"
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
