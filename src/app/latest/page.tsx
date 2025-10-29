'use client';

import { useState, useEffect } from 'react';
import SeveritySection from '../components/SeveritySection';
import CVEStatisticsGraph from '../components/CVEStatisticsGraph';

export default function LatestPage() {
  const [cves, setCves] = useState<{[key: string]: any[]}>({
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
  });
  const [loading, setLoading] = useState(true);
  const [timeframe, setTimeframe] = useState<'24h'|'7d'|'30d'>('24h');
  const [error, setError] = useState('');

  useEffect(() => {
    fetchLatestCVEs();
  }, [timeframe]);

  const fetchLatestCVEs = async () => {
    setLoading(true);
    setError('');

    try {
      // Calculate date range based on timeframe
      const now = new Date();
      const start = new Date(now);
      switch (timeframe) {
        case '7d':
          start.setDate(start.getDate() - 7);
          break;
        case '30d':
          start.setDate(start.getDate() - 30);
          break;
        default: // 24h
          start.setDate(start.getDate() - 1);
      }

      const res = await fetch(`/api/cves?startDate=${start.toISOString()}&sort=newest`);
      if (!res.ok) throw new Error(`Fetch failed with status ${res.status}`);
      
      const data = await res.json();
      const results = data.results || [];

      // Group by severity
      const grouped = results.reduce((acc: {[key: string]: any[]}, cve: any) => {
        const severity = cve.severity || 'UNKNOWN';
        if (!acc[severity]) acc[severity] = [];
        acc[severity].push(cve);
        return acc;
      }, {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
      });

      setCves(grouped);
    } catch (err: any) {
      console.error('❌ Latest CVEs fetch error:', err);
      setError('Failed to fetch latest CVEs. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#282a36] text-[#f8f8f2] p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-4xl font-bold text-[#50fa7b]">Latest Vulnerabilities</h1>
          
          <div className="flex items-center gap-4">
            <select
              value={timeframe}
              onChange={(e) => setTimeframe(e.target.value as '24h'|'7d'|'30d')}
              className="px-4 py-2 rounded-md bg-[#44475a] text-[#f8f8f2] border border-[#6272a4] focus:outline-none focus:ring-2 focus:ring-[#bd93f9]"
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            
            <button
              onClick={() => fetchLatestCVEs()}
              disabled={loading}
              className={`px-4 py-2 rounded-md font-semibold ${
                loading ? 'bg-[#6272a4] cursor-not-allowed' : 'bg-[#50fa7b] hover:bg-[#8be9fd]'
              } text-[#282a36]`}
            >
              {loading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-[#ff5555] text-white rounded-lg">
            {error}
          </div>
        )}

        <div className="mb-8">
          <CVEStatisticsGraph />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <SeveritySection
            title="Critical"
            cves={cves.CRITICAL}
            loading={loading}
            bgColor="bg-[#ff5555]"
          />
          <SeveritySection
            title="High"
            cves={cves.HIGH}
            loading={loading}
            bgColor="bg-[#ffb86c]"
          />
          <SeveritySection
            title="Medium"
            cves={cves.MEDIUM}
            loading={loading}
            bgColor="bg-[#f1fa8c]"
            textColor="text-[#282a36]"
          />
          <SeveritySection
            title="Low"
            cves={cves.LOW}
            loading={loading}
            bgColor="bg-[#50fa7b]"
            textColor="text-[#282a36]"
          />
        </div>
      </div>
    </div>
  );
}