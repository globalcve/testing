'use client';

import React from 'react';

interface SearchFiltersProps {
  filters: {
    severity: string;
    source: string;
    hasExploit: boolean;
    isKev: boolean;
    timeframe: string;
  };
  onChange: (key: string, value: string | boolean) => void;
}

export default function SearchFilters({ filters, onChange }: SearchFiltersProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      <select
        value={filters.severity}
        onChange={(e) => onChange('severity', e.target.value)}
        className="px-4 py-2 rounded-md bg-[#44475a] text-[#f8f8f2] border border-[#6272a4] focus:outline-none focus:ring-2 focus:ring-[#bd93f9]"
      >
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      <select
        value={filters.source}
        onChange={(e) => onChange('source', e.target.value)}
        className="px-4 py-2 rounded-md bg-[#44475a] text-[#f8f8f2] border border-[#6272a4] focus:outline-none focus:ring-2 focus:ring-[#bd93f9]"
      >
        <option value="">All Sources</option>
        <option value="NVD">NVD</option>
        <option value="CIRCL">CIRCL</option>
        <option value="JVN">JVN</option>
        <option value="CNNVD">CNNVD</option>
        <option value="EXPLOITDB">ExploitDB</option>
      </select>

      <select
        value={filters.timeframe}
        onChange={(e) => onChange('timeframe', e.target.value)}
        className="px-4 py-2 rounded-md bg-[#44475a] text-[#f8f8f2] border border-[#6272a4] focus:outline-none focus:ring-2 focus:ring-[#bd93f9]"
      >
        <option value="">Any Time</option>
        <option value="24h">Last 24 Hours</option>
        <option value="7d">Last 7 Days</option>
        <option value="30d">Last 30 Days</option>
        <option value="1y">Last Year</option>
      </select>

      <label className="flex items-center space-x-2 text-[#f8f8f2] cursor-pointer">
        <input
          type="checkbox"
          checked={filters.hasExploit}
          onChange={(e) => onChange('hasExploit', e.target.checked)}
          className="form-checkbox h-5 w-5 text-[#ff79c6] rounded border-[#6272a4] focus:ring-[#ff79c6]"
        />
        <span>Has Exploit</span>
      </label>

      <label className="flex items-center space-x-2 text-[#f8f8f2] cursor-pointer">
        <input
          type="checkbox"
          checked={filters.isKev}
          onChange={(e) => onChange('isKev', e.target.checked)}
          className="form-checkbox h-5 w-5 text-[#50fa7b] rounded border-[#6272a4] focus:ring-[#50fa7b]"
        />
        <span>Known Exploited (KEV)</span>
      </label>
    </div>
  );
}