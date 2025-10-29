import React from 'react';
import CveCard from '../components/CveCard';

interface SeveritySectionProps {
  title: string;
  cves: any[];
  loading?: boolean;
  bgColor: string;
  textColor?: string;
}

export default function SeveritySection({ title, cves, loading, bgColor, textColor = 'text-white' }: SeveritySectionProps) {
  return (
    <div className={`p-6 rounded-lg shadow-lg ${bgColor} ${textColor}`}>
      <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
        {title === 'Critical' && '🛑'}
        {title === 'High' && '⚠️'}
        {title === 'Medium' && '🔶'}
        {title === 'Low' && '✅'}
        {title}
        <span className="text-sm font-normal ml-2">({cves.length})</span>
      </h2>
      
      {loading ? (
        <div className="animate-pulse space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-white/10 rounded"></div>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          {cves.length > 0 ? (
            cves.map((cve) => (
              <CveCard key={cve.id} {...cve} />
            ))
          ) : (
            <p className="text-white/70">No vulnerabilities found</p>
          )}
        </div>
      )}
    </div>
  );
}