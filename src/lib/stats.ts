export interface CVEStats {
  totalCount: number;
  bySeverity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    UNKNOWN: number;
  };
  bySource: Record<string, number>;
  byDate: Record<string, number>;
  exploitCount: number;
  kevCount: number;
  topVendors: Array<{ vendor: string; count: number }>;
}

function extractVendor(description: string): string {
  const commonVendors = [
    'Microsoft', 'Apple', 'Google', 'Oracle', 'Cisco', 'Adobe',
    'VMware', 'IBM', 'Red Hat', 'Linux', 'Apache', 'Mozilla',
    'WordPress', 'Drupal', 'PHP', 'Python', 'Node.js', 'Intel',
    'AMD', 'NVIDIA', 'Samsung', 'Lenovo', 'Dell', 'HP'
  ];

  const desc = description.toLowerCase();
  return commonVendors.find(vendor => 
    desc.includes(vendor.toLowerCase())
  ) || 'Other';
}

export function calculateStats(results: any[]): CVEStats {
  const stats: CVEStats = {
    totalCount: results.length,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0
    },
    bySource: {},
    byDate: {},
    exploitCount: 0,
    kevCount: 0,
    topVendors: []
  };

  const vendorCounts: Record<string, number> = {};

  results.forEach(cve => {
    // Count by severity
    const severity = (cve.severity || 'UNKNOWN') as keyof typeof stats.bySeverity;
    stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;

    // Count by source
    stats.bySource[cve.source] = (stats.bySource[cve.source] || 0) + 1;

    // Count by month
    const date = new Date(cve.published);
    const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
    stats.byDate[monthKey] = (stats.byDate[monthKey] || 0) + 1;

    // Count exploits and KEVs
    if (cve.source === 'EXPLOITDB') stats.exploitCount++;
    if (cve.kev) stats.kevCount++;

    // Count vendors
    const vendor = extractVendor(cve.description);
    vendorCounts[vendor] = (vendorCounts[vendor] || 0) + 1;
  });

  // Calculate top vendors
  stats.topVendors = Object.entries(vendorCounts)
    .map(([vendor, count]) => ({ vendor, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return stats;
}