/**
 * Atlassian Security Advisory Parser
 * Source: https://security.atlassian.com/advisories
 */

const ATLASSIAN_API = 'https://security.atlassian.com/rest/api/1/advisories';

interface AtlassianAdvisory {
  id: string;         // Advisory ID
  cveIds: string[];   // CVE IDs
  products: string[]; // Affected products
  severity: string;
  published: string;
  title: string;
  description: string;
  affectedVersions: { [key: string]: string[] };
  fixedVersions: { [key: string]: string[] };
}

/**
 * Fetches Atlassian Security Advisories
 * Returns array of normalized vulnerability objects
 */
export async function fetchAtlassianAdvisories(): Promise<any[]> {
  const results: any[] = [];

  try {
    // Fetch recent advisories (last 90 days)
    const nintyDaysAgo = new Date();
    nintyDaysAgo.setDate(nintyDaysAgo.getDate() - 90);

    const res = await fetch(`${ATLASSIAN_API}?publishedAfter=${nintyDaysAgo.toISOString()}`);
    if (!res.ok) throw new Error(`Atlassian API error: ${res.status}`);

    const advisories = await res.json();

    for (const advisory of advisories) {
      try {
        const cves = advisory.cveIds || [];
        const products = Object.keys(advisory.affectedVersions || {});

        // Format affected versions
        const affectedVersions = products.map(product => {
          const versions = advisory.affectedVersions[product] || [];
          return `${product} ${versions.join(', ')}`;
        });

        // Format fixed versions
        const fixedVersions = products.map(product => {
          const versions = advisory.fixedVersions[product] || [];
          return `${product} ${versions.join(', ')}`;
        });

        // Create entry for each CVE
        for (const cveId of cves) {
          results.push({
            id: cveId,
            description: advisory.description || advisory.title,
            severity: mapAtlassianSeverity(advisory.severity),
            published: advisory.published,
            source: 'ATLASSIAN',
            metadata: {
              advisory: advisory.id,
              products,
              affectedVersions,
              fixedVersions,
              advisory_url: `https://security.atlassian.com/advisory/${advisory.id}`
            }
          });
        }

      } catch (err) {
        console.error('❌ Atlassian advisory parse error:', err);
        continue;
      }
    }

    console.log('🔵 Atlassian CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ Atlassian advisory fetch error:', err);
    return [];
  }
}

function mapAtlassianSeverity(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'medium':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    default:
      return 'UNKNOWN';
  }
}