/**
 * Microsoft Windows Security Update Parser
 * Sources:
 * - MSRC API: https://api.msrc.microsoft.com/
 * - Security Update Guide: https://msrc.microsoft.com/update-guide/
 */

const MSRC_API = 'https://api.msrc.microsoft.com/cvrf/v2.0';
const MSRC_API_KEY = process.env.MSRC_API_KEY;

interface WindowsUpdate {
  id: string;         // CVE ID
  kb: string;         // KB article number
  title: string;
  description: string;
  severity: string;
  published: string;
  updated: string;
  products: string[];
  impact: string;
}

/**
 * Fetches Microsoft Windows Security Updates
 * Returns array of normalized vulnerability objects
 */
export async function fetchWindowsUpdates(): Promise<any[]> {
  const results: any[] = [];

  try {
    // Get recent update guides (last 3 months)
    const headers: any = {
      'Accept': 'application/json',
    };
    if (MSRC_API_KEY) {
      headers['api-key'] = MSRC_API_KEY;
    }

    // Get update guides for last 3 months
    const months = Array.from({ length: 3 }, (_, i) => {
      const date = new Date();
      date.setMonth(date.getMonth() - i);
      return date.toISOString().slice(0, 7);
    });

    for (const month of months) {
      try {
        const res = await fetch(`${MSRC_API}/updates?date=${month}`, { headers });
        if (!res.ok) continue;

        const data = await res.json();
        const updates = data.value || [];

        // Process each update
        for (const update of updates) {
          try {
            // Get detailed vulnerability info
            const vulnRes = await fetch(`${MSRC_API}/vulnerabilities/${update.id}`, { headers });
            if (!vulnRes.ok) continue;
            
            const vulnData = await vulnRes.json();
            const threats = vulnData.threats || [];
            const products = vulnData.products || [];

            // Map to common format
            results.push({
              id: update.id, // This is the CVE ID
              description: threats[0]?.description?.value || update.title,
              severity: mapWindowsSeverity(threats[0]?.severity),
              published: update.initialReleaseDate,
              source: 'WINDOWS',
              metadata: {
                kb: update.knowledgeBaseId,
                products: products.map((p: any) => p.name),
                impact: threats[0]?.impact,
                remediations: vulnData.remediations?.map((r: any) => ({
                  type: r.type,
                  url: r.url,
                  description: r.description?.value
                })),
                references: [
                  `https://msrc.microsoft.com/update-guide/vulnerability/${update.id}`,
                  update.documentUrl
                ].filter(Boolean)
              }
            });

          } catch (err) {
            console.error('❌ Windows update parse error:', err);
            continue;
          }
        }

      } catch (err) {
        console.error(`❌ Windows updates fetch error for ${month}:`, err);
        continue;
      }
    }

    console.log('🪟 Windows CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ Windows updates fetch error:', err);
    return [];
  }
}

function mapWindowsSeverity(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'important':
      return 'HIGH';
    case 'moderate':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    default:
      return 'UNKNOWN';
  }
}