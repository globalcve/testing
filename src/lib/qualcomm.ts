/**
 * Qualcomm Security Advisory Parser
 * Source: https://www.qualcomm.com/company/product-security/bulletins
 */

const QCOM_BULLETIN_URL = 'https://www.qualcomm.com/company/product-security/bulletins';
const QCOM_API_URL = 'https://www.qualcomm.com/api/security/bulletins';

interface QualcommAdvisory {
  id: string;          // Qualcomm bulletin ID
  cves: string[];      // Associated CVE IDs
  products: string[];  // Affected products
  description: string;
  published: string;
  severity: string;
  impact: string;
}

/**
 * Fetches Qualcomm Security Bulletins
 * Returns array of normalized vulnerability objects
 */
export async function fetchQualcommAdvisories(): Promise<any[]> {
  const results: any[] = [];

  try {
    // Fetch bulletin index
    const res = await fetch(QCOM_API_URL);
    if (!res.ok) throw new Error(`Qualcomm API error: ${res.status}`);

    const data = await res.json();
    const bulletins = data.bulletins || [];

    // Process each bulletin
    for (const bulletin of bulletins) {
      try {
        // Extract CVEs from bulletin
        const cveMatches = bulletin.content?.match(/CVE-\d{4}-\d{4,}/g) || [];
        const cves = Array.from(new Set(cveMatches));

        // Extract affected products
        const products = bulletin.products?.map((p: any) => p.name) || [];

        // Create entry for each CVE
        for (const cveId of cves) {
          results.push({
            id: cveId,
            description: bulletin.description || 
              `Qualcomm security update affecting ${products.join(', ')}`,
            severity: mapQualcommSeverity(bulletin.severity),
            published: bulletin.published_date,
            source: 'QUALCOMM',
            metadata: {
              bulletinId: bulletin.id,
              products,
              impact: bulletin.impact,
              references: [
                `${QCOM_BULLETIN_URL}#${bulletin.id}`,
                ...(bulletin.references || [])
              ]
            }
          });
        }

      } catch (err) {
        console.error('❌ Qualcomm bulletin parse error:', err);
        continue;
      }
    }

    console.log('📱 Qualcomm CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ Qualcomm advisory fetch error:', err);
    return [];
  }
}

function mapQualcommSeverity(severity: string): string {
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