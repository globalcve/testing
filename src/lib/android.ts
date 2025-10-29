/**
 * Android Security Bulletin parser
 * Source: https://source.android.com/security/bulletin
 */

const ANDROID_BULLETIN_BASE = 'https://source.android.com/security/bulletin';
const CURRENT_YEAR = new Date().getFullYear();

interface AndroidBulletinItem {
  id: string;          // CVE ID
  type: string;        // Component type
  severity: string;
  description: string;
  published: string;
  references: string[];
  platform: string[];  // Affected Android versions
  patch: string;       // Patch level
}

/**
 * Fetches and parses Android Security Bulletins
 * Returns array of normalized vulnerability objects
 */
export async function fetchAndroidBulletin(): Promise<any[]> {
  const results: any[] = [];
  
  try {
    // Fetch last 12 months of bulletins
    const startYear = CURRENT_YEAR - 1;
    const months = Array.from({ length: 12 }, (_, i) => {
      const date = new Date();
      date.setMonth(date.getMonth() - i);
      return {
        year: date.getFullYear(),
        month: (date.getMonth() + 1).toString().padStart(2, '0')
      };
    });

    for (const { year, month } of months) {
      try {
        const bulletinUrl = `${ANDROID_BULLETIN_BASE}/${year}-${month}-01`;
        console.log(`🤖 Fetching Android bulletin: ${year}-${month}`);
        
        const res = await fetch(bulletinUrl);
        if (!res.ok) continue;

        const html = await res.text();
        
        // Extract CVE details from bulletin HTML
        const cveMatches = html.matchAll(
          /CVE-\d{4}-\d{4,}.*?Severity:\s*(Critical|High|Moderate|Low).*?Component:\s*([^<\n]+)/gi
        );

        for (const match of Array.from(cveMatches)) {
          const [full, severity, component] = match;
          const cveId = full.match(/CVE-\d{4}-\d{4,}/)?.[0];
          
          if (!cveId) continue;

          // Extract description if available
          const descriptionMatch = full.match(/Description:(.*?)(?=CVE-|Severity:|$)/i);
          const description = descriptionMatch?.[1]?.trim() || 
            `Android ${component?.trim()} vulnerability addressed in ${year}-${month} security patch level`;

          results.push({
            id: cveId,
            description,
            severity: mapAndroidSeverity(severity),
            published: `${year}-${month}-01`,
            source: 'ANDROID',
            metadata: {
              component: component?.trim(),
              patchLevel: `${year}-${month}-01`,
              bulletinUrl
            }
          });
        }

      } catch (err) {
        console.error(`❌ Android bulletin fetch error for ${year}-${month}:`, err);
        continue;
      }
    }

    console.log('🤖 Android CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ Android bulletin fetch error:', err);
    return [];
  }
}

function mapAndroidSeverity(severity: string): string {
  switch (severity?.trim().toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'moderate':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    default:
      return 'UNKNOWN';
  }
}