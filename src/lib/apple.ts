/**
 * Apple Security Advisory parser
 * Sources: 
 * - https://support.apple.com/en-us/HT201222
 * - https://support.apple.com/en-us/HT201222.rss
 */

const APPLE_HT_URL = 'https://support.apple.com/en-us/HT201222';
const APPLE_RSS_URL = 'https://support.apple.com/en-us/HT201222.rss';

interface AppleAdvisory {
  id: string;         // HT ID
  cves: string[];     // Associated CVE IDs
  product: string;    // Affected product
  version: string;    // Affected version
  description: string;
  published: string;
  url: string;
}

/**
 * Fetches Apple Security Advisories
 * Returns array of normalized vulnerability objects
 */
export async function fetchAppleAdvisories( ): Promise<any[]> {
  const results: any[] = [];

  try {
    // Fetch RSS feed first for recent advisories
    const rssRes = await fetch(APPLE_RSS_URL);
    if (!rssRes.ok) throw new Error(`RSS fetch failed: ${rssRes.status}`);
    
    const rssText = await rssRes.text();
    
    // Parse RSS feed for recent advisories
    const items = rssText.match(/<item>[\s\S]*?<\/item>/g) || [];
    
    for (const item of items) {
      try {
        const title = item.match(/<title>(.*?)<\/title>/)?.[1] || '';
        const link = item.match(/<link>(.*?)<\/link>/)?.[1] || '';
        const pubDate = item.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] || '';
        const description = item.match(/<description>(.*?)<\/description>/)?.[1] || '';
        
        // Extract HT ID from link
        const htId = link.match(/HT\d+/)?.[0];
        if (!htId) continue;

        // Fetch individual advisory page for CVE details
        const advisoryRes = await fetch(link);
        if (!advisoryRes.ok) continue;
        
        const advisoryHtml = await advisoryRes.text();
        
        // Extract CVEs
        const cveMatches = advisoryHtml.matchAll(/CVE-\d{4}-\d{4,}/g);
        const cves = Array.from(new Set(Array.from(cveMatches).map(m => m[0])));
        
        // Extract affected products
        const productMatch = title.match(/for\s+(.*?)$/);
        const product = productMatch?.[1] || 'Apple Product';

        // Create entry for each CVE
        for (const cveId of cves) {
          results.push({
            id: cveId,
            description: description.replace(/<[^>]*>/g, '').trim() || 
              `Security update for ${product}. See ${htId} for details.`,
            severity: inferAppleSeverity(description),
            published: new Date(pubDate).toISOString(),
            source: 'APPLE',
            metadata: {
              advisory: htId,
              product,
              advisoryUrl: link
            }
          });
        }

      } catch (err) {
        console.error('❌ Apple advisory parse error:', err);
        continue;
      }
    }

    console.log('🍎 Apple CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ Apple advisory fetch error:', err);
    return [];
  }
}

function inferAppleSeverity(description: string): string {
  const text = description.toLowerCase();
  if (text.includes('arbitrary code execution') || 
      text.includes('kernel') ||
      text.includes('root') ||
      text.includes('elevation of privilege')) {
    return 'CRITICAL';
  }
  if (text.includes('denial of service') ||
      text.includes('information disclosure')) {
    return 'HIGH';
  }
  if (text.includes('bypass') ||
      text.includes('tracking')) {
    return 'MEDIUM';
  }
  return 'UNKNOWN';
}
