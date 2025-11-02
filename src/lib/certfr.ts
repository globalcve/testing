/**
 * CERT-FR Advisory Parser
 * Source: https://cert.ssi.gouv.fr/
 */

const CERT_FR_FEED = 'https://cert.ssi.gouv.fr/feed/';
const CERT_FR_ALERTS = 'https://cert.ssi.gouv.fr/alerts/';

interface CertFRAdvisory {
  id: string;          // CERTFR-YYYY-XXX
  cves: string[];
  title: string;
  description: string;
  published: string;
  updated: string;
  risk: string;
  systems: string[];
  references: string[];
}

/**
 * Fetches CERT-FR advisories
 * Returns array of normalized vulnerability objects
 */
export async function fetchCertFR( ): Promise<any[]> {
  const results: any[] = [];

  try {
    // Fetch both French and English feeds
    const [frRes, enRes] = await Promise.all([
      fetch(`${CERT_FR_FEED}fr.xml`),
      fetch(`${CERT_FR_FEED}en.xml`)
    ]);

    if (!frRes.ok && !enRes.ok) {
      throw new Error('Both FR and EN feeds failed');
    }

    // Parse both feeds
    const feeds = [];
    if (frRes.ok) {
      const frText = await frRes.text();
      feeds.push({ lang: 'fr', data: frText });
    }
    if (enRes.ok) {
      const enText = await enRes.text();
      feeds.push({ lang: 'en', data: enText });
    }

    // Process each feed
    for (const { lang, data } of feeds) {
      try {
        // Extract items
        const items = data.match(/<item>[\s\S]*?<\/item>/g) || [];

        for (const item of items) {
          const certId = item.match(/CERTFR-\d{4}-[A-Z]{3,4}\d+/)?.[0];
          if (!certId) continue;

          // Extract CVEs
          const cveMatches = item.matchAll(/CVE-\d{4}-\d{4,}/g);
          const cves = Array.from(new Set(Array.from(cveMatches).map(m => m[0])));

          // Extract other fields
          const title = item.match(/<title>(.*?)<\/title>/)?.[1] || '';
          const description = item.match(/<description>(.*?)<\/description>/)?.[1] || '';
          const pubDate = item.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] || '';
          
          // Risk level from title/description
          const risk = inferCertFRRisk(title + ' ' + description);

          // Create entry for each CVE
          for (const cveId of cves) {
            results.push({
              id: cveId,
              description: description.replace(/<[^>]*>/g, '').trim(),
              severity: mapCertFRRisk(risk),
              published: new Date(pubDate).toISOString(),
              source: 'CERT-FR',
              metadata: {
                advisory: certId,
                risk,
                lang,
                alertUrl: `${CERT_FR_ALERTS}${certId}.html`
              }
            });
          }
        }

      } catch (err) {
        console.error(`❌ CERT-FR ${lang} parse error:`, err);
        continue;
      }
    }

    console.log('🇫🇷 CERT-FR CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ CERT-FR fetch error:', err);
    return [];
  }
}

function inferCertFRRisk(text: string): string {
  const lowered = text.toLowerCase();
  
  // French keywords
  if (lowered.includes('critique') || lowered.includes('critical')) return 'CRITICAL';
  if (lowered.includes('important') || lowered.includes('élevé')) return 'HIGH';
  if (lowered.includes('modéré') || lowered.includes('moderate')) return 'MEDIUM';
  if (lowered.includes('faible') || lowered.includes('low')) return 'LOW';
  
  return 'UNKNOWN';
}

function mapCertFRRisk(risk: string): string {
  return risk; // Already in correct format
}
