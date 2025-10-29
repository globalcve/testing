import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const CISCO_ADVISORY_URL = 'https://tools.cisco.com/security/center/publicationListing.x';

export async function fetchCiscoAdvisories(): Promise<CVE[]> {
  try {
    const response = await fetch(CISCO_ADVISORY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Cisco advisories: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const advisoryElements = doc.querySelectorAll('.cisco_alert');

    for (const advisory of Array.from(advisoryElements)) {
      const titleElement = advisory.querySelector('.alert_title');
      const dateElement = advisory.querySelector('.alert_date');
      const impactElement = advisory.querySelector('.cvss_score');
      const cveElement = advisory.querySelector('.cve_id');

      const title = titleElement?.textContent?.trim() || '';
      const publishDate = dateElement?.textContent?.trim() || '';
      const cvssScore = impactElement?.textContent?.trim() || '';
      const cveId = cveElement?.textContent?.trim() || '';

      if (!cveId.startsWith('CVE-')) continue;

      // Extract product information from title
      const productMatch = title.match(/\[(.*?)\]/);
      const product = productMatch ? productMatch[1] : 'Unknown Product';

      cves.push({
        id: cveId,
        description: title,
        severity: inferSeverityFromCVSS(parseFloat(cvssScore)),
        published: new Date(publishDate).toISOString(),
        source: 'CISCO',
        metadata: {
          product,
          cvssScore,
          advisoryUrl: CISCO_ADVISORY_URL,
          type: 'Cisco Security Advisory',
          vendor: 'Cisco'
        }
      });
    }

    return cves;
  } catch (error) {
    console.error('Error fetching Cisco advisories:', error);
    return [];
  }
}

function inferSeverityFromCVSS(score: number): string {
  if (isNaN(score)) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0.0) return 'LOW';
  return 'UNKNOWN';
}