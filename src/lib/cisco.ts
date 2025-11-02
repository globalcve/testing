import { CVE } from '@/types';
import * as cheerio from 'cheerio';

const CISCO_ADVISORY_URL = 'https://tools.cisco.com/security/center/publicationListing.x';

export async function fetchCiscoAdvisories( ): Promise<CVE[]> {
  try {
    const response = await fetch(CISCO_ADVISORY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Cisco advisories: ${response.statusText}`);
    }
    
    const html = await response.text();
    const $ = cheerio.load(html);

    const cves: CVE[] = [];
    
    // Target the table rows that contain the advisory data.
    // This is a guess based on common Cisco advisory page structure.
    $('table.data-table tr').each((_, row) => {
      const cells = $(row).find('td');
      if (cells.length < 5) return;

      const advisoryLink = $(cells[0]).find('a');
      const advisoryTitle = advisoryLink.text().trim();
      const advisoryUrl = advisoryLink.attr('href') || CISCO_ADVISORY_URL;
      const publishDate = $(cells[1]).text().trim();
      const cveId = $(cells[2]).text().trim();
      const cvssScore = $(cells[3]).text().trim();

      if (!cveId.startsWith('CVE-')) return;

      // Extract product information from title
      const productMatch = advisoryTitle.match(/\[(.*?)\]/);
      const product = productMatch ? productMatch[1] : 'Unknown Product';

      cves.push({
        id: cveId,
        description: advisoryTitle,
        severity: inferSeverityFromCVSS(parseFloat(cvssScore)),
        published: new Date(publishDate).toISOString(),
        source: 'CISCO',
        metadata: {
          product,
          cvssScore,
          advisoryUrl,
          type: 'Cisco Security Advisory',
          vendor: 'Cisco'
        }
      });
    });

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
