import { CVE } from '@/types';
import * as cheerio from 'cheerio';

const VMWARE_ADVISORY_URL = 'https://www.vmware.com/security/advisories.html';

export async function fetchVMwareAdvisories( ): Promise<CVE[]> {
  try {
    const response = await fetch(VMWARE_ADVISORY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch VMware advisories: ${response.statusText}`);
    }
    
    const html = await response.text();
    const $ = cheerio.load(html);

    const cves: CVE[] = [];
    const advisoryRows = $('table tr');

    advisoryRows.each((_, row) => {
      const cells = $(row).find('td');
      if (cells.length < 5) return;

      const advisoryId = $(cells[0]).text().trim();
      const updateLink = $(cells[0]).find('a').attr('href') || '';
      const description = $(cells[1]).text().trim();
      const products = $(cells[2]).text().trim();
      const severity = $(cells[3]).text().trim().toUpperCase() || 'UNKNOWN';
      const publishDate = $(cells[4]).text().trim();

      // Extract CVE IDs from description
      const cveMatches = description.match(/CVE-\d{4}-\d{4,}/g) || [];
      
      for (const cveId of cveMatches) {
        cves.push({
          id: cveId,
          description: `[${products}] ${description}`,
          severity,
          published: new Date(publishDate).toISOString(),
          source: 'VMWARE',
          metadata: {
            advisoryId,
            advisoryUrl: updateLink,
            affectedProducts: products.split(',').map(p => p.trim()),
            type: 'VMware Security Advisory',
            vendor: 'VMware'
          }
        });
      }
    });

    return cves;
  } catch (error) {
    console.error('Error fetching VMware advisories:', error);
    return [];
  }
}
