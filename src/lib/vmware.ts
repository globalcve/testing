import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const VMWARE_ADVISORY_URL = 'https://www.vmware.com/security/advisories.html';

export async function fetchVMwareAdvisories(): Promise<CVE[]> {
  try {
    const response = await fetch(VMWARE_ADVISORY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch VMware advisories: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const advisoryRows = doc.querySelectorAll('table tr');

    for (const row of Array.from(advisoryRows)) {
      const cells = row.querySelectorAll('td');
      if (cells.length < 5) continue;

      const advisoryId = cells[0].textContent?.trim() || '';
      const updateLink = cells[0].querySelector('a')?.href || '';
      const description = cells[1].textContent?.trim() || '';
      const products = cells[2].textContent?.trim() || '';
      const severity = cells[3].textContent?.trim().toUpperCase() || 'UNKNOWN';
      const publishDate = cells[4].textContent?.trim() || '';

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
    }

    return cves;
  } catch (error) {
    console.error('Error fetching VMware advisories:', error);
    return [];
  }
}