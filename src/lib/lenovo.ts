import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const LENOVO_PSIRT_URL = 'https://support.lenovo.com/us/en/product_security/ps';

export async function fetchThinkpadCVEs(): Promise<CVE[]> {
  try {
    const response = await fetch(LENOVO_PSIRT_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Lenovo PSIRT: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    // Find all advisory entries that mention ThinkPad
    const advisories = Array.from(doc.querySelectorAll('table tr'))
      .filter((row): row is HTMLTableRowElement => {
        const text = row.textContent?.toLowerCase() || '';
        return text.includes('thinkpad');
      });

    const cves: CVE[] = [];

    for (const advisory of advisories) {
      const cells = Array.from(advisory.getElementsByTagName('td'));
      if (cells.length < 4) continue;

      const id = cells[0].textContent?.trim() || '';
      const description = cells[1].textContent?.trim() || '';
      const severity = cells[2].textContent?.trim().toUpperCase() || 'UNKNOWN';
      const published = cells[3].textContent?.trim() || new Date().toISOString();

      // Get affected ThinkPad models
      const affectedModels = description.match(/ThinkPad\s+[A-Za-z0-9]+/g) || [];

      cves.push({
        id,
        description,
        severity,
        published,
        source: 'LENOVO.THINKPAD',
        metadata: {
          affectedModels: [...new Set(affectedModels)], // Remove duplicates
          advisoryUrl: LENOVO_PSIRT_URL,
          type: 'ThinkPad',
          vendor: 'Lenovo'
        }
      });
    }

    return cves;
  } catch (error) {
    console.error('Error fetching Lenovo ThinkPad CVEs:', error);
    return [];
  }
}