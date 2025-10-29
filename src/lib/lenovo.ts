import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const LENOVO_PSIRT_URL = 'https://support.lenovo.com/us/en/product_security/ps';

import * as cheerio from 'cheerio';

export async function fetchThinkpadCVEs(query: string = ''): Promise<any[]> {
  try {
    const response = await fetch('https://support.lenovo.com/us/en/solutions/len-24692');
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const html = await response.text();

    const $ = cheerio.load(html);

    // Find all advisory entries that mention ThinkPad
    const $ = cheerio.load(html);

    const advisories = $('table tr')
      .map((_, row) => {
        const text = $(row).text().toLowerCase();
        if (!text.includes(query.toLowerCase())) return null;
        
        const cells = $(row).find('td');
        return {
          id: $(cells[0]).text().trim() || '',
          description: $(cells[1]).text().trim() || '',
          severity: $(cells[2]).text().trim() || 'UNKNOWN',
          published: new Date().toISOString(), // Using current date as fallback
          source: 'LENOVO'
        };

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