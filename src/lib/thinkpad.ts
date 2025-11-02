import { CVE } from '@/types';
// import { JSDOM } from 'jsdom'; // Not needed if using cheerio

const LENOVO_PSIRT_URL = 'https://support.lenovo.com/us/en/product_security/ps';

import * as cheerio from 'cheerio';

export async function fetchThinkpadCVEs(query: string = '' ): Promise<CVE[]> {
  try {
    const response = await fetch('https://support.lenovo.com/us/en/solutions/len-24692' );
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const html = await response.text();


    
    // Find all advisory entries that mention ThinkPad


    const advisories: CVE[] = [];

    // Assuming the relevant data is in a table, we'll iterate over rows
    // This is a placeholder logic as the actual structure of the Lenovo page is unknown
    // and the original code was clearly broken.
    $('table.data-table tr').each((_, row) => {
      const cells = $(row).find('td');
      if (cells.length < 4) return;

      const id = $(cells[0]).text().trim();
      const description = $(cells[1]).text().trim();
      const severity = $(cells[2]).text().trim().toUpperCase();
      const published = $(cells[3]).text().trim() || new Date().toISOString();

      if (id.startsWith('CVE-') && description.toLowerCase().includes(query.toLowerCase())) {
        advisories.push({
          id,
          description,
          severity,
          published,
          source: 'LENOVO.THINKPAD',
          metadata: {
            advisoryUrl: LENOVO_PSIRT_URL,
            type: 'ThinkPad',
            vendor: 'Lenovo'
          }
        });
      }
    });

    return advisories;
  } catch (error) {
    console.error('Error fetching Lenovo ThinkPad CVEs:', error);
    return [];
  }
}
