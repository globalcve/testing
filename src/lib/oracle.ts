import { CVE } from '@/types';
// import { JSDOM } from 'jsdom'; // Using cheerio instead

const ORACLE_CPU_URL = 'https://www.oracle.com/security-alerts/';

import * as cheerio from 'cheerio';

export async function fetchOracleCPUs(query: string = '' ): Promise<any[]> {
  try {
    const response = await fetch('https://www.oracle.com/security-alerts/cpujan2024.html' );
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const html = await response.text();

    const $ = cheerio.load(html);

    const cves: CVE[] = [];

    // Find all tables that contain CVE data (assuming they are the main tables)
    $('table').each((_, table) => {
      $(table).find('tr').each((_, row) => {
        const cells = $(row).find('td');
        if (cells.length < 4) return;

        const id = $(cells[0]).text().trim();
        if (!id.startsWith('CVE-')) return;

        const description = $(cells[1]).text().trim();
        const component = $(cells[2]).text().trim();
        const baseScore = $(cells[3]).text().trim();
        const versionInfo = $(cells[4]).text().trim();

        if (id.toLowerCase().includes(query.toLowerCase()) || description.toLowerCase().includes(query.toLowerCase())) {
          cves.push({
            id,
            description: `[${component}] ${description}`,
            severity: inferSeverityFromCVSS(parseFloat(baseScore)),
            published: new Date().toISOString(), // CPU release date
            source: 'ORACLE.CPU',
            metadata: {
              product: component,
              cvssBaseScore: baseScore,
              affectedVersions: versionInfo,
              type: 'Oracle CPU',
              vendor: 'Oracle',
              cpuUrl: ORACLE_CPU_URL
            }
          });
        }
      });
    });

    return cves;
  } catch (error) {
    console.error('Error fetching Oracle CPUs:', error);
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
