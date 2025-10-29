import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const ORACLE_CPU_URL = 'https://www.oracle.com/security-alerts/';

export async function fetchOracleCPUs(): Promise<CVE[]> {
  try {
    const response = await fetch(ORACLE_CPU_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Oracle CPUs: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const cpuTables = Array.from(doc.getElementsByTagName('table'));

    for (const table of Array.from(cpuTables)) {
      const rows = table.querySelectorAll('tr');
      
      for (const row of Array.from(rows)) {
        const cells = row.querySelectorAll('td');
        if (cells.length < 4) continue;

        const id = cells[0].textContent?.trim() || '';
        if (!id.startsWith('CVE-')) continue;

        const description = cells[1].textContent?.trim() || '';
        const component = cells[2].textContent?.trim() || '';
        const baseScore = cells[3].textContent?.trim() || '';

        // Extract version information if available
        const versionInfo = cells[4]?.textContent?.trim() || '';

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
    }

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