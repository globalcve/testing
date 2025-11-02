import { CVE } from '@/types';
import * as cheerio from 'cheerio';

const SAP_SECURITY_URL = 'https://support.sap.com/security';

export async function fetchSAPNotes( ): Promise<CVE[]> {
  try {
    const response = await fetch(SAP_SECURITY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch SAP Security Notes: ${response.statusText}`);
    }
    
    const html = await response.text();
    const $ = cheerio.load(html);

    const cves: CVE[] = [];
    
    // Target the table rows that contain the security notes.
    // This is a guess based on common SAP security page structure.
    $('table.security-notes-table tr').each((_, row) => {
      const cells = $(row).find('td');
      if (cells.length < 5) return;

      const noteId = $(cells[0]).text().trim();
      const title = $(cells[1]).text().trim();
      const published = $(cells[2]).text().trim();
      const priority = $(cells[3]).text().trim();
      const cveIdText = $(cells[4]).text().trim();

      // Extract CVE references
      const cveMatches = cveIdText.match(/CVE-\d{4}-\d{4,}/g) || [];
      const componentInfo = $(cells[5]).text().trim();

      for (const cveId of cveMatches) {
        cves.push({
          id: cveId,
          description: `[SAP ${componentInfo}] ${title}`,
          severity: mapSAPPriority(priority),
          published: new Date(published).toISOString(),
          source: 'SAP',
          metadata: {
            noteId,
            component: componentInfo,
            type: 'SAP Security Note',
            vendor: 'SAP',
            noteUrl: `${SAP_SECURITY_URL}/${noteId}`,
            priority
          }
        });
      }
    });

    return cves;
  } catch (error) {
    console.error('Error fetching SAP Security Notes:', error);
    return [];
  }
}

function mapSAPPriority(priority: string): string {
  switch (priority.toLowerCase()) {
    case 'hot news': return 'CRITICAL';
    case 'high priority': return 'HIGH';
    case 'medium priority': return 'MEDIUM';
    case 'low priority': return 'LOW';
    default: return 'UNKNOWN';
  }
}
