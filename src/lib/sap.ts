import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const SAP_SECURITY_URL = 'https://support.sap.com/security';

export async function fetchSAPNotes(): Promise<CVE[]> {
  try {
    const response = await fetch(SAP_SECURITY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch SAP Security Notes: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const notes = doc.querySelectorAll('.security-note');

    for (const note of Array.from(notes)) {
      const noteId = note.querySelector('.note-id')?.textContent?.trim() || '';
      const title = note.querySelector('.note-title')?.textContent?.trim() || '';
      const description = note.querySelector('.note-description')?.textContent?.trim() || '';
      const published = note.querySelector('.note-date')?.textContent?.trim() || '';
      const priority = note.querySelector('.note-priority')?.textContent?.trim() || '';
      
      // Extract CVE references
      const cveRefs = note.querySelectorAll('.cve-ref');
      const componentInfo = note.querySelector('.component')?.textContent?.trim() || '';

      for (const cveRef of Array.from(cveRefs)) {
        const cveId = cveRef.textContent?.trim() || '';
        if (!cveId.startsWith('CVE-')) continue;

        cves.push({
          id: cveId,
          description: `[SAP ${componentInfo}] ${description || title}`,
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
    }

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