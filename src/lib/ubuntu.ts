import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const UBUNTU_USN_URL = 'https://ubuntu.com/security/notices/';

export async function fetchUbuntuCVEs(): Promise<CVE[]> {
  try {
    const response = await fetch(UBUNTU_USN_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Ubuntu Security Notices: ${response.statusText}`);
    }
    
    const html = await response.text();
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const notices = doc.querySelectorAll('.cve-notice');

    for (const notice of Array.from(notices)) {
      const titleElement = notice.querySelector('.p-notification__title');
      const dateElement = notice.querySelector('.p-notification__date');
      const descriptionElement = notice.querySelector('.p-notification__description');
      const cveElements = notice.querySelectorAll('.cve-reference');

      const title = titleElement?.textContent?.trim() || '';
      const published = dateElement?.textContent?.trim() || '';
      const description = descriptionElement?.textContent?.trim() || '';

      // Extract affected packages
      const packageMatch = title.match(/\((.*?)\)/);
      const affectedPackage = packageMatch ? packageMatch[1] : '';

      for (const cveElement of Array.from(cveElements)) {
        const cveId = cveElement.textContent?.trim() || '';
        if (!cveId.startsWith('CVE-')) continue;

        cves.push({
          id: cveId,
          description: `[Ubuntu ${affectedPackage}] ${description}`,
          severity: determineSeverity(notice),
          published: new Date(published).toISOString(),
          source: 'UBUNTU',
          metadata: {
            affectedPackage,
            usnUrl: UBUNTU_USN_URL,
            type: 'Ubuntu Security Notice',
            vendor: 'Ubuntu',
            releasePackages: title.split(',').map(p => p.trim())
          }
        });
      }
    }

    return cves;
  } catch (error) {
    console.error('Error fetching Ubuntu Security Notices:', error);
    return [];
  }
}

function determineSeverity(element: Element): string {
  const priorityElement = element.querySelector('.p-notification__priority');
  const priority = priorityElement?.textContent?.toLowerCase().trim() || '';
  
  switch (priority) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH';
    case 'medium': return 'MEDIUM';
    case 'low': return 'LOW';
    default: return 'UNKNOWN';
  }
}