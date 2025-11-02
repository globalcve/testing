import { CVE } from '@/types';
import * as cheerio from 'cheerio';

const UBUNTU_USN_URL = 'https://ubuntu.com/security/notices';

export async function fetchUbuntuCVEs(): Promise<CVE[]> {
  try {
    const response = await fetch(UBUNTU_USN_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Ubuntu Security Notices: ${response.statusText}`);
    }
    const html = await response.text();
    const $ = cheerio.load(html);

    const cves: CVE[] = [];
    const notices = $('.cve-notice');

    notices.each((_, notice) => {
      const title = $(notice).find('.p-notification__title').text().trim() || '';
      const published = $(notice).find('.p-notification__date').text().trim() || '';
      const description = $(notice).find('.p-notification__description').text().trim() || '';
      const cveElements = $(notice).find('.cve-reference');

      // Extract affected packages
      const packageMatch = title.match(/\((.*?)\)/);
      const affectedPackage = packageMatch ? packageMatch[1] : '';

      cveElements.each((_, cveElement) => {
        const cveId = $(cveElement).text().trim();
        if (!cveId.startsWith('CVE-')) return;

        cves.push({
          id: cveId,
          description: `[Ubuntu ${affectedPackage}] ${description}`,
          severity: determineSeverity($(notice)),
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
      });
    });

    return cves;
  } catch (error) {
    console.error('Error fetching Ubuntu Security Notices:', error);
    return [];
  }
}

function determineSeverity(element: cheerio.Cheerio<cheerio.AnyNode>): string {
  const priority = element.find('.p-notification__priority').text().toLowerCase().trim() || '';
  
  switch (priority) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH';
    case 'medium': return 'MEDIUM';
    case 'low': return 'LOW';
    default: return 'UNKNOWN';
  }
}
