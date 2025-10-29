import { CVE } from '@/types';
import { JSDOM } from 'jsdom';

const REDHAT_OVAL_URL = 'https://www.redhat.com/security/data/oval/v2/RHEL8/';

export async function fetchRedHatCVEs(): Promise<CVE[]> {
  try {
    const response = await fetch(REDHAT_OVAL_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch RedHat CVEs: ${response.statusText}`);
    }
    
    const xml = await response.text();
    const dom = new JSDOM(xml, { contentType: 'text/xml' });
    const doc = dom.window.document;

    const cves: CVE[] = [];
    const definitions = doc.querySelectorAll('definition');

    for (const def of Array.from(definitions)) {
      const metadata = def.querySelector('metadata');
      if (!metadata) continue;

      const title = metadata.querySelector('title')?.textContent || '';
      const description = metadata.querySelector('description')?.textContent || '';
      const severity = metadata.querySelector('severity')?.textContent?.toUpperCase() || 'UNKNOWN';
      const issued = metadata.querySelector('issued')?.getAttribute('date') || '';
      const cveRefs = metadata.querySelectorAll('reference[source="CVE"]');

      // Get affected packages
      const affectedPackages = Array.from(def.querySelectorAll('rpm'))
        .map(rpm => rpm.getAttribute('name'))
        .filter((name): name is string => name !== null);

      for (const cveRef of Array.from(cveRefs)) {
        const cveId = cveRef.getAttribute('ref_id');
        if (!cveId?.startsWith('CVE-')) continue;

        cves.push({
          id: cveId,
          description: `[RedHat] ${description || title}`,
          severity,
          published: new Date(issued).toISOString(),
          source: 'REDHAT',
          metadata: {
            affectedPackages,
            type: 'RedHat Security Data',
            vendor: 'RedHat',
            advisory: title,
            dataSource: REDHAT_OVAL_URL
          }
        });
      }
    }

    return cves;
  } catch (error) {
    console.error('Error fetching RedHat CVEs:', error);
    return [];
  }
}