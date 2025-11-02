import { CVE } from '@/types';
// import { JSDOM } from 'jsdom'; // Using regex for XML parsing

const REDHAT_OVAL_URL = 'https://www.redhat.com/security/data/oval/v2/RHEL8/';

export async function fetchRedHatCVEs( ): Promise<CVE[]> {
  try {
    const response = await fetch(REDHAT_OVAL_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch RedHat CVEs: ${response.statusText}`);
    }
    
    const xml = await response.text();

    const cves: CVE[] = [];
    
    // Simple regex to extract definition blocks
    const definitionMatches = xml.matchAll(/<definition[\s\S]*?<\/definition>/g);

    for (const defMatch of Array.from(definitionMatches)) {
      const def = defMatch[0];

      // Extract metadata
      const title = def.match(/<title>([\s\S]*?)<\/title>/)?.[1]?.trim() || '';
      const description = def.match(/<description>([\s\S]*?)<\/description>/)?.[1]?.trim() || '';
      const severity = def.match(/<severity>([\s\S]*?)<\/severity>/)?.[1]?.trim().toUpperCase() || 'UNKNOWN';
      const issued = def.match(/<issued date="([\s\S]*?)"/)?.[1]?.trim() || '';
      
      // Extract CVE IDs
      const cveRefMatches = def.matchAll(/<reference source="CVE" ref_id="([\s\S]*?)"/g);
      const cveIds = Array.from(cveRefMatches).map(m => m[1]).filter(id => id.startsWith('CVE-'));

      // Extract affected packages (simplified)
      const affectedPackages = Array.from(def.matchAll(/<rpm name="([\s\S]*?)"/g)).map(m => m[1]);

      for (const cveId of cveIds) {
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
