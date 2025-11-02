import { CVE } from '@/types';

const DEBIAN_SECURITY_URL = 'https://security-tracker.debian.org/tracker/data/json';

interface DebianRelease {
  status: string;
  fixed_version?: string;
  urgency?: string;
}

interface DebianVulnerability {
  description?: string;
  releases?: Record<string, DebianRelease>;
  urgency?: string;
}

type DebianData = Record<string, Record<string, DebianVulnerability>>;

export async function fetchDebianCVEs( ): Promise<CVE[]> {
  try {
    const response = await fetch(DEBIAN_SECURITY_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch Debian Security Tracker: ${response.statusText}`);
    }
    
    const data = await response.json() as DebianData;
    const cves: CVE[] = [];

    for (const [packageName, vulnerabilities] of Object.entries(data)) {
      for (const [cveId, info] of Object.entries(vulnerabilities)) {
        if (!cveId.startsWith('CVE-')) continue;

        const description = info.description || `Security issue in ${packageName}`;
        const severity = mapDebianUrgency(info.urgency || '');
        
        // Get affected versions
        const releases = info.releases || {};
        const affectedVersions = Object.entries(releases)
          .filter(([_, release]) => release.status === 'vulnerable')
          .map(([version]) => version);

        // Get fixed versions if available
        const fixedVersions = Object.entries(releases)
          .filter(([_, release]) => release.fixed_version)
          .map(([dist, release]) => `${dist}: ${release.fixed_version}`);

        cves.push({
          id: cveId,
          description: `[Debian ${packageName}] ${description}`,
          severity,
          published: new Date().toISOString(), // Debian doesn't provide dates in the JSON
          source: 'DEBIAN',
          metadata: {
            package: packageName,
            affectedVersions,
            fixedVersions,
            type: 'Debian Security Tracker',
            vendor: 'Debian',
            trackerUrl: `${DEBIAN_SECURITY_URL}#${cveId}`,
            releases: Object.fromEntries(
              Object.entries(releases).map(([dist, rel]) => [
                dist,
                {
                  status: rel.status,
                  fixedVersion: rel.fixed_version,
                  urgency: rel.urgency
                }
              ])
            )
          }
        });
      }
    }

    return cves;
  } catch (error) {
    console.error('Error fetching Debian Security Tracker:', error);
    return [];
  }
}

function mapDebianUrgency(urgency: string): string {
  switch (urgency.toLowerCase()) {
    case 'high': return 'CRITICAL';
    case 'medium': return 'HIGH';
    case 'low': return 'MEDIUM';
    case 'unimportant': return 'LOW';
    default: return 'UNKNOWN';
  }
}
