/**
 * GitHub Security Advisory Parser
 * Uses GitHub GraphQL API
 */

const GITHUB_API = 'https://api.github.com/graphql';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

interface GitHubAdvisory {
  id: string;
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  published: string;
  ecosystem: string;
  package: string;
  cves: string[];
  references: string[];
}

/**
 * Fetches GitHub Security Advisories
 * Returns array of normalized vulnerability objects
 */
export async function fetchGitHubAdvisories(): Promise<any[]> {
  if (!GITHUB_TOKEN) {
    console.warn('⚠️ No GITHUB_TOKEN set, skipping GitHub advisories');
    return [];
  }

  const results: any[] = [];

  try {
    // GraphQL query for recent advisories
    const query = `
      query {
        securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
          nodes {
            ghsaId
            summary
            description
            severity
            publishedAt
            withdrawnAt
            references {
              url
            }
            identifiers {
              type
              value
            }
            vulnerabilities(first: 5) {
              nodes {
                package {
                  ecosystem
                  name
                }
              }
            }
          }
        }
      }
    `;

    const res = await fetch(GITHUB_API, {
      method: 'POST',
      headers: {
        'Authorization': `bearer ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query })
    });

    if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);

    const data = await res.json();
    const advisories = data.data?.securityAdvisories?.nodes || [];

    for (const advisory of advisories) {
      // Skip withdrawn advisories
      if (advisory.withdrawnAt) continue;

      // Extract CVEs
      const cves = advisory.identifiers
        ?.filter((id: any) => id.type === 'CVE')
        .map((id: any) => id.value) || [];

      // Get affected packages
      const packages = advisory.vulnerabilities?.nodes
        ?.map((v: any) => ({
          ecosystem: v.package?.ecosystem,
          name: v.package?.name
        }))
        .filter((p: any) => p.name) || [];

      // Create entry for each CVE
      for (const cveId of cves) {
        results.push({
          id: cveId,
          description: advisory.description || advisory.summary,
          severity: mapGitHubSeverity(advisory.severity),
          published: advisory.publishedAt,
          source: 'GITHUB',
          metadata: {
            ghsaId: advisory.ghsaId,
            ecosystem: packages.map((p: any) => p.ecosystem).join(', '),
            package: packages.map((p: any) => p.name).join(', '),
            references: advisory.references?.map((r: any) => r.url) || []
          }
        });
      }
    }

    console.log('🐱 GitHub CVEs loaded:', results.length);
    return results;

  } catch (err) {
    console.error('❌ GitHub advisory fetch error:', err);
    return [];
  }
}

function mapGitHubSeverity(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MODERATE':
      return 'MEDIUM';
    case 'LOW':
      return 'LOW';
    default:
      return 'UNKNOWN';
  }
}