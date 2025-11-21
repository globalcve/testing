import { NextResponse } from 'next/server';
import { fetchJVNFeed } from "@/lib/jvn";
import { fetchExploitDB } from "@/lib/exploitdb";
import { fetchKEV } from "@/lib/kev";
import { calculateStats } from "@/lib/stats";
import { fetchAndroidBulletin } from "@/lib/android";
import { fetchAppleAdvisories } from "@/lib/apple";
import { fetchCertFR } from "@/lib/certfr";
import { fetchThinkpadCVEs } from "@/lib/thinkpad";
import { fetchOracleCPUs } from "@/lib/oracle";
import { fetchVMwareAdvisories } from "@/lib/vmware";
import { fetchCiscoAdvisories } from "@/lib/cisco";
import { fetchRedHatCVEs } from "@/lib/redhat";
import { fetchUbuntuCVEs } from "@/lib/ubuntu";
import { fetchDebianCVEs } from "@/lib/debian";
import { fetchSAPNotes } from "@/lib/sap";

const NVD_API_KEY = process.env.NVD_API_KEY;

function inferSeverity(item: any): string {
  const score = item.cvss ?? item.cvssScore ?? item.cvssv3 ?? item.cvssv2;
  if (typeof score === 'number') {
    if (score >= 9) return 'CRITICAL';
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    if (score > 0) return 'LOW';
  }

  const label = item.severity?.toUpperCase?.();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(label)) return label;

  return 'UNKNOWN';
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const startDate = searchParams.get('startDate');
  const sortOrder = searchParams.get('sort') || 'newest';

  let startDateTime: number | null = null;
  if (startDate) {
    const date = new Date(startDate);
    if (!isNaN(date.getTime())) {
      startDateTime = date.getTime();
    }
  }

  const allResults: any[] = [];

  console.log('🔍 Latest CVEs API - Date filter:', startDate);

  // KEV enrichment
  let kevMap = new Map<string, boolean>();
  try {
    const kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    console.log('🚨 KEV entries loaded:', kevMap.size);
  } catch (err) {
    console.error('❌ KEV fetch error:', err);
  }

  // Fetch from NVD (recent CVEs, 5 pages)
  if (NVD_API_KEY) {
    for (let i = 0; i < 5; i++) {
      const startIndex = i * 100;
      try {
        const pageUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=${startIndex}`;
        const pageRes = await fetch(pageUrl, {
          headers: { 'apiKey': NVD_API_KEY },
        });
        
        if (!pageRes.ok) continue;

        const pageData = await pageRes.json();
        allResults.push(...(pageData.vulnerabilities || []).map((item: any) => ({
          id: item.cve.id,
          description: item.cve.descriptions?.[0]?.value || 'No description',
          severity: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
          published: item.cve.published || new Date().toISOString(),
          source: 'NVD',
          kev: kevMap.has(item.cve.id),
          metadata: {
            cvss: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore,
          }
        })));
      } catch (err) {
        console.error(`❌ NVD page ${i + 1} error:`, err);
      }
    }
  }

  // JVN Feed
  try {
    const jvnResults = await fetchJVNFeed();
    allResults.push(...jvnResults.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'JVN',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ JVN fetch error:', err);
  }

  // ExploitDB
  try {
    const exploitResults = await fetchExploitDB();
    allResults.push(...exploitResults.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'EXPLOITDB',
      kev: kevMap.has(item.id),
      metadata: { exploitAvailable: true }
    })));
  } catch (err) {
    console.error('❌ ExploitDB fetch error:', err);
  }

  // Android Security Bulletins
  try {
    const androidResults = await fetchAndroidBulletin();
    allResults.push(...androidResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'ANDROID',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Android fetch error:', err);
  }

  // Apple Advisories
  try {
    const appleResults = await fetchAppleAdvisories();
    allResults.push(...appleResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'APPLE',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Apple fetch error:', err);
  }

  // CERT-FR
  try {
    const certfrResults = await fetchCertFR();
    allResults.push(...certfrResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'CERT-FR',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ CERT-FR fetch error:', err);
  }

  // Cisco
  try {
    const ciscoResults = await fetchCiscoAdvisories();
    allResults.push(...ciscoResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'CISCO',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Cisco fetch error:', err);
  }

  // Red Hat
  try {
    const redhatResults = await fetchRedHatCVEs();
    allResults.push(...redhatResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'REDHAT',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Red Hat fetch error:', err);
  }

  // Ubuntu
  try {
    const ubuntuResults = await fetchUbuntuCVEs();
    allResults.push(...ubuntuResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'UBUNTU',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Ubuntu fetch error:', err);
  }

  // Debian
  try {
    const debianResults = await fetchDebianCVEs();
    allResults.push(...debianResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'DEBIAN',
      kev: kevMap.has(item.id),
    })));
  } catch (err) {
    console.error('❌ Debian fetch error:', err);
  }

  // Filter by date if provided
  let filtered = allResults;
  if (startDateTime) {
    filtered = allResults.filter(cve => {
      try {
        const cveDate = new Date(cve.published).getTime();
        return cveDate >= startDateTime;
      } catch {
        return false;
      }
    });
  }

  // Remove duplicates
  const uniqueResults = Array.from(
    new Map(filtered.map(item => [item.id, item])).values()
  );

  // Sort
  uniqueResults.sort((a, b) => {
    const dateA = new Date(a.published).getTime();
    const dateB = new Date(b.published).getTime();
    return sortOrder === 'newest' ? dateB - dateA : dateA - dateB;
  });

  // Calculate stats
  const stats = calculateStats(uniqueResults);

  console.log('✅ Latest CVEs API - Total results:', uniqueResults.length);

  return NextResponse.json({
    results: uniqueResults,
    stats,
    total: uniqueResults.length
  });
}
