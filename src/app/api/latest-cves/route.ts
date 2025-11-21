import { NextResponse } from 'next/server';
import { fetchJVNFeed } from "@/lib/jvn";
import { fetchKEV } from "@/lib/kev";
import { calculateStats } from "@/lib/stats";

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
  const sortOrder = searchParams.get('sort') || 'newest';

  const allResults: any[] = [];
  console.log('🔍 Latest CVEs API - Fetching from optimized sources');

  // KEV - Fetch for enrichment only
  let kevMap = new Map<string, boolean>();
  try {
    const kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    console.log('🚨 KEV entries loaded for enrichment:', kevMap.size);
  } catch (err) {
    console.error('❌ KEV fetch error:', err);
  }

  // 🔹 NVD - Use pubStartDate for recent CVEs
  if (NVD_API_KEY) {
    try {
      const nvdStartDate = new Date();
      nvdStartDate.setDate(nvdStartDate.getDate() - 120);
      const nvdStartDateStr = nvdStartDate.toISOString();

      const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${nvdStartDateStr}&resultsPerPage=2000`;
      console.log('🌐 NVD URL:', nvdUrl);

      const nvdRes = await fetch(nvdUrl, {
        headers: { 'apiKey': NVD_API_KEY },
      });

      if (nvdRes.ok) {
        const nvdData = await nvdRes.json();
        const nvdCVEs = (nvdData.vulnerabilities || []).map((item: any) => ({
          id: item.cve.id,
          description: item.cve.descriptions?.[0]?.value || 'No description',
          severity: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
          published: item.cve.published || new Date().toISOString(),
          source: 'NVD',
          kev: kevMap.has(item.cve.id),
          metadata: {
            cvss: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore,
          }
        }));
        allResults.push(...nvdCVEs);
        console.log('✅ NVD CVEs fetched:', nvdCVEs.length);
      } else {
        console.error('❌ NVD fetch failed:', nvdRes.status);
      }
    } catch (err) {
      console.error('❌ NVD error:', err);
    }
  } else {
    console.warn('⚠️ NVD_API_KEY not configured');
  }

// 🔹 CIRCL - Get recent CVEs (skip GHSA)
  try {
    const circlUrl = `https://cve.circl.lu/api/last/100`;
    const circlRes = await fetch(circlUrl);
    
    if (circlRes.ok) {
      const circlData = await circlRes.json();
      const items = Array.isArray(circlData) ? circlData : [circlData];
      
      const circlCVEs = items
        .filter((item: any) => {
          const id = item.id || item.cveMetadata?.cveId;
          // Only accept CVE-* IDs, skip GHSA-*
          return id && id.startsWith('CVE-');
        })
        .map((item: any) => {
          const id = item.id || item.cveMetadata?.cveId;
          
          // Try multiple description fields
          let description = 'No description available';
          if (item.summary?.trim()) {
            description = item.summary.trim();
          } else if (item.description?.trim()) {
            description = item.description.trim();
          } else if (item.containers?.cna?.descriptions?.[0]?.value) {
            description = item.containers.cna.descriptions[0].value;
          }
          
          return {
            id,
            description,
            severity: inferSeverity(item),
            published: item.Published || item.Modified || new Date().toISOString(),
            source: 'CIRCL',
            kev: kevMap.has(id),
          };
        });

      allResults.push(...circlCVEs);
      console.log('✅ CIRCL CVEs fetched (filtered GHSA):', circlCVEs.length);
    }
  } catch (err) {
    console.error('❌ CIRCL error:', err);
  }

  // 🔹 JVN Feed
  try {
    const jvnResults = await fetchJVNFeed();
    const jvnCVEs = jvnResults.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'JVN',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...jvnCVEs);
    console.log('✅ JVN CVEs fetched:', jvnCVEs.length);
  } catch (err) {
    console.error('❌ JVN error:', err);
  }

  // Disabled sources
  console.log('⏭️ Skipping: ExploitDB, Android, Apple, CERT-FR, Cisco, VMware, Oracle, Red Hat, Ubuntu, Debian, SAP, ThinkPad');

  console.log('📊 Total CVEs:', allResults.length);

  // Remove duplicates by ID
  const uniqueResults = Array.from(
    new Map(allResults.map(item => [item.id, item])).values()
  );
  console.log('📊 CVEs after deduplication:', uniqueResults.length);

  // Sort
  uniqueResults.sort((a, b) => {
    const dateA = new Date(a.published || 0).getTime();
    const dateB = new Date(b.published || 0).getTime();
    return sortOrder === 'newest' ? dateB - dateA : dateA - dateB;
  });

  // Calculate stats
  const stats = calculateStats(uniqueResults);

  console.log('✅ Latest CVEs API complete - Returning:', uniqueResults.length, 'CVEs');

  return NextResponse.json({
    results: uniqueResults,
    stats,
    total: uniqueResults.length
  });
}
