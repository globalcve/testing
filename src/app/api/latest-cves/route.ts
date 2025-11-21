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
  console.log('🔍 Latest CVEs API - Using sources that support browse mode');

// Add KEV as source
    const kevCVEs = kevList.map(item => ({
      id: item.cveID,
      description: item.vulnerabilityName || 'Known exploited vulnerability',
      severity: 'CRITICAL',
      published: item.dateAdded,
      source: 'KEV',
      kev: true,
    }));

  // 2. NVD - Use pubStartDate (no query needed)
  if (NVD_API_KEY) {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 120);
      
      const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate.toISOString()}&resultsPerPage=2000`;
      
      const nvdRes = await fetch(nvdUrl, {
        headers: { 'apiKey': NVD_API_KEY }
      });

      if (nvdRes.ok) {
        const nvdData = await nvdRes.json();
        const nvdCVEs = (nvdData.vulnerabilities || []).map((item: any) => ({
          id: item.cve.id,
          description: item.cve.descriptions?.[0]?.value || 'No description',
          severity: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
          published: item.cve.published,
          source: 'NVD',
          kev: kevMap.has(item.cve.id),
          metadata: {
            cvss: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
          }
        }));
        allResults.push(...nvdCVEs);
        console.log('✅ NVD CVEs:', nvdCVEs.length);
      }
    } catch (err) {
      console.error('❌ NVD error:', err);
    }
  }

  // 3. JVN - RSS feed returns all
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
    console.log('✅ JVN CVEs:', jvnCVEs.length);
  } catch (err) {
    console.error('❌ JVN error:', err);
  }

  console.log('📊 Total CVEs:', allResults.length);
  console.log('ℹ️ Note: Other sources require search queries and are only available via home page search');

  // Remove duplicates
  const uniqueResults = Array.from(
    new Map(allResults.map(item => [item.id, item])).values()
  );

  // Sort
  uniqueResults.sort((a, b) => {
    const dateA = new Date(a.published || 0).getTime();
    const dateB = new Date(b.published || 0).getTime();
    return sortOrder === 'newest' ? dateB - dateA : dateA - dateB;
  });

  const stats = calculateStats(uniqueResults);

  return NextResponse.json({
    results: uniqueResults,
    stats,
    total: uniqueResults.length
  });
}
