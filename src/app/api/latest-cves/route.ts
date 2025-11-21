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

  // KEV - Fetch as BOTH enrichment AND source
  let kevMap = new Map<string, boolean>();
  let kevList: any[] = [];
  try {
    kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    
    // Add KEV entries as their own source
// KEV - Fetch as BOTH enrichment AND source
  let kevMap = new Map<string, boolean>();
  let kevList: any[] = [];
  try {
    kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    
    // DON'T add KEV as separate source - they're already in other sources
    // Just use for enrichment
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

  
 // 🔹 CIRCL - Get recent CVEs
  try {
    const circlUrl = `https://cve.circl.lu/api/last/100`; // Get more results
    const circlRes = await fetch(circlUrl);
    
    if (circlRes.ok) {
      const circlData = await circlRes.json();
      const items = Array.isArray(circlData) ? circlData : [circlData];
      
      const circlCVEs = items
        .filter((item: any) => item.id) // Must have ID
        .map((item: any) => {
          const id = item.id || item.cveMetadata?.cveId;
          const description = item.summary?.trim() || 
                            item.vulnerable_configuration_cpe_2_2?.[0] ||
                            item.vulnerable_product?.[0] ||
                            'No description available';
          
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
      console.log('✅ CIRCL CVEs fetched:', circlCVEs.length);
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

  // Disabled sources (too slow or return 0 results)
  console.log('⏭️ Skipping: ExploitDB (30k+ entries)');
  console.log('⏭️ Skipping: Android (slow, 0 results)');
  console.log('⏭️ Skipping: Apple (0 results)');
  console.log('⏭️ Skipping: CERT-FR (0 results)');
  console.log('⏭️ Skipping: Cisco (0 results)');
  console.log('⏭️ Skipping: VMware (0 results)');
  console.log('⏭️ Skipping: Oracle (0 results)');
  console.log('⏭️ Skipping: Red Hat (0 results)');
  console.log('⏭️ Skipping: Ubuntu (0 results)');
  console.log('⏭️ Skipping: Debian (53k+ entries)');
  console.log('⏭️ Skipping: SAP (0 results)');
  console.log('⏭️ Skipping: ThinkPad (0 results)');

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
