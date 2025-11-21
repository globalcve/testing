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
  console.log('🔍 Latest CVEs API - Fetching from all sources');
  console.log('📅 Date filter:', startDate);

  // KEV enrichment
// KEV - Fetch as BOTH enrichment AND source
  let kevMap = new Map<string, boolean>();
  let kevList: any[] = [];
  try {
    kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    
    // Add KEV entries as their own source
    const kevCVEs = kevList.map(item => ({
      id: item.cveID,
      description: item.vulnerabilityName || item.shortDescription || 'KEV-listed vulnerability',
      severity: 'CRITICAL', // KEV are actively exploited
      published: item.dateAdded || new Date().toISOString(),
      source: 'KEV',
      kev: true,
      metadata: {
        vendorProject: item.vendorProject,
        product: item.product,
        requiredAction: item.requiredAction,
        dueDate: item.dueDate
      }
    }));
    
    allResults.push(...kevCVEs);
    console.log('🚨 KEV entries loaded:', kevMap.size);
    console.log('✅ KEV CVEs fetched:', kevCVEs.length);
  } catch (err) {
    console.error('❌ KEV fetch error:', err);
  }

  // 🔹 NVD - Use pubStartDate for recent CVEs
  if (NVD_API_KEY) {
    try {
      // Calculate date for NVD pubStartDate (last 120 days to get enough results)
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
    const circlUrl = `https://cve.circl.lu/api/last`;
    const circlRes = await fetch(circlUrl);
    
    if (circlRes.ok) {
      const circlData = await circlRes.json();
      const items = Array.isArray(circlData) ? circlData : [circlData];
      
      const circlCVEs = items.map((item: any) => ({
        id: item.id || item.cveMetadata?.cveId,
        description: item.summary || item?.containers?.cna?.descriptions?.[0]?.value || 'No description',
        severity: inferSeverity(item),
        published: item.Published || new Date().toISOString(),
        source: 'CIRCL',
        kev: kevMap.has(item.id || item.cveMetadata?.cveId),
      })).filter((cve: any) => cve.id);

      allResults.push(...circlCVEs);
      console.log('✅ CIRCL CVEs fetched:', circlCVEs.length);
    }
  } catch (err) {
    console.error('❌ CIRCL error:', err);
  }

  // 🔹 JVN Feed - Get ALL, filter by date later
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

  // 🔹 ExploitDB
  try {
    const exploitResults = await fetchExploitDB();
    const exploitCVEs = exploitResults.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'EXPLOITDB',
      kev: kevMap.has(item.id),
      metadata: { exploitAvailable: true }
    }));
    allResults.push(...exploitCVEs);
    console.log('✅ ExploitDB CVEs fetched:', exploitCVEs.length);
  } catch (err) {
    console.error('❌ ExploitDB error:', err);
  }

  // 🔹 Android Security Bulletins
  try {
    const androidResults = await fetchAndroidBulletin();
    const androidCVEs = androidResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'ANDROID',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...androidCVEs);
    console.log('✅ Android CVEs fetched:', androidCVEs.length);
  } catch (err) {
    console.error('❌ Android error:', err);
  }

  // 🔹 Apple Advisories
  try {
    const appleResults = await fetchAppleAdvisories();
    const appleCVEs = appleResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'APPLE',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...appleCVEs);
    console.log('✅ Apple CVEs fetched:', appleCVEs.length);
  } catch (err) {
    console.error('❌ Apple error:', err);
  }

  // 🔹 CERT-FR
  try {
    const certfrResults = await fetchCertFR();
    const certfrCVEs = certfrResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'CERT-FR',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...certfrCVEs);
    console.log('✅ CERT-FR CVEs fetched:', certfrCVEs.length);
  } catch (err) {
    console.error('❌ CERT-FR error:', err);
  }

  // 🔹 Cisco
  try {
    const ciscoResults = await fetchCiscoAdvisories();
    const ciscoCVEs = ciscoResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'CISCO',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...ciscoCVEs);
    console.log('✅ Cisco CVEs fetched:', ciscoCVEs.length);
  } catch (err) {
    console.error('❌ Cisco error:', err);
  }

  // 🔹 VMware
  try {
    const vmwareResults = await fetchVMwareAdvisories();
    const vmwareCVEs = vmwareResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'VMWARE',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...vmwareCVEs);
    console.log('✅ VMware CVEs fetched:', vmwareCVEs.length);
  } catch (err) {
    console.error('❌ VMware error:', err);
  }

  // 🔹 Oracle
  try {
    const oracleResults = await fetchOracleCPUs();
    const oracleCVEs = oracleResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'ORACLE',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...oracleCVEs);
    console.log('✅ Oracle CVEs fetched:', oracleCVEs.length);
  } catch (err) {
    console.error('❌ Oracle error:', err);
  }

  // 🔹 Red Hat
  try {
    const redhatResults = await fetchRedHatCVEs();
    const redhatCVEs = redhatResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'REDHAT',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...redhatCVEs);
    console.log('✅ Red Hat CVEs fetched:', redhatCVEs.length);
  } catch (err) {
    console.error('❌ Red Hat error:', err);
  }

  // 🔹 Ubuntu
  try {
    const ubuntuResults = await fetchUbuntuCVEs();
    const ubuntuCVEs = ubuntuResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'UBUNTU',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...ubuntuCVEs);
    console.log('✅ Ubuntu CVEs fetched:', ubuntuCVEs.length);
  } catch (err) {
    console.error('❌ Ubuntu error:', err);
  }

  // 🔹 Debian
  try {
    const debianResults = await fetchDebianCVEs();
    const debianCVEs = debianResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'DEBIAN',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...debianCVEs);
    console.log('✅ Debian CVEs fetched:', debianCVEs.length);
  } catch (err) {
    console.error('❌ Debian error:', err);
  }

  // 🔹 SAP
  try {
    const sapResults = await fetchSAPNotes();
    const sapCVEs = sapResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'SAP',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...sapCVEs);
    console.log('✅ SAP CVEs fetched:', sapCVEs.length);
  } catch (err) {
    console.error('❌ SAP error:', err);
  }

  // 🔹 Lenovo ThinkPad
  try {
    const thinkpadResults = await fetchThinkpadCVEs();
    const thinkpadCVEs = thinkpadResults.map(item => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'LENOVO.THINKPAD',
      kev: kevMap.has(item.id),
    }));
    allResults.push(...thinkpadCVEs);
    console.log('✅ ThinkPad CVEs fetched:', thinkpadCVEs.length);
  } catch (err) {
    console.error('❌ ThinkPad error:', err);
  }

  console.log('📊 Total CVEs before filtering:', allResults.length);

// Filter by date if provided (but keep KEV regardless of date)
  let filtered = allResults;
  if (startDateTime) {
    filtered = allResults.filter(cve => {
      // Always include KEV source
      if (cve.source === 'KEV') return true;
      
      try {
        const cveDate = new Date(cve.published).getTime();
        return cveDate >= startDateTime;
      } catch {
        return false;
      }
    });
    console.log('📊 CVEs after date filter:', filtered.length);
  }

  // Remove duplicates by ID
  const uniqueResults = Array.from(
    new Map(filtered.map(item => [item.id, item])).values()
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
