import AdmZip from 'adm-zip';
import { Buffer } from 'buffer';
import { NextResponse } from 'next/server';
import { fetchJVNFeed } from "@/lib/jvn";
import { fetchExploitDB } from "@/lib/exploitdb";
import { fetchKEV, keywordMatchKEV } from "@/lib/kev";
import { parseAdvancedQuery, matchesQuery } from "@/lib/search";
import { calculateStats } from "@/lib/stats";
import { fetchCNNVD } from "@/lib/cnnvd"; // ✅ ADDED: CNNVD integration
import { fetchAndroidBulletin } from "@/lib/android"; // ✅ ADDED: Android Security Bulletin
import { fetchAppleAdvisories } from "@/lib/apple"; // ✅ ADDED: Apple Security Advisory
import { fetchCertFR } from "@/lib/certfr"; // ✅ ADDED: CERT-FR
import { fetchThinkpadCVEs } from "@/lib/lenovo"; // ✅ ADDED: Lenovo ThinkPad CVEs
import { fetchOracleCPUs } from "@/lib/oracle"; // ✅ ADDED: Oracle CPUs
import { fetchVMwareAdvisories } from "@/lib/vmware"; // ✅ ADDED: VMware Advisories
import { fetchCiscoAdvisories } from "@/lib/cisco"; // ✅ ADDED: Cisco Advisories
import { fetchRedHatCVEs } from "@/lib/redhat"; // ✅ ADDED: RedHat CVEs
import { fetchUbuntuCVEs } from "@/lib/ubuntu"; // ✅ ADDED: Ubuntu CVEs
import { fetchDebianCVEs } from "@/lib/debian"; // ✅ ADDED: Debian CVEs
import { fetchSAPNotes } from "@/lib/sap"; // ✅ ADDED: SAP Notes

const NVD_API_KEY = process.env.NVD_API_KEY;

function isString(field: unknown): field is string {
  return typeof field === 'string';
}

function isValidDate(date: unknown): date is string {
  return (
    typeof date === 'string' &&
    !isNaN(Date.parse(date)) &&
    new Date(date).getFullYear() <= 2025
  );
}

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
  const query = searchParams.get('query') || '';
  const severityFilter = searchParams.get('severity')?.toUpperCase();
  const sortOrder = searchParams.get('sort') || 'newest';
  const startDate = searchParams.get('startDate');
  const endDate = searchParams.get('endDate');
  const sourceFilter = searchParams.get('source')?.toUpperCase();
  const hasExploit = searchParams.get('hasExploit') === 'true';
  const isKev = searchParams.get('isKev') === 'true';
  const isExactCveId = /^CVE-\d{4}-\d{4,}$/.test(query);
  
  // Parse advanced search operators
  const searchTerms = parseAdvancedQuery(query);

  // Validate startDate if provided
  let startDateTime: number | null = null;
  if (startDate) {
    const date = new Date(startDate);
    if (!isNaN(date.getTime())) {
      startDateTime = date.getTime();
    }
  }

  const allResults: any[] = [];

  console.log('🔍 Query:', query);
  console.log('🔐 API key loaded:', !!NVD_API_KEY);
  console.log('⚠️ Severity filter:', severityFilter);
  console.log('🔎 Exact CVE ID match mode:', isExactCveId);
  console.log('📅 Sort order:', sortOrder);

  // 🔹 KEV enrichment (preload)
  let kevMap = new Map<string, boolean>();
  let kevKeywordMatches = new Set<string>();
  try {
    const kevList = await fetchKEV();
    kevMap = new Map(kevList.map(entry => [entry.cveID, true]));
    kevKeywordMatches = keywordMatchKEV(kevList, query); // ✅ PATCHED: keyword match set
    console.log('🚨 KEV entries loaded:', kevMap.size);
    console.log('🔎 KEV keyword matches:', kevKeywordMatches.size);
  } catch (err) {
    console.error('❌ KEV fetch error:', err);
  }

  // 🔹 Fetch from NVD (5 pages)
  for (let i = 0; i < 5; i++) {
    const startIndex = i * 100;
    const pageUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=100&startIndex=${startIndex}`;
    console.log(`🌐 NVD page ${i + 1}: ${pageUrl}`);

    try {
      const pageRes = await fetch(pageUrl, {
        headers: NVD_API_KEY ? { 'apiKey': NVD_API_KEY } : {},
      });
      console.log(`📡 NVD page ${i + 1} status: ${pageRes.status}`);
      if (!pageRes.ok) continue;

      const pageData = await pageRes.json();
      allResults.push(...(pageData.vulnerabilities || []).map((item: any) => ({
        id: item.cve.id,
        description: item.cve.descriptions?.[0]?.value || 'No description',
        severity: item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
        published: item.cve.published || new Date().toISOString(),
        source: 'NVD',
        kev: kevMap.has(item.cve.id) || kevKeywordMatches.has(item.cve.id), // ✅ PATCHED
        cwe: item.cve.weaknesses?.[0]?.description?.[0]?.value || null,
        cwes: item.cve.weaknesses?.map((w: any) => w.description?.[0]?.value).filter(Boolean) || [],
        references: item.cve.references?.map((ref: any) => ({
          url: ref.url,
          source: ref.source,
          tags: ref.tags || []
        })) || []
      })));
    } catch (err) {
      console.error(`❌ NVD page ${i + 1} error:`, err);
    }
  }
  // 🔹 CIRCL fallback — keyword or exact ID
  try {
    const circlUrl = isExactCveId
      ? `https://cve.circl.lu/api/cve/${encodeURIComponent(query)}`
      : `https://cve.circl.lu/api/search/${encodeURIComponent(query)}`;
    console.log(`🔁 CIRCL query: ${circlUrl}`);

    const circlRes = await fetch(circlUrl);
    console.log(`📡 CIRCL status: ${circlRes.status}`);

    if (circlRes.ok) {
      const data = await circlRes.json();
      const items = Array.isArray(data) ? data : [data];

      for (const item of items) {
        const rawDate = item.Published;
        const published = rawDate && !isNaN(Date.parse(rawDate)) ? rawDate : null;

        const description =
          item?.summary?.trim() ||
          item?.containers?.cna?.descriptions?.[0]?.value?.trim() ||
          'No description available from CIRCL.';

        const id = item.cveMetadata?.cveId || item.id;

        allResults.push({
          id,
          description,
          severity: inferSeverity(item),
          published,
          source: 'CIRCL',
          kev: kevMap.has(id) || kevKeywordMatches.has(id), // ✅ PATCHED
        });
      }

      console.log('🧩 CIRCL entries added:', items.length);
    }
  } catch (err) {
    console.error('❌ CIRCL error:', err);
  }

  // 🔹 JVN feed with manual keyword match (lint-cleaned)
  try {
    const jvnResults = await fetchJVNFeed();
    console.log('📰 JVN feed loaded:', jvnResults.length);

    const q = query.toLowerCase();
    const matchingJVNs = jvnResults.filter((item) =>
      [item.id, item.title, item.description, item.link]
        .filter(Boolean)
        .some((field) => isString(field) && field.toLowerCase().includes(q))
    );

    console.log('🔎 Matching JVN entries:', matchingJVNs.length);
    allResults.push(...matchingJVNs.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: item.published,
      source: 'JVN',
      kev: kevMap.has(item.id) || kevKeywordMatches.has(item.id), // ✅ PATCHED
    })));
  } catch (err) {
    console.error('❌ JVN fetch error:', err);
  }

  // 🔹 CNNVD integration with KEV enrichment
  try {
    const cnnvdResults = await fetchCNNVD(query);
    console.log('🇨🇳 CNNVD entries loaded:', cnnvdResults.length);
    
    allResults.push(...cnnvdResults.map(item => ({
      ...item,
      kev: kevMap.has(item.id) || kevKeywordMatches.has(item.id), // ✅ PATCHED: KEV enrichment
    })));
  } catch (err) {
    console.error('❌ CNNVD fetch error:', err);
  }

  // 🔹 ExploitDB with partial match
  let exploitResults = [];
  try {
    console.log('🧪 ExploitDB fallback active');
    exploitResults = await fetchExploitDB();
    console.log('💣 ExploitDB entries loaded:', exploitResults.length);
  } catch (err) {
    console.error('❌ ExploitDB fetch error:', err);
  }

  if (exploitResults.length > 0) {
    const q = query.toLowerCase();
    const matchingExploits = exploitResults.filter((item) =>
      [item.id, item.description, item.source, item.link]
        .filter(Boolean)
        .some((field) => isString(field) && field.toLowerCase().includes(q))
    );

    console.log('🔎 Matching ExploitDB entries:', matchingExploits.length);
    allResults.push(...matchingExploits.map((item) => ({
      id: item.id,
      description: item.description,
      severity: inferSeverity(item),
      published: isValidDate(item.date) ? item.date : "2000-01-01",
      source: 'EXPLOITDB',
      kev: kevMap.has(item.id) || kevKeywordMatches.has(item.id), // ✅ PATCHED
    })));
  }

  // 🔹 CVE.org GitHub release
  // 🔹 Additional advisory sources
  console.log('📱 Fetching vendor advisories...');
  
  // Android Security Bulletin
  try {
    const androidResults = await fetchAndroidBulletin();
    allResults.push(...androidResults);
  } catch (err) {
    console.error('❌ Android bulletin error:', err);
  }

  // Apple Security Advisory
  try {
    const appleResults = await fetchAppleAdvisories();
    allResults.push(...appleResults);
  } catch (err) {
    console.error('❌ Apple advisory error:', err);
  }

  // CERT-FR
  try {
    const certFrResults = await fetchCertFR();
    allResults.push(...certFrResults);
  } catch (err) {
    console.error('❌ CERT-FR error:', err);
  }

  // Lenovo ThinkPad CVEs
  try {
    const thinkpadResults = await fetchThinkpadCVEs();
    allResults.push(...thinkpadResults);
  } catch (err) {
    console.error('❌ Lenovo ThinkPad CVE error:', err);
  }

  // Oracle Critical Patch Updates
  try {
    const oracleCPUResults = await fetchOracleCPUs();
    allResults.push(...oracleCPUResults);
  } catch (err) {
    console.error('❌ Oracle CPU error:', err);
  }

  // VMware Security Advisories
  try {
    const vmwareResults = await fetchVMwareAdvisories();
    allResults.push(...vmwareResults);
  } catch (err) {
    console.error('❌ VMware advisory error:', err);
  }

  // Cisco Security Advisories
  try {
    const ciscoResults = await fetchCiscoAdvisories();
    allResults.push(...ciscoResults);
  } catch (err) {
    console.error('❌ Cisco advisory error:', err);
  }

  // RedHat Security Data
  try {
    const redhatResults = await fetchRedHatCVEs();
    allResults.push(...redhatResults);
  } catch (err) {
    console.error('❌ RedHat CVE error:', err);
  }

  // Ubuntu Security Notices
  try {
    const ubuntuResults = await fetchUbuntuCVEs();
    allResults.push(...ubuntuResults);
  } catch (err) {
    console.error('❌ Ubuntu CVE error:', err);
  }

  // Debian Security Tracker
  try {
    const debianResults = await fetchDebianCVEs();
    allResults.push(...debianResults);
  } catch (err) {
    console.error('❌ Debian CVE error:', err);
  }

  // SAP Security Notes
  try {
    const sapResults = await fetchSAPNotes();
    allResults.push(...sapResults);
  } catch (err) {
    console.error('❌ SAP Security Note error:', err);
  }

  // CVE.org data
  try {
    if (query.trim()) {
      const res = await fetch('https://github.com/globalcve/globalcve/releases/download/v1.0.0/cveorg.json');
      const cveorgData = await res.json();

      const q = query.toLowerCase();
      const matchingCveOrg = cveorgData.filter((item: any) =>
        [item.id, item.description]
          .filter(Boolean)
          .some((field) => isString(field) && field.toLowerCase().includes(q))
      );

      console.log('📁 Matching CVE.org entries:', matchingCveOrg.length);

      allResults.push(...matchingCveOrg.map((item: any) => ({
        id: item.id,
        description: item.description || 'No description available from CVE.org.',
        severity: inferSeverity(item),
        published: item.published || new Date().toISOString(),
        source: 'CVE.ORG',
        kev: kevMap.has(item.id) || kevKeywordMatches.has(item.id), // ✅ PATCHED
      })));
    }
  } catch (err) {
    console.error('❌ CVE.org fetch error:', err);
  }
  // 🔹 Archive ZIP with guard for missing year (patched)
  try {
    const yearMatch = !isExactCveId ? query.match(/^CVE-(\d{4})-/) : null;
    const year = yearMatch?.[1];

    if (year) {
      console.log(`📦 Fetching ${year}.json from cves.zip`);
      const zipRes = await fetch('https://github.com/globalcve/globalcve/releases/download/v1.0.1/cves.zip');
      const zipBuffer = Buffer.from(await zipRes.arrayBuffer());
      const zip = new AdmZip(zipBuffer);

      const entry = zip.getEntry(`cves/${year}.json`);
      if (entry) {
        const jsonString = entry.getData().toString('utf-8');
        const yearData = JSON.parse(jsonString);

        const q = query.toLowerCase();
        const matchingYearCVEs = yearData.filter((item: any) =>
          [item.id, item.description]
            .filter(Boolean)
            .some((field) => isString(field) && field.toLowerCase().includes(q))
        );

        console.log(`📁 Matching ${year} CVEs:`, matchingYearCVEs.length);

        allResults.push(...matchingYearCVEs.map((item: any) => ({
          id: item.id,
          description: item.description || 'No description available from archive.',
          severity: inferSeverity(item),
          published: item.published || new Date().toISOString(),
          source: 'ARCHIVE',
          kev: kevMap.has(item.id) || kevKeywordMatches.has(item.id), // ✅ PATCHED
        })));
      } else {
        console.warn(`⚠️ ${year}.json not found in cves.zip`);
      }
    }
  } catch (err) {
    console.error('❌ Archive CVE fetch error:', err);
  }

  // 🔹 Apply advanced search filters
  let results = isExactCveId
    ? allResults.filter((r) => r.id?.toUpperCase() === query.toUpperCase())
    : allResults.filter((item) => {
        const searchTerms = parseAdvancedQuery(query);
        const searchText = `${item.description} ${item.id} ${item.source}`.toLowerCase();
        return matchesQuery(searchText, searchTerms);
      });

  console.log('🎯 Exact match results:', results.length);

  // 🔹 Filter by severity
  if (severityFilter) {
    results = results.filter((cve) => cve.severity?.toUpperCase() === severityFilter);
  }

  // 🔹 Apply all filters
  console.log('🎯 Applying filters...');
  
  // Date filters
  if (startDateTime || endDate) {
    const endDateTime = endDate ? new Date(endDate).getTime() : Infinity;
    console.log('📅 Date range:', startDateTime ? new Date(startDateTime).toISOString() : 'any', 'to', endDate || 'any');
    
    results = results.filter((cve) => {
      const pubDate = new Date(cve.published).getTime();
      return (!startDateTime || pubDate >= startDateTime) && 
             (pubDate <= endDateTime);
    });
  }

  // Source filter
  if (sourceFilter) {
    console.log('🔍 Filtering by source:', sourceFilter);
    results = results.filter((cve) => cve.source?.toUpperCase() === sourceFilter);
  }

  // Exploit filter
  if (hasExploit) {
    console.log('💣 Filtering for exploits');
    results = results.filter((cve) => cve.source === 'EXPLOITDB');
  }

  // KEV filter
  if (isKev) {
    console.log('🚨 Filtering for KEV');
    results = results.filter((cve) => cve.kev === true);
  }

  // 🔹 Sort by publish date
  results = results.sort((a, b) => {
    const dateA = new Date(a.published).getTime();
    const dateB = new Date(b.published).getTime();
    return sortOrder === 'oldest' ? dateA - dateB : dateB - dateA;
  });

  // 🔹 Apply pagination
  const startIndex = parseInt(searchParams.get('startIndex') || '0', 10);
  const paginatedResults = results.slice(startIndex, startIndex + 100);

  // Calculate statistics for the full result set
  const stats = calculateStats(results);
  
  console.log(`🧠 Returning ${paginatedResults.length} CVEs with statistics`);
  return NextResponse.json({ 
    query, 
    results: paginatedResults,
    stats,
    total: results.length,
    page: Math.floor(startIndex / 100) + 1,
    totalPages: Math.ceil(results.length / 100)
  });
}
