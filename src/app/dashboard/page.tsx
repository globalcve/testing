// 🔹 CIRCL - Get recent CVEs (skip GHSA)
try {
  const circlUrl = `https://cve.circl.lu/api/last/100`;
  console.log('🔁 Fetching from CIRCL:', circlUrl);
  
  const circlRes = await fetch(circlUrl, {
    headers: {
      'Accept': 'application/json',
    },
    signal: AbortSignal.timeout(10000), // 10 second timeout
  });
  
  if (!circlRes.ok) {
    console.error('❌ CIRCL fetch failed:', circlRes.status, circlRes.statusText);
    throw new Error(`CIRCL API returned ${circlRes.status}`);
  }

  const circlData = await circlRes.json();
  
  if (!circlData) {
    console.warn('⚠️ CIRCL returned empty data');
    throw new Error('Empty response from CIRCL');
  }

  const items = Array.isArray(circlData) ? circlData : [circlData];
  console.log('📦 CIRCL raw items received:', items.length);
  
  const circlCVEs = items
    .filter((item: any) => {
      if (!item) return false;
      
      const id = item.id || item.cveMetadata?.cveId;
      
      // Only accept CVE-* IDs, skip GHSA-* and invalid entries
      if (!id || typeof id !== 'string') {
        return false;
      }
      
      if (!id.startsWith('CVE-')) {
        console.log('⏭️ Skipping non-CVE ID:', id);
        return false;
      }
      
      return true;
    })
    .map((item: any) => {
      try {
        const id = item.id || item.cveMetadata?.cveId;
        
        // Try multiple description fields
        let description = 'No description available';
        
        if (item.summary && typeof item.summary === 'string' && item.summary.trim()) {
          description = item.summary.trim();
        } else if (item.description && typeof item.description === 'string' && item.description.trim()) {
          description = item.description.trim();
        } else if (item.containers?.cna?.descriptions?.[0]?.value) {
          description = item.containers.cna.descriptions[0].value;
        } else if (item.vulnerable_product && Array.isArray(item.vulnerable_product) && item.vulnerable_product.length > 0) {
          description = `Affects: ${item.vulnerable_product.slice(0, 3).join(', ')}`;
        }
        
        // Get published date
        let published = new Date().toISOString();
        if (item.Published && !isNaN(Date.parse(item.Published))) {
          published = item.Published;
        } else if (item.Modified && !isNaN(Date.parse(item.Modified))) {
          published = item.Modified;
        } else if (item.last_modified && !isNaN(Date.parse(item.last_modified))) {
          published = item.last_modified;
        }
        
        return {
          id,
          description,
          severity: inferSeverity(item),
          published,
          source: 'CIRCL',
          kev: kevMap.has(id),
        };
      } catch (mapError) {
        console.error('❌ Error mapping CIRCL item:', mapError);
        return null;
      }
    })
    .filter((cve: any) => cve !== null); // Remove failed mappings

  allResults.push(...circlCVEs);
  console.log('✅ CIRCL CVEs fetched (filtered GHSA):', circlCVEs.length);
  
} catch (err: any) {
  console.error('❌ CIRCL error:', err.message || err);
  // Continue execution - don't let CIRCL failure stop other sources
}
