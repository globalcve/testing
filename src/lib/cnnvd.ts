/**
 * CNNVD (China National Vulnerability Database) feed parser
 * Documentation: https://www.cnnvd.org.cn/web/interface/list.html
 */

const CNNVD_API_URL = 'https://www.cnnvd.org.cn/web/vulInfo/queryList';
const CNNVD_VULN_URL = 'https://www.cnnvd.org.cn/web/cnnvdInfo/getCnnvdDetail';

interface CNNVDItem {
  cnnvdCode: string;  // CNNVD-YYYY-XXXXX format
  cveCode: string;    // CVE ID if available
  vulLevel: string;   // High, Medium, Low
  vulType: string;
  publishTime: string;
  title: string;
  description: string;
}

function mapSeverity(vulLevel: string): string {
  switch (vulLevel?.toLowerCase()) {
    case 'high':
      return 'HIGH';
    case 'medium':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Fetches vulnerabilities from CNNVD API
 * Returns array of normalized vulnerability objects
 */
export async function fetchCNNVD(query?: string): Promise<any[]> {
  try {
    // Initial search request
    const searchRes = await fetch(CNNVD_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pageIndex: 1,
        pageSize: 50,
        keyword: query || '',
      }),
    });

    if (!searchRes.ok) {
      console.error('❌ CNNVD API error:', searchRes.status);
      return [];
    }

    const searchData = await searchRes.json();
    const items: CNNVDItem[] = searchData.list || [];

    // For each item, fetch full details
    const detailedItems = await Promise.all(
      items.map(async (item) => {
        try {
          const detailRes = await fetch(CNNVD_VULN_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              cnnvdCode: item.cnnvdCode,
            }),
          });

          if (!detailRes.ok) return item;

          const details = await detailRes.json();
          return {
            ...item,
            ...details,
          };
        } catch (err) {
          console.error('❌ CNNVD detail fetch error:', err);
          return item;
        }
      })
    );

    // Map to common format
    return detailedItems.map((item) => ({
      id: item.cveCode || item.cnnvdCode,
      description: item.description || item.title || 'No description available',
      severity: mapSeverity(item.vulLevel),
      published: item.publishTime || new Date().toISOString(),
      source: 'CNNVD',
      metadata: {
        cnnvdId: item.cnnvdCode,
        vulType: item.vulType,
      },
    }));

  } catch (err) {
    console.error('❌ CNNVD fetch error:', err);
    return [];
  }
}