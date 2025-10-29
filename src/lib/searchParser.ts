type SearchTerm = {
  include: string[];
  exclude: string[];
  exact: string[];
  any: string[];
};

export function parseSearchQuery(query: string): SearchTerm {
  const terms: SearchTerm = {
    include: [],
    exclude: [],
    exact: [],
    any: []
  };

  let currentTerm = '';
  let inQuotes = false;

  for (let i = 0; i < query.length; i++) {
    const char = query[i];

    if (char === '"') {
      if (inQuotes) {
        if (currentTerm) terms.exact.push(currentTerm.trim());
        currentTerm = '';
      }
      inQuotes = !inQuotes;
      continue;
    }

    if (char === ' ' && !inQuotes) {
      if (currentTerm) {
        if (currentTerm.startsWith('-')) {
          terms.exclude.push(currentTerm.slice(1).trim());
        } else if (currentTerm.startsWith('+')) {
          terms.include.push(currentTerm.slice(1).trim());
        } else if (currentTerm.includes('|')) {
          terms.any.push(...currentTerm.split('|').map(t => t.trim()).filter(Boolean));
        } else {
          terms.include.push(currentTerm.trim());
        }
      }
      currentTerm = '';
      continue;
    }

    currentTerm += char;
  }

  // Handle the last term
  if (currentTerm) {
    if (currentTerm.startsWith('-')) {
      terms.exclude.push(currentTerm.slice(1).trim());
    } else if (currentTerm.startsWith('+')) {
      terms.include.push(currentTerm.slice(1).trim());
    } else if (currentTerm.includes('|')) {
      terms.any.push(...currentTerm.split('|').map(t => t.trim()).filter(Boolean));
    } else {
      terms.include.push(currentTerm.trim());
    }
  }

  return terms;
}