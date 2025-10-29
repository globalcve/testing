export type SearchTerm = {
  include: string[];  // Terms that must be present (AND)
  exclude: string[];  // Terms that must not be present (NOT)
  exact: string[];    // Exact phrase matches (quoted strings)
  any: string[];      // Terms where at least one must match (OR)
};

export const parseAdvancedQuery = (query: string): SearchTerm => {
  const terms: SearchTerm = {
    include: [],
    exclude: [],
    exact: [],
    any: []
  };

  let currentTerm = '';
  let inQuotes = false;

  const processCurrentTerm = () => {
    if (!currentTerm.trim()) return;
    
    if (currentTerm.startsWith('-')) {
      terms.exclude.push(currentTerm.slice(1).trim().toLowerCase());
    } else if (currentTerm.startsWith('+')) {
      terms.include.push(currentTerm.slice(1).trim().toLowerCase());
    } else if (currentTerm.includes('|')) {
      terms.any.push(...currentTerm.split('|').map(t => t.trim().toLowerCase()).filter(Boolean));
    } else {
      terms.include.push(currentTerm.trim().toLowerCase());
    }
    currentTerm = '';
  };

  // Process each character
  for (let i = 0; i < query.length; i++) {
    const char = query[i];

    if (char === '"') {
      if (inQuotes) {
        // End of quoted string
        terms.exact.push(currentTerm.trim().toLowerCase());
        currentTerm = '';
      }
      inQuotes = !inQuotes;
      continue;
    }

    if (char === ' ' && !inQuotes) {
      processCurrentTerm();
      continue;
    }

    currentTerm += char;
  }

  // Process any remaining term
  if (inQuotes && currentTerm.trim()) {
    terms.exact.push(currentTerm.trim().toLowerCase());
  } else if (currentTerm.trim()) {
    processCurrentTerm();
  }

  return terms;
};

export const matchesQuery = (text: string, terms: SearchTerm): boolean => {
  const normalizedText = text.toLowerCase();

  // Check exact phrases first
  if (terms.exact.some(phrase => !normalizedText.includes(phrase))) {
    return false;
  }

  // Check excluded terms
  if (terms.exclude.some(term => normalizedText.includes(term))) {
    return false;
  }

  // Check required terms
  if (terms.include.some(term => !normalizedText.includes(term))) {
    return false;
  }

  // Check "any" terms (OR condition)
  if (terms.any.length > 0 && !terms.any.some(term => normalizedText.includes(term))) {
    return false;
  }

  return true;
};