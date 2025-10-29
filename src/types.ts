export type CVE = {
  id: string;
  description: string;
  severity: string;
  published: string;
  source: string;
  metadata?: {
    [key: string]: any;
  };
  kev?: boolean;
};