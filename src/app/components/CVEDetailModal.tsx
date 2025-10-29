'use client';

import React from 'react';
import SourceBadge from './SourceBadge';

interface CVEDetailModalProps {
  cve: {
    id: string;
    description: string;
    severity: string;
    published: string;
    source: string;
    kev?: boolean;
    metadata?: any;
  };
  onClose: () => void;
  show: boolean;
}

export default function CVEDetailModal({ cve, onClose, show }: CVEDetailModalProps) {
  if (!show || !cve) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
      <div className="bg-[#282a36] rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="border-b border-[#44475a] p-6">
          <div className="flex justify-between items-start">
            <h2 className="text-2xl font-bold text-[#f8f8f2] flex items-center gap-2">
              {cve.id}
              <SourceBadge source={cve.source} metadata={cve.metadata} />
            </h2>
            <button
              onClick={onClose}
              className="text-[#6272a4] hover:text-[#f8f8f2] transition-colors"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <h3 className="text-lg font-semibold text-[#bd93f9] mb-2">Description</h3>
            <p className="text-[#f8f8f2]">{cve.description}</p>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Severity */}
            <div>
              <h3 className="text-lg font-semibold text-[#ff79c6] mb-2">Severity</h3>
              <div className={`inline-block px-3 py-1 rounded text-sm font-medium ${
                cve.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                cve.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                cve.severity === 'MEDIUM' ? 'bg-yellow-400 text-black' :
                'bg-green-500 text-white'
              }`}>
                {cve.severity}
              </div>
            </div>

            {/* Published Date */}
            <div>
              <h3 className="text-lg font-semibold text-[#8be9fd] mb-2">Published</h3>
              <p className="text-[#f8f8f2]">
                {new Date(cve.published).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric'
                })}
              </p>
            </div>
          </div>

          {/* Source-specific details */}
          {cve.metadata && (
            <div>
              <h3 className="text-lg font-semibold text-[#50fa7b] mb-2">Additional Details</h3>
              <div className="bg-[#44475a] rounded-lg p-4 space-y-4">
                {/* Products */}
                {cve.metadata.products && (
                  <div>
                    <h4 className="text-sm font-semibold text-[#f1fa8c]">Affected Products</h4>
                    <ul className="list-disc list-inside text-[#f8f8f2]">
                      {Array.isArray(cve.metadata.products) 
                        ? cve.metadata.products.map((p: string) => (
                            <li key={p}>{p}</li>
                          ))
                        : <li>{cve.metadata.products}</li>
                      }
                    </ul>
                  </div>
                )}

                {/* References */}
                {cve.metadata.references && (
                  <div>
                    <h4 className="text-sm font-semibold text-[#f1fa8c]">References</h4>
                    <ul className="space-y-2">
                      {Array.isArray(cve.metadata.references) 
                        ? cve.metadata.references.map((ref: string) => (
                            <li key={ref}>
                              <a
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[#8be9fd] hover:underline"
                              >
                                {ref}
                              </a>
                            </li>
                          ))
                        : <li>
                            <a
                              href={cve.metadata.references}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[#8be9fd] hover:underline"
                            >
                              {cve.metadata.references}
                            </a>
                          </li>
                      }
                    </ul>
                  </div>
                )}

                {/* Fixed Versions */}
                {cve.metadata.fixedVersions && (
                  <div>
                    <h4 className="text-sm font-semibold text-[#f1fa8c]">Fixed Versions</h4>
                    <ul className="list-disc list-inside text-[#f8f8f2]">
                      {Array.isArray(cve.metadata.fixedVersions)
                        ? cve.metadata.fixedVersions.map((v: string) => (
                            <li key={v}>{v}</li>
                          ))
                        : <li>{cve.metadata.fixedVersions}</li>
                      }
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-[#44475a] p-6 flex justify-end space-x-4">
          <button
            onClick={() => {
              navigator.clipboard.writeText(cve.id);
            }}
            className="px-4 py-2 bg-[#44475a] text-[#f8f8f2] rounded hover:bg-[#6272a4] transition-colors"
          >
            Copy CVE ID
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-[#ff5555] text-white rounded hover:bg-[#ff6e6e] transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}