import React from 'react';

interface SourceBadgeProps {
  source: string;
  metadata?: any;
}

export default function SourceBadge({ source, metadata }: SourceBadgeProps) {
  switch (source.toUpperCase()) {
    case 'ANDROID':
      return (
        <span title="Android Security Bulletin" className="text-xs px-2 py-1 rounded bg-[#3DDC84] text-black">
          🤖 Android {metadata?.patchLevel ? `(${metadata.patchLevel})` : ''}
        </span>
      );

    case 'APPLE':
      return (
        <span title="Apple Security Advisory" className="text-xs px-2 py-1 rounded bg-[#A2AAAD] text-white">
          🍎 {metadata?.advisory || 'Apple'}
        </span>
      );

    case 'CERT-FR':
      return (
        <span title="CERT-FR Advisory" className="text-xs px-2 py-1 rounded bg-[#002395] text-white">
          🇫🇷 CERT-FR {metadata?.advisory ? `(${metadata.advisory})` : ''}
        </span>
      );

    case 'GITHUB':
      return (
        <span title="GitHub Security Advisory" className="text-xs px-2 py-1 rounded bg-[#2DBA4E] text-white">
          🐱 {metadata?.ghsaId || 'GitHub'}
        </span>
      );

    case 'NVD':
      return (
        <span title="NVD source" className="text-xs px-2 py-1 rounded bg-blue-500 text-white">
          📘 NVD
        </span>
      );

    case 'CIRCL':
      return (
        <span title="CIRCL source" className="text-xs px-2 py-1 rounded bg-purple-500 text-white">
          🧠 CIRCL
        </span>
      );

    case 'JVN':
      return (
        <span title="Japanese advisory source" className="text-xs px-2 py-1 rounded bg-red-700 text-white">
          🇯🇵 JVN
        </span>
      );

    case 'CNNVD':
      return (
        <span title="China National Vulnerability Database" className="text-xs px-2 py-1 rounded bg-[#DE2910] text-white">
          🇨🇳 CNNVD
        </span>
      );

    case 'EXPLOITDB':
      return (
        <span title="ExploitDB source" className="text-xs px-2 py-1 rounded bg-red-600 text-white">
          💣 ExploitDB
        </span>
      );

    case 'CVE.ORG':
      return (
        <span title="CVE.org release" className="text-xs px-2 py-1 rounded bg-black text-white">
          🗂️ CVE.org
        </span>
      );

    case 'ARCHIVE':
      return (
        <span title="Archived CVE data" className="text-xs px-2 py-1 rounded bg-gray-600 text-white">
          🗃️ Archive
        </span>
      );

    default:
      return (
        <span title="Unknown source" className="text-xs px-2 py-1 rounded bg-gray-400 text-white">
          ❔ {source}
        </span>
      );
  }
}