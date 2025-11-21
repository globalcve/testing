'use client';

import { useEffect, useRef } from 'react';
import { Chart, ChartConfiguration, registerables } from 'chart.js';

Chart.register(...registerables);

interface TopSourcesChartProps {
  stats: any;
  detailed?: boolean;
}

export default function TopSourcesChart({ stats, detailed = false }: TopSourcesChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);

  useEffect(() => {
    if (!chartRef.current || !stats?.bySources) return;

    // Destroy previous chart
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    if (!ctx) return;

    // Get top sources
    const sourcesArray = Object.entries(stats.bySources)
      .map(([source, count]) => ({ source, count: count as number }))
      .sort((a, b) => b.count - a.count)
      .slice(0, detailed ? 15 : 8);

    const sourceColors = [
      'rgba(80, 250, 123, 0.8)',   // Green
      'rgba(139, 233, 253, 0.8)',  // Cyan
      'rgba(255, 121, 198, 0.8)',  // Pink
      'rgba(189, 147, 249, 0.8)',  // Purple
      'rgba(255, 184, 108, 0.8)',  // Orange
      'rgba(241, 250, 140, 0.8)',  // Yellow
      'rgba(255, 85, 85, 0.8)',    // Red
      'rgba(98, 114, 164, 0.8)',   // Blue-gray
    ];

    const config: ChartConfiguration = {
      type: 'bar',
      data: {
        labels: sourcesArray.map(s => s.source),
        datasets: [{
          label: 'CVE Count',
          data: sourcesArray.map(s => s.count),
          backgroundColor: sourcesArray.map((_, i) => sourceColors[i % sourceColors.length]),
          borderColor: sourcesArray.map((_, i) => sourceColors[i % sourceColors.length].replace('0.8', '1')),
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        indexAxis: detailed ? 'y' : 'x',
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            backgroundColor: '#44475a',
            titleColor: '#f8f8f2',
            bodyColor: '#f8f8f2',
            borderColor: '#6272a4',
            borderWidth: 1,
            padding: 12,
            displayColors: true,
            callbacks: {
              label: function(context) {
                const total = stats.total || 1;
                const value = context.parsed.x || context.parsed.y;
                const percentage = (value / total * 100).toFixed(1);
                return `${context.label}: ${value} CVEs (${percentage}%)`;
              }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: {
              color: '#f8f8f2',
              font: {
                size: 10
              }
            },
            grid: {
              color: 'rgba(98, 114, 164, 0.1)'
            }
          },
          y: {
            beginAtZero: true,
            ticks: {
              color: '#f8f8f2',
              font: {
                size: 10
              }
            },
            grid: {
              color: detailed ? 'rgba(98, 114, 164, 0.1)' : undefined
            }
          }
        }
      }
    };

    chartInstance.current = new Chart(ctx, config);

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [stats, detailed]);

  if (!stats?.bySources) {
    return (
      <div className="flex items-center justify-center h-64 text-[#6272a4]">
        No source data available
      </div>
    );
  }

  return (
    <div className={`${detailed ? 'h-96' : 'h-64'} flex items-center justify-center`}>
      <canvas ref={chartRef}></canvas>
    </div>
  );
}
