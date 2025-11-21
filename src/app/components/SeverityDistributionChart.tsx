'use client';

import { useEffect, useRef } from 'react';
import { Chart, ChartConfiguration, registerables } from 'chart.js';

Chart.register(...registerables);

interface SeverityDistributionChartProps {
  stats: any;
  detailed?: boolean;
}

export default function SeverityDistributionChart({ stats, detailed = false }: SeverityDistributionChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);

  useEffect(() => {
    if (!chartRef.current || !stats?.bySeverity) return;

    // Destroy previous chart
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    if (!ctx) return;

    const severityData = {
      CRITICAL: stats.bySeverity.CRITICAL || 0,
      HIGH: stats.bySeverity.HIGH || 0,
      MEDIUM: stats.bySeverity.MEDIUM || 0,
      LOW: stats.bySeverity.LOW || 0,
    };

    const config: ChartConfiguration = {
      type: detailed ? 'bar' : 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          label: 'CVE Count',
          data: [
            severityData.CRITICAL,
            severityData.HIGH,
            severityData.MEDIUM,
            severityData.LOW
          ],
          backgroundColor: [
            'rgba(255, 85, 85, 0.8)',   // Critical - red
            'rgba(255, 184, 108, 0.8)', // High - orange
            'rgba(241, 250, 140, 0.8)', // Medium - yellow
            'rgba(80, 250, 123, 0.8)',  // Low - green
          ],
          borderColor: [
            'rgb(255, 85, 85)',
            'rgb(255, 184, 108)',
            'rgb(241, 250, 140)',
            'rgb(80, 250, 123)',
          ],
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              color: '#f8f8f2',
              font: {
                size: 12
              },
              padding: 15
            }
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
                const value = context.parsed as any;
                const percentage = ((detailed ? value : (value || 0)) / total * 100).toFixed(1);
                return `${context.label}: ${detailed ? value : context.parsed} (${percentage}%)`;
              }
            }
          }
        },
        scales: detailed ? {
          y: {
            beginAtZero: true,
            ticks: {
              color: '#f8f8f2',
              font: {
                size: 11
              }
            },
            grid: {
              color: 'rgba(98, 114, 164, 0.1)'
            }
          },
          x: {
            ticks: {
              color: '#f8f8f2',
              font: {
                size: 11
              }
            },
            grid: {
              display: false
            }
          }
        } : undefined,
      }
    };

    chartInstance.current = new Chart(ctx, config);

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [stats, detailed]);

  if (!stats?.bySeverity) {
    return (
      <div className="flex items-center justify-center h-64 text-[#6272a4]">
        No severity data available
      </div>
    );
  }

  return (
    <div className={`${detailed ? 'h-80' : 'h-64'} flex items-center justify-center`}>
      <canvas ref={chartRef}></canvas>
    </div>
  );
}
