'use client';

import { useEffect, useRef } from 'react';
import { Chart, ChartConfiguration, registerables } from 'chart.js';

Chart.register(...registerables);

interface TrendChartProps {
  stats: any;
  timeframe: '7d' | '30d' | '1y';
}

export default function TrendChart({ stats, timeframe }: TrendChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);

  useEffect(() => {
    if (!chartRef.current || !stats) return;

    // Destroy previous chart
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    if (!ctx) return;

    // Generate trend data based on timeframe
    const generateTrendData = () => {
      const now = new Date();
      const dataPoints: { date: string; count: number }[] = [];
      
      if (timeframe === '7d') {
        // Last 7 days
        for (let i = 6; i >= 0; i--) {
          const date = new Date(now);
          date.setDate(date.getDate() - i);
          dataPoints.push({
            date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
            count: Math.floor(Math.random() * 50) + 20 // Simulated data
          });
        }
      } else if (timeframe === '30d') {
        // Last 30 days (weekly aggregation)
        for (let i = 4; i >= 0; i--) {
          const date = new Date(now);
          date.setDate(date.getDate() - (i * 7));
          dataPoints.push({
            date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
            count: Math.floor(Math.random() * 150) + 80 // Simulated data
          });
        }
      } else {
        // Last year (monthly aggregation)
        for (let i = 11; i >= 0; i--) {
          const date = new Date(now);
          date.setMonth(date.getMonth() - i);
          dataPoints.push({
            date: date.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
            count: Math.floor(Math.random() * 500) + 300 // Simulated data
          });
        }
      }
      
      return dataPoints;
    };

    const trendData = generateTrendData();

    const config: ChartConfiguration = {
      type: 'line',
      data: {
        labels: trendData.map(d => d.date),
        datasets: [{
          label: 'CVE Count',
          data: trendData.map(d => d.count),
          borderColor: 'rgb(80, 250, 123)',
          backgroundColor: 'rgba(80, 250, 123, 0.1)',
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: 'rgb(80, 250, 123)',
          pointBorderColor: '#282a36',
          pointBorderWidth: 2,
          pointRadius: 5,
          pointHoverRadius: 7,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
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
                return `CVEs: ${context.parsed.y}`;
              }
            }
          }
        },
        scales: {
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
                size: 10
              },
              maxRotation: 45,
              minRotation: 45
            },
            grid: {
              display: false
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
  }, [stats, timeframe]);

  // Calculate trend statistics
  const calculateTrend = () => {
    if (!stats?.total) return { change: 0, direction: 'stable' };
    
    // Simulated trend calculation
    const change = Math.floor(Math.random() * 30) - 10; // -10% to +20%
    const direction = change > 5 ? 'up' : change < -5 ? 'down' : 'stable';
    
    return { change, direction };
  };

  const trend = calculateTrend();

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h4 className="text-lg font-semibold text-[#f8f8f2]">CVE Discovery Rate</h4>
          <p className="text-sm text-[#6272a4]">Trends over the selected period</p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${
          trend.direction === 'up' ? 'bg-[#ff5555]/20 text-[#ff5555]' :
          trend.direction === 'down' ? 'bg-[#50fa7b]/20 text-[#50fa7b]' :
          'bg-[#f1fa8c]/20 text-[#f1fa8c]'
        }`}>
          <span className="text-2xl">
            {trend.direction === 'up' ? '↑' : trend.direction === 'down' ? '↓' : '→'}
          </span>
          <div>
            <div className="text-lg font-bold">
              {trend.change > 0 ? '+' : ''}{trend.change}%
            </div>
            <div className="text-xs">vs previous period</div>
          </div>
        </div>
      </div>

      <div className="h-80 flex items-center justify-center">
        <canvas ref={chartRef}></canvas>
      </div>

      <div className="grid grid-cols-3 gap-4 mt-4">
        <div className="bg-[#282a36] p-4 rounded-lg">
          <div className="text-sm text-[#6272a4]">Average per day</div>
          <div className="text-2xl font-bold text-[#8be9fd]">
            {stats?.total ? Math.floor(stats.total / (timeframe === '7d' ? 7 : timeframe === '30d' ? 30 : 365)) : 0}
          </div>
        </div>
        <div className="bg-[#282a36] p-4 rounded-lg">
          <div className="text-sm text-[#6272a4]">Peak day</div>
          <div className="text-2xl font-bold text-[#ff79c6]">
            {stats?.total ? Math.floor(stats.total / (timeframe === '7d' ? 4 : timeframe === '30d' ? 20 : 200)) : 0}
          </div>
        </div>
        <div className="bg-[#282a36] p-4 rounded-lg">
          <div className="text-sm text-[#6272a4]">Growth rate</div>
          <div className="text-2xl font-bold text-[#50fa7b]">
            {trend.change > 0 ? '+' : ''}{trend.change}%
          </div>
        </div>
      </div>
    </div>
  );
}
