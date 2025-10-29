'use client';

import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface TrendData {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function CVEStatisticsGraph() {
  const [trendData, setTrendData] = useState<TrendData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchTrendData();
  }, []);

  const fetchTrendData = async () => {
    setLoading(true);
    setError('');

    try {
      // Get last 30 days
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 30);

      const res = await fetch(`/api/cves?startDate=${startDate.toISOString()}&sort=oldest`);
      if (!res.ok) throw new Error(`Fetch failed with status ${res.status}`);
      
      const data = await res.json();
      const results = data.results || [];

      // Group by date and severity
      const dailyData = results.reduce((acc: { [key: string]: TrendData }, cve: any) => {
        const date = new Date(cve.published).toISOString().split('T')[0];
        if (!acc[date]) {
          acc[date] = {
            date,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
          };
        }
        
        switch (cve.severity?.toUpperCase()) {
          case 'CRITICAL':
            acc[date].critical++;
            break;
          case 'HIGH':
            acc[date].high++;
            break;
          case 'MEDIUM':
            acc[date].medium++;
            break;
          case 'LOW':
            acc[date].low++;
            break;
        }
        
        return acc;
      }, {});

      // Fill in missing dates
      const allDates: TrendData[] = [];
      for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
        const dateStr = d.toISOString().split('T')[0];
        allDates.push(dailyData[dateStr] || {
          date: dateStr,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        });
      }

      setTrendData(allDates);
    } catch (err: any) {
      console.error('❌ Trend data fetch error:', err);
      setError('Failed to fetch trend data');
    } finally {
      setLoading(false);
    }
  };

  const chartData = {
    labels: trendData.map(d => d.date.split('-').slice(1).join('/')), // MM/DD format
    datasets: [
      {
        label: 'Critical',
        data: trendData.map(d => d.critical),
        borderColor: '#ff5555',
        backgroundColor: 'rgba(255, 85, 85, 0.1)',
        fill: true,
        tension: 0.4
      },
      {
        label: 'High',
        data: trendData.map(d => d.high),
        borderColor: '#ffb86c',
        backgroundColor: 'rgba(255, 184, 108, 0.1)',
        fill: true,
        tension: 0.4
      },
      {
        label: 'Medium',
        data: trendData.map(d => d.medium),
        borderColor: '#f1fa8c',
        backgroundColor: 'rgba(241, 250, 140, 0.1)',
        fill: true,
        tension: 0.4
      },
      {
        label: 'Low',
        data: trendData.map(d => d.low),
        borderColor: '#50fa7b',
        backgroundColor: 'rgba(80, 250, 123, 0.1)',
        fill: true,
        tension: 0.4
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    interaction: {
      intersect: false,
      mode: 'index' as const
    },
    plugins: {
      legend: {
        position: 'top' as const,
        labels: {
          color: '#f8f8f2'
        }
      },
      title: {
        display: true,
        text: 'CVE Severity Trends (Last 30 Days)',
        color: '#f8f8f2',
        font: {
          size: 16
        }
      }
    },
    scales: {
      x: {
        grid: {
          color: '#44475a'
        },
        ticks: {
          color: '#f8f8f2'
        }
      },
      y: {
        beginAtZero: true,
        grid: {
          color: '#44475a'
        },
        ticks: {
          color: '#f8f8f2'
        }
      }
    }
  };

  if (loading) {
    return (
      <div className="w-full h-80 bg-[#44475a] rounded-lg flex items-center justify-center">
        <div className="text-[#f8f8f2]">Loading statistics...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full p-4 bg-[#ff5555] text-white rounded-lg">
        {error}
      </div>
    );
  }

  return (
    <div className="w-full bg-[#44475a] rounded-lg p-6">
      <Line data={chartData} options={chartOptions} />
    </div>
  );
}