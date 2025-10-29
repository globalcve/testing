import { 
  Chart as ChartJS, 
  ArcElement, 
  Tooltip, 
  Legend, 
  CategoryScale, 
  LinearScale, 
  BarElement,
  PointElement,
  LineElement,
  Title
} from 'chart.js';
import { Pie, Bar, Line } from 'react-chartjs-2';
import { useEffect, useState } from 'react';
import { CVEStats } from '@/lib/stats';

// Register Chart.js components
ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title
);

interface StatisticsProps {
  stats: CVEStats;
}

const severityColors = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#16a34a',
  UNKNOWN: '#6b7280'
};

const Statistics = ({ stats }: StatisticsProps) => {
  // Prepare data for severity pie chart
  const severityData = {
    labels: Object.keys(stats.bySeverity),
    datasets: [{
      data: Object.values(stats.bySeverity),
      backgroundColor: Object.keys(stats.bySeverity).map(key => severityColors[key as keyof typeof severityColors]),
      borderWidth: 1
    }]
  };

  // Prepare data for vendor bar chart
  const vendorData = {
    labels: stats.topVendors.map(v => v.vendor),
    datasets: [{
      label: 'CVEs by Vendor',
      data: stats.topVendors.map(v => v.count),
      backgroundColor: '#3b82f6',
      borderWidth: 1
    }]
  };

  // Prepare data for timeline
  const timelineData = {
    labels: Object.keys(stats.byDate).slice(-12), // Last 12 months
    datasets: [{
      label: 'CVEs by Month',
      data: Object.values(stats.byDate).slice(-12),
      backgroundColor: '#3b82f6',
      borderWidth: 1
    }]
  };

  return (
    <div className="space-y-6">
      {/* Key Metrics Dashboard */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-[#282a36] rounded-lg">
        <div className="bg-[#44475a] rounded-lg p-4 text-center">
          <h4 className="text-sm font-medium text-[#bd93f9]">Total CVEs</h4>
          <p className="text-2xl font-bold text-[#f8f8f2]">{stats.totalCount}</p>
        </div>
        <div className="bg-[#44475a] rounded-lg p-4 text-center">
          <h4 className="text-sm font-medium text-[#ff5555]">Known Exploits</h4>
          <p className="text-2xl font-bold text-[#ff5555]">{stats.exploitCount}</p>
        </div>
        <div className="bg-[#44475a] rounded-lg p-4 text-center">
          <h4 className="text-sm font-medium text-[#ffb86c]">Active KEVs</h4>
          <p className="text-2xl font-bold text-[#ffb86c]">{stats.kevCount}</p>
        </div>
        <div className="bg-[#44475a] rounded-lg p-4 text-center">
          <h4 className="text-sm font-medium text-[#50fa7b]">Sources</h4>
          <p className="text-2xl font-bold text-[#50fa7b]">{Object.keys(stats.bySource).length}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-[#44475a] rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-4 text-[#bd93f9]">Severity Distribution</h3>
          <div className="h-64">
            <Pie 
              data={severityData} 
              options={{ 
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'right' as const,
                    labels: {
                      color: '#f8f8f2'
                    }
                  }
                }
              }} 
            />
          </div>
        </div>

        {/* Top Affected Vendors */}
        <div className="bg-[#44475a] rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-4 text-[#ff79c6]">Top Affected Vendors</h3>
          <div className="h-64">
            <Bar 
              data={vendorData} 
              options={{ 
                maintainAspectRatio: false,
                indexAxis: 'y' as const,
                scales: {
                  x: {
                    beginAtZero: true,
                    grid: {
                      color: '#6272a4'
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  },
                  y: {
                    grid: {
                      display: false
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  }
                },
                plugins: {
                  legend: {
                    display: false
                  }
                }
              }} 
            />
          </div>
        </div>

        {/* Risk Score Timeline */}
        <div className="bg-[#44475a] rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-4 text-[#8be9fd]">Risk Score Timeline</h3>
          <div className="h-64">
            <Line
              data={{
                labels: Object.keys(stats.byDate).slice(-12),
                datasets: [
                  {
                    label: 'High/Critical CVEs',
                    data: Object.values(stats.byDate).slice(-12).map((_, i) => 
                      stats.bySeverity.CRITICAL + stats.bySeverity.HIGH
                    ),
                    borderColor: '#ff5555',
                    backgroundColor: '#ff555533',
                    fill: true
                  },
                  {
                    label: 'With Known Exploits',
                    data: Object.values(stats.byDate).slice(-12).map(() => stats.exploitCount),
                    borderColor: '#ffb86c',
                    backgroundColor: '#ffb86c33',
                    fill: true
                  }
                ]
              }}
              options={{
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    grid: {
                      color: '#6272a4'
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  },
                  x: {
                    grid: {
                      color: '#6272a4'
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  }
                },
                plugins: {
                  legend: {
                    labels: {
                      color: '#f8f8f2'
                    }
                  }
                }
              }}
            />
          </div>
        </div>

        {/* Source Distribution */}
        <div className="bg-[#44475a] rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-4 text-[#50fa7b]">Source Distribution</h3>
          <div className="h-64">
            <Bar
              data={{
                labels: Object.keys(stats.bySource),
                datasets: [{
                  data: Object.values(stats.bySource),
                  backgroundColor: '#50fa7b',
                  borderColor: '#44475a',
                  borderWidth: 1
                }]
              }}
              options={{
                maintainAspectRatio: false,
                indexAxis: 'y' as const,
                scales: {
                  x: {
                    beginAtZero: true,
                    grid: {
                      color: '#6272a4'
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  },
                  y: {
                    grid: {
                      display: false
                    },
                    ticks: {
                      color: '#f8f8f2'
                    }
                  }
                },
                plugins: {
                  legend: {
                    display: false
                  }
                }
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Statistics;