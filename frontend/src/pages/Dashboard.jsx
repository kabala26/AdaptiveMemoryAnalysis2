import React, { useMemo } from 'react';
import { useAuth } from '../hooks/useAuth';
import ThemeToggle from '../components/ThemeToggle.jsx';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
} from '@tanstack/react-table';
import { 
  LayoutDashboard, FileUp, History, PieChart, 
  Bell, Settings, BookOpen, ShieldAlert, 
  Users, Database, Activity, LogOut, Cpu
} from 'lucide-react';

// --- Sub-Components ---

const StatCard = ({ label, value, accent = 'text-blue-600', trend = '▲ 1.2%' }) => (
  <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-lg dark:bg-gray-800 dark:border-gray-700">
    <div className="flex items-center justify-between">
      <div>
        <div className="text-xs font-medium text-gray-400 uppercase tracking-wider dark:text-gray-300">{label}</div>
        <div className={`text-3xl font-bold ${accent} mt-2 font-mono`}>{value}</div>
      </div>
      <div className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded-md dark:text-gray-300 dark:bg-gray-700">{trend}</div>
    </div>
  </div>
);

const FileUploadZone = ({ onUpload }) => {
  const [drag, setDrag] = React.useState(false);
  const [progress, setProgress] = React.useState(0);

  const onDrop = (ev) => {
    ev.preventDefault();
    setDrag(false);
    const file = ev.dataTransfer.files?.[0];
    if (!file) return;
    setProgress(10);
    const t = setInterval(() => {
      setProgress((p) => {
        if (p >= 100) {
          clearInterval(t);
          onUpload && onUpload(file);
          return 100;
        }
        return p + 10;
      });
    }, 150);
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
      className={`w-full rounded-xl p-8 border-2 transition-all duration-200 cursor-pointer 
        ${drag ? 'border-blue-500 bg-blue-500/5' : 'border-dashed border-gray-300 bg-gray-50 hover:border-gray-400 dark:border-gray-600 dark:bg-gray-800 dark:hover:border-gray-500'}`}
    >
      <div className="flex flex-col items-center text-center gap-3">
        <div className="p-3 bg-gray-100 rounded-full dark:bg-gray-700">
          <FileUp className="w-6 h-6 text-gray-400 dark:text-gray-300" />
        </div>
        <div>
          <p className="text-sm font-medium text-gray-700 dark:text-gray-200">Drop memory dump to analyze</p>
          <p className="text-xs text-gray-500 mt-1 dark:text-gray-400">Supports .raw, .mem, .vmem</p>
        </div>
        {progress > 0 && (
          <div className="w-full mt-4">
            <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden dark:bg-gray-600">
              <div className="h-full bg-green-500 transition-all duration-300" style={{ width: `${progress}%` }} />
            </div>
            <p className="text-[10px] mt-2 text-gray-500 font-mono text-right dark:text-gray-400">{progress}% UPLOADED</p>
          </div>
        )}
      </div>
    </div>
  );
};

const AnalysisTable = ({ data }) => {
  const columns = useMemo(
    () => [
      {
        header: 'ID',
        accessorKey: 'id',
        cell: (info) => <span className="text-xs font-mono text-gray-500 dark:text-gray-400">{info.getValue()}</span>,
      },
        { header: 'Filename', accessorKey: 'filename', cell: (info) => <span className="text-sm font-medium text-gray-700 dark:text-gray-200">{info.getValue()}</span> },
      {
        header: 'Status',
        accessorKey: 'status',
        cell: (info) => {
          const val = info.getValue();
          const colors = {
            'Scanning': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
            'Success': 'bg-green-500/10 text-green-400 border-green-500/20',
            'Failed': 'bg-red-500/10 text-red-400 border-red-500/20'
          };
          return <span className={`px-2.5 py-0.5 text-[10px] font-bold uppercase rounded-full border ${colors[val] || 'bg-gray-100 text-gray-400 dark:bg-gray-800 dark:text-gray-400'}`}>{val}</span>;
        },
      },
      {
        header: 'Verdict',
        accessorKey: 'verdict',
        cell: (info) => {
          const v = info.getValue();
          const map = { 
            benign: 'text-green-500', 
            malicious: 'text-red-500', 
            unknown: 'text-yellow-500' 
          };
          return <span className={`text-xs font-bold uppercase tracking-wider ${map[v] ?? 'text-gray-500 dark:text-gray-400'}`}>{v}</span>;
        },
      },
        { header: 'Submitted', accessorKey: 'submitted_at', cell: (info) => <span className="text-xs text-gray-500 dark:text-gray-400">{info.getValue()}</span> }
    ],
    []
  );

  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-b border-gray-200 dark:border-gray-700">
              {hg.headers.map((header) => (
                <th key={header.id} className="p-4 text-[10px] font-bold text-gray-500 uppercase tracking-widest dark:text-gray-400">
                  {flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="p-4">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// --- Main Dashboard Implementation ---

export default function Dashboard() {
  // Pulling from your custom useAuth hook
  const { user, logout } = useAuth();
  const role = user?.role || 'analyst';

  const sampleData = [
    { id: 'ANL-092', filename: 'win10_dump.mem', status: 'Scanning', verdict: 'unknown', submitted_at: '2026-05-08 14:20' },
    { id: 'ANL-091', filename: 'srv_prod_01.raw', status: 'Success', verdict: 'malicious', submitted_at: '2026-05-08 11:05' },
    { id: 'ANL-090', filename: 'user_laptop.vmem', status: 'Success', verdict: 'benign', submitted_at: '2026-05-07 16:45' },
  ];

  const sidebarLinks = role === 'admin' ? [
    { name: 'Home', icon: LayoutDashboard, active: true },
    { name: 'Models', icon: Cpu },
    { name: 'Users', icon: Users },
    { name: 'Datasets', icon: Database },
    { name: 'Analytics', icon: Activity },
    { name: 'Settings', icon: Settings },
    { name: 'Audit Logs', icon: ShieldAlert },
  ] : [
    { name: 'Home', icon: LayoutDashboard, active: true },
    { name: 'Upload', icon: FileUp },
    { name: 'History', icon: History },
    { name: 'Statistics', icon: PieChart },
    { name: 'Alerts', icon: Bell },
    { name: 'Settings', icon: Settings },
    { name: 'Guide', icon: BookOpen },
  ];

  return (
    <div className="flex min-h-screen bg-gray-50 text-gray-900 font-sans light dark:bg-gray-900 dark:text-gray-50">
      {/* Sidebar - Dynamic based on AuthContext Role */}
      <aside className="w-64 bg-white border-r border-gray-200 flex flex-col fixed h-full dark:bg-gray-800 dark:border-gray-700">
        <div className="p-6">
          <div className="flex items-center gap-3 px-2">
            <div className="w-8 h-8 bg-ember-500 rounded-lg flex items-center justify-center font-bold text-white shadow-lg shadow-ember-500/20">M</div>
            <span className="font-bold tracking-tight text-gray-900 dark:text-gray-50">ADAPTIVE-ML</span>
          </div>
        </div>

        <nav className="flex-1 px-4 space-y-1 mt-4">
          {sidebarLinks.map((link) => (
            <button
              key={link.name}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all
                ${link.active ? 'bg-blue-100 text-blue-700 dark:bg-gray-700 dark:text-blue-400 font-medium' : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'}`}
            >
              <link.icon className="w-4 h-4" />
              {link.name}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-3 p-2 mb-4 bg-gray-100 rounded-xl border border-gray-200 dark:bg-gray-700 dark:border-gray-600">
            <div className="w-9 h-9 rounded-lg bg-gray-200 flex items-center justify-center text-xs font-bold text-blue-600 dark:bg-gray-600 dark:text-blue-400">
              {user?.username?.substring(0, 2).toUpperCase() || 'AU'}
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-medium text-gray-900 truncate dark:text-gray-50">{user?.username || 'User'}</p>
              <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold dark:text-gray-400">{role}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle className="flex-1" />
            <button 
              onClick={logout}
              className="flex-1 flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-red-600 hover:bg-red-50 transition-colors dark:text-red-400 dark:hover:bg-red-900/20"
            >
              <LogOut className="w-4 h-4" />
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 ml-64 p-8">
        <header className="flex justify-between items-end mb-10">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 tracking-tight dark:text-gray-50">System Overview</h1>
            <p className="text-gray-500 mt-1 dark:text-gray-400">Adaptive analysis monitoring for volatile memory artifacts.</p>
          </div>
          <div className="flex gap-2">
            <div className="px-3 py-1.5 bg-gray-100 border border-gray-200 rounded-lg text-[10px] font-mono text-gray-600 dark:bg-gray-700 dark:border-gray-600 dark:text-gray-300">
              Uptime: 99.9%
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <StatCard label="Model Accuracy" value="94.2%" accent="text-success-500" />
              <StatCard label="Analysis Queue" value="12" accent="text-primary-400" trend="▼ 2" />
              <StatCard label="Threat Detection" value="6.8%" accent="text-danger-500" trend="▲ 0.5%" />
            </div>

            <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-[0_8px_40px_-12px_rgba(28,23,18,0.15)] dark:bg-gray-800 dark:border-gray-700 dark:shadow-[0_8px_40px_-12px_rgba(0,0,0,0.5)]">
              <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50 dark:border-gray-700 dark:bg-gray-700">
                <h2 className="font-semibold text-gray-900 uppercase text-[10px] tracking-widest dark:text-gray-50">Recent Forensic Artifacts</h2>
                <button className="text-[10px] font-bold text-blue-600 hover:text-blue-700 uppercase tracking-wider">Full History</button>
              </div>
              <AnalysisTable data={sampleData} />
            </div>
          </div>

          <aside className="space-y-6">
            <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-xl dark:bg-gray-800 dark:border-gray-700">
              <h3 className="text-xs font-bold text-gray-900 mb-4 uppercase tracking-widest text-gray-400 dark:text-gray-50 dark:text-gray-400">Extraction Engine</h3>
              <FileUploadZone onUpload={(f) => console.log('File:', f.name)} />
            </div>

            {role === 'admin' ? (
              <div className="bg-white border border-gray-200 rounded-xl p-6 dark:bg-gray-800 dark:border-gray-700">
                <h3 className="text-xs font-bold text-gray-900 mb-4 uppercase tracking-widest text-gray-400 dark:text-gray-50 dark:text-gray-400">Administration</h3>
                <div className="space-y-2">
                  <button className="w-full py-2.5 px-4 rounded-lg bg-blue-600 text-white text-xs font-bold uppercase tracking-wider hover:bg-blue-500 transition-all flex items-center justify-center gap-2">
                    <Cpu className="w-4 h-4" /> Trigger Model Retrain
                  </button>
                  <button className="w-full py-2.5 px-4 rounded-lg bg-gray-100 text-gray-700 text-xs font-bold uppercase tracking-wider hover:bg-gray-200 transition-all dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                    System Configuration
                  </button>
                </div>
              </div>
            ) : (
              <div className="bg-green-500/5 border border-green-500/10 rounded-xl p-6 dark:bg-green-500/10 dark:border-green-500/20">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-4 h-4 text-green-500" />
                  <h3 className="text-xs font-bold text-green-500 uppercase tracking-wider">Analyst protocol</h3>
                </div>
                <p className="text-[11px] text-gray-600 leading-relaxed dark:text-gray-400">
                  Classification results are based on memory feature extraction. Cross-reference findings with network logs for high-confidence verdicts.
                </p>
              </div>
            )}
          </aside>
        </div>
      </main>
    </div>
  );
}