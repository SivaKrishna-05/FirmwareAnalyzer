import { useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Link, Route, Switch, useLocation, useParams, Router as WouterRouter } from 'wouter';
import {
  Activity, AlertCircle, AlertTriangle, Archive, ArrowDownToLine, ArrowLeft, ArrowUpRight, BarChart3,
  Bell, Binary, Check, CheckCircle2, ChevronDown, ChevronRight, CircleHelp, ClipboardCheck, Clock3,
  Code2, Database, Download, FileArchive, FileCode2, FileKey2, FileSearch, Filter, FolderTree,
  Gauge, HardDrive, History, Info, LayoutDashboard, LockKeyhole, Menu, MoreHorizontal, Network,
  Radar, RefreshCw, Search, Server, Settings2, ShieldCheck, ShieldAlert, SlidersHorizontal, UploadCloud,
  UserRound, X, XCircle, Zap
} from 'lucide-react';
import {
  getGetDashboardSummaryQueryKey, getGetScanProgressQueryKey, getGetScanQueryKey,
  getGetScanReportQueryKey, getGetSessionQueryKey, getHealthCheckQueryKey, getListScansQueryKey,
  getListScanFilesQueryKey, getListScanVulnerabilitiesQueryKey, getListFirmwareFormatsQueryKey, useCreateScan, useGetDashboardSummary,
  useGetScan, useGetScanProgress, useGetScanReport, useGetSession, useHealthCheck, useListScans,
  useListScanFiles, useListScanVulnerabilities, useListFirmwareFormats,
  ListScansStatus
} from '@workspace/api-client-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { toast } from 'sonner';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient();

const cx = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(' ');
const formatBytes = (bytes?: number | null) => {
  if (bytes === undefined || bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
};
const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(value)) : '—';
const initials = (name?: string | null) => (name || 'Analyst').split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase();

function Skeleton({ className = '' }: { className?: string }) {
  return <div className={cx('skeleton rounded-md', className)} data-testid="loading-skeleton" />;
}

function ErrorState({ label = 'The service did not return a result.', onRetry }: { label?: string; onRetry?: () => void }) {
  return <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-destructive/40 bg-destructive/5 px-6 py-10 text-center" data-testid="state-error">
    <AlertCircle className="size-5 text-destructive" />
    <p className="text-sm text-foreground">{label}</p>
    {onRetry && <button onClick={onRetry} className="text-xs font-bold text-primary underline underline-offset-4" data-testid="button-retry">Try again</button>}
  </div>;
}

function StatusPill({ status, risk }: { status?: string | null; risk?: string | null }) {
  const value = risk || status || 'Unknown';
  const tone = risk === 'CRITICAL' || risk === 'HIGH' || status?.includes('Failed') || status === 'Encrypted' || status === 'Corrupted'
    ? 'danger' : risk === 'MEDIUM' || status === 'Analysis Running' || status === 'Extracting' || status === 'Validating'
      ? 'warn' : risk === 'LOW' || status === 'Analysis Completed' ? 'good' : 'neutral';
  return <span className={cx('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[.12em]', tone === 'danger' && 'border-red-200 bg-red-50 text-red-700', tone === 'warn' && 'border-amber-200 bg-amber-50 text-amber-700', tone === 'good' && 'border-teal-200 bg-teal-50 text-teal-700', tone === 'neutral' && 'border-slate-200 bg-slate-50 text-slate-600')} data-testid={`status-${String(value).toLowerCase().replaceAll(' ', '-')}`}>
    <span className={cx('size-1.5 rounded-full', tone === 'danger' && 'bg-red-500', tone === 'warn' && 'bg-amber-500', tone === 'good' && 'bg-teal-500', tone === 'neutral' && 'bg-slate-400')} />
    {value}
  </span>;
}

function BrandMark() {
  return <div className="flex items-center gap-3" data-testid="brand-mark">
    <div className="relative flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
      <Radar className="size-5" strokeWidth={2.4} />
      <span className="absolute -right-1 -top-1 size-2 rounded-full bg-accent ring-2 ring-sidebar" />
    </div>
    <div><div className="font-serif text-[15px] font-bold tracking-tight text-sidebar-foreground">SENTRY/OS</div><div className="mono text-[9px] uppercase tracking-[.22em] text-sidebar-foreground/45">firmware lab</div></div>
  </div>;
}

/**
 * Login / first-run gate.
 *
 * Credentials are posted to the API, which sets an httpOnly session cookie;
 * the token is never held in JS, so it is not reachable from XSS.
 * `credentials: 'include'` is required for the cookie to be stored.
 */
function LoginScreen({ onAuthenticated, needsBootstrap }: { onAuthenticated: () => void; needsBootstrap: boolean }) {
  const [mode, setMode] = useState<'login' | 'register'>(needsBootstrap ? 'register' : 'login');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const body = mode === 'register' ? { email, name, password } : { email, password };
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(data.error || 'Sign in failed.');
        setBusy(false);
        return;
      }
      if (mode === 'register') {
        // The bootstrap endpoint creates the admin but does not sign in.
        setMode('login');
        setPassword('');
        setError('Administrator account created. Sign in with those credentials.');
        setBusy(false);
        return;
      }
      onAuthenticated();
    } catch {
      setError('Could not reach the server.');
      setBusy(false);
    }
  };

  return <div className="flex min-h-[100dvh] items-center justify-center bg-background px-6">
    <div className="w-full max-w-sm rounded-2xl border border-border bg-card p-8 shadow-sm">
      <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground"><Radar className="size-6" /></div>
      <h1 className="mt-5 text-center font-serif text-2xl font-bold">{mode === 'register' ? 'Create administrator' : 'Sign in'}</h1>
      <p className="mt-2 text-center text-sm leading-6 text-muted-foreground">
        {mode === 'register'
          ? 'No accounts exist yet. The first account you create becomes the administrator.'
          : 'Firmware analysis workspace'}
      </p>

      <div className="mt-6 space-y-3">
        <div>
          <label className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground" htmlFor="login-email">Email</label>
          <input id="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)}
            className="mt-1 h-10 w-full rounded-md border border-border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-email" />
        </div>
        {mode === 'register' && <div>
          <label className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground" htmlFor="login-name">Name</label>
          <input id="login-name" value={name} onChange={(e) => setName(e.target.value)}
            className="mt-1 h-10 w-full rounded-md border border-border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-name" />
        </div>}
        <div>
          <label className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground" htmlFor="login-password">Password</label>
          <input id="login-password" type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            value={password} onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !busy) void submit(); }}
            className="mt-1 h-10 w-full rounded-md border border-border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-password" />
          {mode === 'register' && <p className="mt-1 text-[11px] text-muted-foreground">At least 12 characters, with upper and lower case letters and a digit.</p>}
        </div>
      </div>

      {error && <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive" data-testid="text-login-error">{error}</div>}

      <button onClick={() => void submit()} disabled={busy || !email || !password || (mode === 'register' && !name)}
        className="mt-6 w-full rounded-lg bg-primary px-4 py-3 text-xs font-extrabold text-primary-foreground shadow-xs transition-transform hover:-translate-y-0.5 disabled:opacity-50 disabled:hover:translate-y-0"
        data-testid="button-sign-in">
        {busy ? 'Working…' : mode === 'register' ? 'Create administrator' : 'Sign in'}
      </button>
    </div>
  </div>;
}

function Shell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [, setLocation] = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [signedOut, setSignedOut] = useState(false);
  const session = useGetSession({ query: { queryKey: getGetSessionQueryKey(), staleTime: 60_000 } });
  const health = useHealthCheck({ query: { queryKey: getHealthCheckQueryKey(), refetchInterval: 30_000 } });
  const nav = [
    { href: '/', label: 'Workspace', icon: LayoutDashboard, test: 'link-workspace' },
    { href: '/history', label: 'Scan history', icon: History, test: 'link-history' },
    { href: '/settings', label: 'Settings', icon: Settings2, test: 'link-settings' },
    ...(session.data?.permissions?.includes('user:manage') ? [{ href: '/admin', label: 'Admin', icon: ShieldCheck, test: 'link-admin' }] : []),
  ];
  const user = session.data?.user;
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setSearchOpen(true);
        setNotificationsOpen(false);
        setProfileOpen(false);
      }
      if (event.key === 'Escape') {
        setSearchOpen(false);
        setNotificationsOpen(false);
        setProfileOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  // Gate on the server session. While it is loading we render nothing rather
  // than flashing the login form at an already-authenticated user.
  if (session.isLoading) return <div className="min-h-[100dvh] bg-background" />;
  if (signedOut || session.data?.authenticated === false) {
    return <LoginScreen
      needsBootstrap={session.data?.needsBootstrap === true}
      onAuthenticated={() => { setSignedOut(false); void session.refetch(); }}
    />;
  }

  const goTo = (href: string) => {
    setSearchOpen(false);
    setLocation(href);
  };

  return <div className="min-h-[100dvh] bg-background text-foreground">
    <aside className={cx('fixed inset-y-0 left-0 z-40 flex w-[248px] flex-col border-r border-sidebar-border bg-sidebar px-4 py-5 transition-transform duration-300 md:translate-x-0', mobileOpen ? 'translate-x-0' : '-translate-x-full')} data-testid="app-sidebar">
      <div className="px-2"><BrandMark /></div>
      <div className="mt-10 px-2 mono text-[9px] font-medium uppercase tracking-[.2em] text-sidebar-foreground/35">Analysis console</div>
      <nav className="mt-3 space-y-1" data-testid="primary-navigation">
        {nav.map(({ href, label, icon: Icon, test }) => <Link key={href} href={href} onClick={() => setMobileOpen(false)} className={cx('group flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] font-semibold transition-colors', location === href ? 'bg-sidebar-accent text-sidebar-accent-foreground' : 'text-sidebar-foreground/60 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground')} data-testid={test}><Icon className={cx('size-4', location === href ? 'text-primary' : 'text-sidebar-foreground/45 group-hover:text-sidebar-foreground')} />{label}{location === href && <span className="ml-auto size-1.5 rounded-full bg-primary" />}</Link>)}
      </nav>
      <div className="mt-auto space-y-3">
        <div className="rounded-xl border border-sidebar-border bg-sidebar-accent/55 p-3.5" data-testid="system-health-card">
          <div className="flex items-center justify-between"><span className="mono text-[9px] uppercase tracking-[.16em] text-sidebar-foreground/45">Service health</span><span className={cx('size-2 rounded-full', health.isError ? 'bg-red-400' : 'bg-teal-400')} /></div>
          <div className="mt-2 flex items-center gap-2 text-xs font-semibold text-sidebar-foreground/85"><Activity className="size-3.5 text-teal-400" />{health.isError ? 'Connection degraded' : health.data?.status || 'Operational'}</div>
          <div className="mt-2 text-[10px] leading-relaxed text-sidebar-foreground/40">Evidence-first analysis pipeline</div>
        </div>
        <div className="flex items-center gap-3 border-t border-sidebar-border px-2 pt-4" data-testid="user-profile">
          <div className="flex size-8 items-center justify-center rounded-full bg-secondary text-[11px] font-extrabold text-secondary-foreground">{initials(user?.name)}</div>
          <div className="min-w-0 flex-1"><div className="truncate text-xs font-bold text-sidebar-foreground">{user?.name || 'Workspace user'}</div><div className="truncate text-[10px] text-sidebar-foreground/45">{user?.email || 'Local analysis account'}</div></div>
          <button onClick={() => { setProfileOpen((open) => !open); setNotificationsOpen(false); }} className="rounded-md p-1 text-sidebar-foreground/45 hover:bg-sidebar hover:text-sidebar-foreground" aria-label="Open account menu" aria-expanded={profileOpen} data-testid="button-account-menu"><MoreHorizontal className="size-4" /></button>
        </div>
        {profileOpen && <div className="absolute bottom-5 left-[232px] z-50 w-52 rounded-xl border border-sidebar-border bg-sidebar p-1.5 shadow-lg" data-testid="account-menu">
          <div className="px-3 py-2"><div className="truncate text-xs font-bold text-sidebar-foreground">{user?.name || 'Workspace user'}</div><div className="truncate text-[10px] text-sidebar-foreground/45">{user?.email || 'Local analysis account'}</div></div>
          <button onClick={async () => { setProfileOpen(false); try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }); } catch { /* fall through: still clear locally */ } setSignedOut(true); void session.refetch(); }} className="w-full rounded-lg px-3 py-2 text-left text-xs font-bold text-sidebar-foreground/75 hover:bg-sidebar-accent hover:text-sidebar-foreground" data-testid="button-sign-out">Sign out</button>
        </div>}
      </div>
    </aside>
    {mobileOpen && <button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="fixed inset-0 z-30 bg-foreground/20 md:hidden" data-testid="button-close-navigation" />}
    <div className="md:pl-[248px]">
      <header className="relative sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-border/80 bg-background/90 px-5 backdrop-blur md:px-9" data-testid="topbar">
        <div className="flex items-center gap-3"><button onClick={() => setMobileOpen(true)} className="rounded-md p-2 hover:bg-muted md:hidden" data-testid="button-open-navigation"><Menu className="size-5" /></button><span className="mono hidden text-[10px] uppercase tracking-[.18em] text-muted-foreground sm:block">Workspace / <span className="text-foreground">{location === '/' ? 'Overview' : location.slice(1).replace('/', ' / ')}</span></span></div>
        <div className="flex items-center gap-2">
          <button onClick={() => { setSearchOpen(true); setNotificationsOpen(false); setProfileOpen(false); }} className="hidden items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs font-semibold text-muted-foreground shadow-xs sm:flex" data-testid="button-command-search"><Search className="size-3.5" />Search workspace <kbd className="ml-2 rounded border border-border px-1.5 py-0.5 mono text-[9px]">⌘ K</kbd></button>
          <button onClick={() => { setNotificationsOpen((open) => !open); setSearchOpen(false); setProfileOpen(false); }} className="relative rounded-lg p-2.5 text-muted-foreground hover:bg-muted" aria-label="Open notifications" aria-expanded={notificationsOpen} data-testid="button-notifications"><Bell className="size-4" /><span className="pointer-events-none absolute right-1.5 top-1.5 size-1.5 rounded-full bg-primary ring-2 ring-background" /></button>
        </div>
        {notificationsOpen && <>
          <button className="fixed inset-0 z-30 cursor-default" aria-label="Close notifications" onClick={() => setNotificationsOpen(false)} />
          <div className="absolute right-5 top-[58px] z-40 w-[min(360px,calc(100vw-2rem))] rounded-xl border border-border bg-card p-4 shadow-lg" data-testid="notifications-panel">
            <div className="flex items-center justify-between"><div><div className="text-sm font-bold">Notifications</div><div className="mt-1 text-xs text-muted-foreground">Workspace activity and analysis updates</div></div><span className="rounded-full bg-accent/10 px-2 py-1 mono text-[9px] font-bold uppercase tracking-[.12em] text-accent">All clear</span></div>
            <div className="mt-4 rounded-lg border border-dashed border-border bg-muted/30 p-5 text-center"><CheckCircle2 className="mx-auto size-5 text-accent" /><p className="mt-2 text-xs font-bold">No new notifications</p><p className="mt-1 text-[11px] text-muted-foreground">You’re up to date.</p></div>
          </div>
        </>}
        {searchOpen && <div className="fixed inset-0 z-50 flex items-start justify-center bg-foreground/20 px-4 pt-[12vh]" onMouseDown={(event) => event.target === event.currentTarget && setSearchOpen(false)} data-testid="command-search-dialog">
          <div className="w-full max-w-lg overflow-hidden rounded-2xl border border-border bg-card shadow-2xl">
            <div className="flex items-center gap-3 border-b border-border px-4"><Search className="size-4 text-muted-foreground" /><input autoFocus onKeyDown={(event) => event.key === 'Escape' && setSearchOpen(false)} className="h-14 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground" placeholder="Search workspace" aria-label="Search workspace" data-testid="input-command-search" /><kbd className="rounded border border-border px-1.5 py-0.5 mono text-[9px] text-muted-foreground">ESC</kbd></div>
            <div className="p-2">
              {[['/', 'Workspace overview', 'Review dashboard metrics and start a new analysis.'], ['/history', 'Scan history', 'Search and filter previous firmware scans.'], ['/settings', 'Workspace settings', 'Manage privacy and analysis preferences.']].map(([href, label, description]) => <button key={href} onClick={() => goTo(href)} className="flex w-full items-start gap-3 rounded-xl px-3 py-3 text-left hover:bg-muted" data-testid={`command-${label.toLowerCase().replaceAll(' ', '-')}`}><span className="mt-0.5 rounded-md bg-primary/10 p-1.5 text-primary"><ArrowUpRight className="size-3.5" /></span><span><span className="block text-xs font-bold">{label}</span><span className="mt-1 block text-[11px] text-muted-foreground">{description}</span></span></button>)}
            </div>
          </div>
        </div>}
      </header>
      <main className="mx-auto max-w-[1480px] px-5 py-7 md:px-9 md:py-9">{children}</main>
    </div>
  </div>;
}

function PageTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-end" data-testid="page-title">
    <div><div className="mono mb-2 text-[10px] font-medium uppercase tracking-[.2em] text-accent">{eyebrow}</div><h1 className="font-serif text-3xl font-bold tracking-[-.035em] text-foreground md:text-4xl">{title}</h1>{description && <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p>}</div>{action}
  </div>;
}

function MetricCard({ label, value, detail, icon: Icon, tone = 'default' }: { label: string; value: ReactNode; detail: string; icon: typeof Gauge; tone?: string }) {
  return <div className="rounded-xl border border-border bg-card p-5 shadow-xs transition-shadow hover:shadow-sm" data-testid={`metric-${label.toLowerCase().replaceAll(' ', '-')}`}>
    <div className="flex items-start justify-between"><span className="mono text-[10px] uppercase tracking-[.15em] text-muted-foreground">{label}</span><span className={cx('flex size-8 items-center justify-center rounded-lg', tone === 'coral' ? 'bg-primary/15 text-primary' : tone === 'teal' ? 'bg-accent/12 text-accent' : 'bg-muted text-muted-foreground')}><Icon className="size-4" /></span></div>
    <div className="mt-4 font-serif text-3xl font-bold tracking-tight">{value}</div><div className="mt-1 text-xs text-muted-foreground">{detail}</div>
  </div>;
}

function UploadPanel() {
  const [, setLocation] = useLocation();
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const createScan = useCreateScan();
  const formats = useListFirmwareFormats({ query: { queryKey: getListFirmwareFormatsQueryKey(), staleTime: 300_000 } });
  const supportedExtensions = formats.data?.extensions ?? ['.bin', '.img', '.zip', '.tar', '.tar.gz', '.tgz', '.squashfs', '.ubi', '.fw', '.iso'];
  const supportedLabel = supportedExtensions.map((extension: string) => extension.replace('.', '').toUpperCase()).join(' · ');
  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => setFile(event.target.files?.[0] || null);
  const onDrop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); setDragging(false); setFile(event.dataTransfer.files?.[0] || null); };
  const submit = () => { if (file) createScan.mutate({ data: { file } }, { onSuccess: (scan: any) => setLocation(`/scans/${scan.id}`), onError: (err: any) => toast.error(err.message || 'Failed to upload firmware image') }); };
  return <section className="relative overflow-hidden rounded-2xl border border-sidebar-border bg-sidebar p-6 text-sidebar-foreground shadow-md md:p-8" data-testid="upload-panel">
    <div className="pointer-events-none absolute -right-20 -top-32 size-80 rounded-full border-[34px] border-primary/10" /><div className="pointer-events-none absolute -right-4 top-8 size-52 rounded-full border border-accent/15" />
    <div className="relative grid gap-8 lg:grid-cols-[1fr_1.15fr] lg:items-center">
      <div><div className="mb-3 flex items-center gap-2 mono text-[10px] uppercase tracking-[.2em] text-primary"><UploadCloud className="size-3.5" /> New analysis</div><h2 className="max-w-md font-serif text-2xl font-bold leading-tight tracking-[-.03em] md:text-3xl">Know what is inside your firmware image.</h2><p className="mt-3 max-w-md text-sm leading-6 text-sidebar-foreground/55">Upload a single image. SENTRY/OS extracts the evidence, checks for exposed risk, and shows where to look next.</p><div className="mt-6 flex flex-wrap gap-x-5 gap-y-2 text-[11px] text-sidebar-foreground/50"><span className="flex items-center gap-1.5"><LockKeyhole className="size-3 text-teal-400" />Private by default</span><span className="flex items-center gap-1.5"><FileSearch className="size-3 text-teal-400" />Evidence-linked findings</span></div></div>
      <div onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} className={cx('rounded-xl border border-dashed p-5 transition-colors', dragging ? 'border-primary bg-primary/10' : 'border-sidebar-foreground/20 bg-sidebar-accent/45')} data-testid="upload-dropzone">
        <input ref={inputRef} type="file" className="hidden" onChange={chooseFile} accept={supportedExtensions.join(',')} data-testid="input-firmware-file" />
        {!file ? <button onClick={() => inputRef.current?.click()} className="flex min-h-[172px] w-full flex-col items-center justify-center rounded-lg text-center" data-testid="button-choose-firmware"><span className="mb-4 flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground"><FileArchive className="size-5" /></span><span className="text-sm font-bold">Drop firmware image here</span><span className="mt-1 text-xs text-sidebar-foreground/45">or <span className="text-primary underline underline-offset-4">browse from your device</span></span><span className="mt-5 mono text-[9px] uppercase tracking-[.14em] text-sidebar-foreground/30">{supportedLabel}</span></button> : <div className="min-h-[172px] px-2 py-2" data-testid="selected-firmware"><div className="flex items-center gap-3 rounded-lg bg-sidebar-accent p-3"><span className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary"><Binary className="size-5" /></span><div className="min-w-0 flex-1"><div className="truncate text-sm font-bold">{file.name}</div><div className="mt-1 mono text-[10px] text-sidebar-foreground/45">{formatBytes(file.size)} · Ready to inspect</div></div><button onClick={() => setFile(null)} className="rounded p-1.5 text-sidebar-foreground/50 hover:bg-sidebar hover:text-sidebar-foreground" data-testid="button-remove-firmware"><X className="size-4" /></button></div><button disabled={createScan.isPending} onClick={submit} className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-xs font-extrabold text-primary-foreground transition-transform hover:-translate-y-0.5 disabled:opacity-60" data-testid="button-start-analysis">{createScan.isPending ? <><RefreshCw className="size-4 animate-spin" />Uploading image…</> : <><Zap className="size-4" />Start analysis</>}</button><p className="mt-3 text-center text-[10px] text-sidebar-foreground/35">The original firmware and extracted contents are deleted after analysis; only metadata, findings, and reports are retained.</p></div>}
      </div>
    </div>
  </section>;
}

function ScanRow({ scan }: { scan: any }) {
  return <Link href={`/scans/${scan.id}`} className="group grid grid-cols-[minmax(0,1.7fr)_110px_90px_100px_20px] items-center gap-4 border-b border-border/70 px-5 py-4 transition-colors last:border-0 hover:bg-muted/45 md:grid-cols-[minmax(0,1.7fr)_130px_100px_110px_20px]" data-testid={`row-scan-${scan.id}`}>
    <div className="min-w-0"><div className="flex items-center gap-2"><FileCode2 className="size-4 shrink-0 text-accent" /><span className="truncate text-sm font-bold">{scan.firmwareName}</span></div><div className="mt-1 flex items-center gap-2 pl-6 mono text-[10px] text-muted-foreground"><span>{scan.firmwareType || 'Firmware image'}</span><span className="text-border">/</span><span>{formatBytes(scan.sizeBytes)}</span></div></div>
    <div className="hidden md:block"><StatusPill status={scan.status} /></div><div className="text-sm font-semibold">{scan.riskScore != null ? `${scan.riskScore}/100` : '—'}</div><div className="text-xs text-muted-foreground">{formatDate(scan.createdAt)}</div><ChevronRight className="size-4 text-muted-foreground/35 transition-transform group-hover:translate-x-1 group-hover:text-accent" />
  </Link>;
}

function Dashboard() {
  const summary = useGetDashboardSummary({ query: { queryKey: getGetDashboardSummaryQueryKey(), staleTime: 30_000 } });
  const data = summary.data;
  return <div className="page-enter space-y-8">
    <PageTitle eyebrow="Workspace overview" title="Analysis workspace" description="A measured view of what has been inspected, what needs attention, and what the evidence says." action={<Link href="/history" className="flex items-center gap-2 rounded-lg border border-border bg-card px-3.5 py-2.5 text-xs font-bold shadow-xs hover:bg-muted" data-testid="link-view-history">View scan history <ArrowUpRight className="size-3.5" /></Link>} />
    <UploadPanel />
    {summary.isLoading ? <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{[1,2,3,4].map((n) => <Skeleton key={n} className="h-[140px]" />)}</div> : summary.isError ? <ErrorState label="Dashboard totals are temporarily unavailable." onRetry={() => summary.refetch()} /> : <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <MetricCard label="Total scans" value={data?.totalScans ?? 0} detail="Images in this workspace" icon={Database} />
      <MetricCard label="Completed" value={data?.completedScans ?? 0} detail="Analysis with a final result" icon={ClipboardCheck} tone="teal" />
      <MetricCard label="Running now" value={data?.runningScans ?? 0} detail="Active analysis jobs" icon={Activity} tone="coral" />
      <MetricCard label="Average risk" value={data?.averageRiskScore != null ? `${data.averageRiskScore}/100` : '—'} detail={`${data?.highRiskScans ?? 0} high attention scan${data?.highRiskScans === 1 ? '' : 's'}`} icon={Gauge} tone="coral" />
    </div>}
    <section className="overflow-hidden rounded-xl border border-border bg-card shadow-xs" data-testid="recent-scans-section">
      <div className="flex items-center justify-between border-b border-border/70 px-5 py-4"><div><h2 className="font-serif text-lg font-bold">Recent scans</h2><p className="mt-0.5 text-xs text-muted-foreground">Latest activity across your analysis workspace</p></div><Link href="/history" className="text-xs font-bold text-accent hover:underline" data-testid="link-all-scans">All scans</Link></div>
      <div className="hidden grid-cols-[minmax(0,1.7fr)_110px_90px_100px_20px] gap-4 border-b border-border/60 bg-muted/30 px-5 py-2.5 mono text-[9px] uppercase tracking-[.16em] text-muted-foreground md:grid"><span>Firmware image</span><span>Status</span><span>Risk score</span><span>Created</span><span /></div>
      {summary.isLoading ? <div className="space-y-3 p-5"><Skeleton className="h-12" /><Skeleton className="h-12" /><Skeleton className="h-12" /></div> : data?.recentScans?.length ? data.recentScans.slice(0, 5).map((scan: any) => <ScanRow key={scan.id} scan={scan} />) : <div className="flex flex-col items-center gap-3 px-6 py-14 text-center" data-testid="empty-recent-scans"><div className="flex size-11 items-center justify-center rounded-xl bg-secondary text-secondary-foreground"><FolderTree className="size-5" /></div><p className="text-sm font-bold">No firmware images yet</p><p className="max-w-xs text-xs leading-5 text-muted-foreground">Start an analysis above to create your first evidence trail.</p></div>}
    </section>
    <div className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
      <div className="rounded-xl border border-border bg-card p-5 shadow-xs" data-testid="trust-principles-card"><div className="flex items-center gap-2 text-accent"><ShieldCheck className="size-4" /><span className="mono text-[10px] font-medium uppercase tracking-[.16em]">How SENTRY/OS reports</span></div><h3 className="mt-4 font-serif text-xl font-bold">Evidence before confidence.</h3><p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">Findings are tied to a path, a concrete signal, and a confidence level. A high risk score is a reason to investigate—not a claim of compromise.</p></div>
      <div className="rounded-xl border border-border bg-secondary/50 p-5" data-testid="capability-card"><div className="flex items-center gap-2 text-secondary-foreground"><CircleHelp className="size-4" /><span className="mono text-[10px] font-medium uppercase tracking-[.16em]">Analysis coverage</span></div><div className="mt-4 flex items-end justify-between"><div><div className="font-serif text-2xl font-bold">Static, local, reviewable</div><div className="mt-1 text-xs text-secondary-foreground/70">No network execution of uploaded images</div></div><LockKeyhole className="size-7 text-secondary-foreground/50" /></div></div>
    </div>
  </div>;
}

function HistoryPage() {
  const [status, setStatus] = useState<ListScansStatus>('all');
  const [search, setSearch] = useState('');
  const params = status === 'all' ? { limit: 100 } : { status, limit: 100 };
  const scans = useListScans(params, { query: { queryKey: getListScansQueryKey(params), staleTime: 20_000 } });
  const filtered = useMemo(() => (Array.isArray(scans.data) ? scans.data : []).filter((scan: any) => scan.firmwareName?.toLowerCase().includes(search.toLowerCase())), [scans.data, search]);
  return <div className="page-enter"><PageTitle eyebrow="Evidence index" title="Scan history" description="Every uploaded image, its current disposition, and the trail back to the evidence." action={<Link href="/" className="flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2.5 text-xs font-extrabold text-primary-foreground shadow-xs hover:-translate-y-0.5" data-testid="link-new-scan"><UploadCloud className="size-3.5" />New scan</Link>} />
    <div className="mb-5 flex flex-col gap-3 sm:flex-row"><div className="relative flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search firmware images" className="h-11 w-full rounded-lg border border-border bg-card pl-9 pr-3 text-sm outline-none ring-accent/20 placeholder:text-muted-foreground/60 focus:ring-4" data-testid="input-search-scans" /></div><div className="flex items-center gap-2 overflow-x-auto rounded-lg border border-border bg-card p-1"><Filter className="ml-2 size-3.5 text-muted-foreground" />{([['all','All scans'],['completed','Completed'],['running','Running'],['failed','Needs review']] as const).map(([key, label]) => <button key={key} onClick={() => setStatus(key as ListScansStatus)} className={cx('whitespace-nowrap rounded-md px-3 py-2 text-xs font-bold transition-colors', status === key ? 'bg-sidebar text-sidebar-foreground' : 'text-muted-foreground hover:bg-muted')} data-testid={`button-filter-${key}`}>{label}</button>)}</div></div>
    <div className="overflow-hidden rounded-xl border border-border bg-card shadow-xs" data-testid="scan-history-table"><div className="hidden grid-cols-[minmax(0,1.7fr)_130px_100px_110px_20px] gap-4 border-b border-border/70 bg-muted/30 px-5 py-3 mono text-[9px] uppercase tracking-[.16em] text-muted-foreground md:grid"><span>Firmware image</span><span>Status</span><span>Risk score</span><span>Created</span><span /></div>
      {scans.isLoading ? <div className="space-y-3 p-5">{[1,2,3,4,5].map((n) => <Skeleton key={n} className="h-14" />)}</div> : scans.isError ? <div className="p-5"><ErrorState label="Scan history could not be loaded." onRetry={() => scans.refetch()} /></div> : filtered.length ? filtered.map((scan: any) => <ScanRow key={scan.id} scan={scan} />) : <div className="flex flex-col items-center gap-3 px-6 py-16 text-center" data-testid="empty-scan-history"><Archive className="size-7 text-muted-foreground/50" /><p className="text-sm font-bold">{search ? 'No matching scans' : 'No scans in this view'}</p><p className="text-xs text-muted-foreground">Try another filter or upload a firmware image.</p></div>}
    </div>
  </div>;
}

function ProgressPanel({ progress, loading }: { progress: any; loading: boolean }) {
  if (loading) return <div className="rounded-xl border border-border bg-card p-6" data-testid="progress-loading"><Skeleton className="h-5 w-40" /><Skeleton className="mt-4 h-3 w-full" /><div className="mt-6 space-y-3"><Skeleton className="h-8" /><Skeleton className="h-8" /><Skeleton className="h-8" /></div></div>;
  if (!progress) return <ErrorState label="Live progress is not available yet." />;
  return <div className="rounded-xl border border-border bg-card p-6 shadow-xs" data-testid="scan-progress-panel"><div className="flex items-start justify-between gap-3"><div><div className="mono text-[10px] uppercase tracking-[.18em] text-accent">Live analysis</div><h2 className="mt-1 font-serif text-xl font-bold">{progress.message || 'Analysis in progress'}</h2></div><span className="mono text-2xl font-medium text-primary">{progress.percent}%</span></div><div className="mt-5 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-[width] duration-700" style={{ width: `${progress.percent}%` }} /></div><div className="mt-6 space-y-2">{(progress.stages || []).map((stage: any) => <div key={stage.key} className="flex items-center gap-3 rounded-lg border border-border/70 px-3 py-2.5" data-testid={`stage-${stage.key}`}><span className={cx('flex size-5 items-center justify-center rounded-full', stage.status === 'completed' ? 'bg-teal-100 text-teal-700' : stage.status === 'running' ? 'bg-primary/15 text-primary' : stage.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-muted text-muted-foreground')}>{stage.status === 'completed' ? <Check className="size-3" /> : stage.status === 'running' ? <RefreshCw className="size-3 animate-spin" /> : stage.status === 'failed' ? <XCircle className="size-3" /> : <span className="size-1.5 rounded-full bg-current" />}</span><span className="flex-1 text-xs font-bold">{stage.label}</span><span className="text-[10px] text-muted-foreground">{stage.detail || stage.status}</span></div>)}</div></div>;
}

function FindingCard({ finding }: { finding: any }) {
  const [open, setOpen] = useState(false);
  return <div className="rounded-xl border border-border bg-card shadow-xs" data-testid={`finding-${finding.id}`}><button onClick={() => setOpen(!open)} className="flex w-full items-start gap-3 p-5 text-left" data-testid={`button-toggle-finding-${finding.id}`}><span className={cx('mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg', finding.severity === 'Critical' || finding.severity === 'High' ? 'bg-red-50 text-red-600' : finding.severity === 'Medium' ? 'bg-amber-50 text-amber-600' : 'bg-teal-50 text-teal-600')}><ShieldAlert className="size-4" /></span><span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-bold">{finding.title}</span><StatusPill risk={finding.severity === 'Critical' ? 'CRITICAL' : finding.severity === 'High' ? 'HIGH' : finding.severity === 'Medium' ? 'MEDIUM' : 'LOW'} /><span className="rounded-full bg-muted px-2 py-1 text-[10px] font-bold text-muted-foreground">{finding.confidence} confidence</span></span><span className="mt-2 block truncate mono text-[10px] text-muted-foreground">{finding.affectedPath}</span></span>{open ? <ChevronDown className="size-4 text-muted-foreground" /> : <ChevronRight className="size-4 text-muted-foreground" />}</button>{open && <div className="space-y-4 border-t border-border/70 bg-muted/20 px-5 py-5 pl-16 text-sm"><div><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Why it matters</div><p className="mt-1 leading-6 text-foreground/80">{finding.description}</p></div><div className="grid gap-4 md:grid-cols-2"><div><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Observed evidence</div><pre className="mt-2 overflow-auto rounded-lg bg-sidebar p-3 text-[11px] leading-5 text-sidebar-foreground">{finding.evidence}</pre>{finding.detectionSource && <div className="mt-2 text-[10px] text-muted-foreground">Detected by: {finding.detectionSource}</div>}</div><div><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Suggested next step</div><p className="mt-1 leading-6 text-foreground/80">{finding.recommendation}</p><div className="mt-3 flex flex-wrap gap-2">{finding.component && <span className="inline-flex items-center gap-1.5 rounded-md bg-secondary px-2 py-1 mono text-[10px] text-secondary-foreground"><Binary className="size-3" />{finding.component}{finding.componentVersion ? ` ${finding.componentVersion}` : ''}</span>}{finding.cve && <span className="inline-flex items-center gap-1.5 rounded-md bg-primary/10 px-2 py-1 mono text-[10px] text-primary"><FileKey2 className="size-3" />{finding.cve}</span>}</div></div></div></div>}</div>;
}

function DetailPage() {
  const { scanId = '' } = useParams<{ scanId: string }>();
  const [, setLocation] = useLocation();
  const [tab, setTab] = useState('overview');
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const scan = useGetScan(scanId, { query: { enabled: !!scanId, queryKey: getGetScanQueryKey(scanId), refetchInterval: 30_000 } });
  const progress = useGetScanProgress(scanId, { query: { enabled: !!scanId, queryKey: getGetScanProgressQueryKey(scanId), refetchInterval: 2500 } });
  const files = useListScanFiles(scanId, { query: { enabled: !!scanId, queryKey: getListScanFilesQueryKey(scanId) } });
  const vulnerabilities = useListScanVulnerabilities(scanId, { query: { enabled: !!scanId, queryKey: getListScanVulnerabilitiesQueryKey(scanId) } });
  const report = useGetScanReport(scanId, { query: { enabled: !!scanId, queryKey: getGetScanReportQueryKey(scanId) } });
  const detail: any = scan.data;
  const deleteScan = async () => {
    setDeleting(true);
    setDeleteError(null);
    try {
      const response = await fetch(`/api/scans/${scanId}`, { method: 'DELETE', credentials: 'include' });
      if (!response.ok && response.status !== 204) {
        const body = await response.json().catch(() => ({}));
        setDeleteError(body.error || 'This scan could not be deleted.');
        setDeleting(false);
        return;
      }
      setLocation('/history');
    } catch {
      setDeleteError('Could not reach the server.');
      setDeleting(false);
    }
  };
  const isRunning = detail?.status && !['Analysis Completed', 'Analysis Failed', 'Extraction Failed', 'Unsupported', 'Encrypted', 'Corrupted'].includes(detail.status);
  const tabs = [{ key: 'overview', label: 'Overview', icon: BarChart3 }, { key: 'findings', label: `Findings ${detail?.vulnerabilityCount != null ? `(${detail.vulnerabilityCount})` : ''}`, icon: ShieldAlert }, { key: 'files', label: 'File inventory', icon: FolderTree }, { key: 'report', label: 'Report', icon: FileSearch }];
  if (scan.isLoading) return <div className="space-y-6 page-enter"><Skeleton className="h-6 w-24" /><Skeleton className="h-40" /><Skeleton className="h-96" /></div>;
  if (scan.isError || !detail) return <div className="page-enter"><Link href="/" className="mb-6 inline-flex items-center gap-2 text-xs font-bold text-muted-foreground hover:text-foreground" data-testid="link-back-workspace"><ArrowLeft className="size-3.5" />Back to workspace</Link><ErrorState label="This scan could not be loaded." onRetry={() => scan.refetch()} /></div>;
  const downloadPdf = () => {
    window.open(`/api/scans/${scanId}/report/pdf`, '_blank');
  };
  return <div className="page-enter">
    <Link href="/history" className="mb-5 inline-flex items-center gap-2 text-xs font-bold text-muted-foreground hover:text-foreground" data-testid="link-back-history"><ArrowLeft className="size-3.5" />Scan history</Link>
    <div className="mb-7 flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div><div className="mb-2 flex items-center gap-2 mono text-[10px] uppercase tracking-[.18em] text-accent"><FileCode2 className="size-3.5" />Scan {scanId.slice(0, 8)}</div><h1 className="max-w-3xl break-words font-serif text-3xl font-bold tracking-[-.035em] md:text-4xl" data-testid="text-scan-name">{detail.firmwareName}</h1><div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-muted-foreground"><span>{detail.firmwareType || 'Firmware image'}</span><span className="text-border">/</span><span>{formatBytes(detail.sizeBytes)}</span><span className="text-border">/</span><span>Uploaded {formatDate(detail.createdAt)}</span></div></div><div className="flex items-center gap-3"><StatusPill status={detail.status} /><button onClick={downloadPdf} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2.5 text-xs font-bold shadow-xs hover:bg-muted" data-testid="button-download-report"><Download className="size-3.5" />Export report</button><button onClick={() => setConfirmingDelete(true)} className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2.5 text-xs font-bold text-destructive shadow-xs hover:bg-destructive/10" data-testid="button-delete-scan"><XCircle className="size-3.5" />Delete</button></div></div>
    {confirmingDelete && <div className="fixed inset-0 z-50 flex items-center justify-center bg-foreground/20 px-4" onMouseDown={(event) => event.target === event.currentTarget && !deleting && setConfirmingDelete(false)} data-testid="dialog-confirm-delete">
      <div className="w-full max-w-sm rounded-2xl border border-border bg-card p-6 shadow-2xl">
        <h3 className="font-serif text-lg font-bold">Delete this scan?</h3>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">This permanently removes the scan record, its file inventory, and all findings. This cannot be undone.</p>
        {deleteError && <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive" data-testid="text-delete-error">{deleteError}</div>}
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={() => setConfirmingDelete(false)} disabled={deleting} className="rounded-lg px-3.5 py-2 text-xs font-bold text-muted-foreground hover:bg-muted disabled:opacity-50" data-testid="button-cancel-delete">Cancel</button>
          <button onClick={() => void deleteScan()} disabled={deleting} className="rounded-lg bg-destructive px-3.5 py-2 text-xs font-extrabold text-destructive-foreground shadow-xs hover:-translate-y-0.5 disabled:opacity-50 disabled:hover:translate-y-0" data-testid="button-confirm-delete">{deleting ? 'Deleting…' : 'Delete scan'}</button>
        </div>
      </div>
    </div>}
    {isRunning && <div className="mb-6"><ProgressPanel progress={progress.data} loading={progress.isLoading} /></div>}
    {(detail.status === 'Analysis Completed' || detail.status === 'Unsupported') && detail.riskScore == null && <div className="mb-6 rounded-xl border border-amber-500/40 bg-amber-500/5 p-5" data-testid="analysis-incomplete-banner"><div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 size-5 shrink-0 text-amber-600" /><div><h3 className="font-serif text-base font-bold text-amber-900 dark:text-amber-200">Analysis incomplete — this image was not fully assessed</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">The firmware filesystem could not be extracted, so no risk score was produced. The absence of findings below does <strong>not</strong> mean this firmware is safe; it means the analyzer could not inspect its contents.</p>{detail.extractionNotes && <details className="mt-3"><summary className="cursor-pointer text-[11px] font-bold text-amber-700 dark:text-amber-300">Why extraction did not complete</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-muted/60 p-3 mono text-[10px] leading-4 text-muted-foreground">{detail.extractionNotes}</pre></details>}</div></div></div>}
    <div className="mb-6 grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-border bg-card p-4 shadow-xs" data-testid="scan-risk-score"><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Risk score</div>{detail.riskScore == null ? <div className="mt-2 font-serif text-xl font-bold text-muted-foreground">Not assessed</div> : <div className="mt-2 flex items-end gap-2"><span className="font-serif text-3xl font-bold">{detail.riskScore}</span><span className="mb-1 text-xs text-muted-foreground">/100</span></div>}</div><div className="rounded-xl border border-border bg-card p-4 shadow-xs" data-testid="scan-vulnerability-count"><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Vulnerabilities</div><div className="mt-2 font-serif text-3xl font-bold">{detail.riskScore == null ? <span className="text-xl text-muted-foreground">Not assessed</span> : detail.vulnerabilityCount ?? '—'}</div></div><div className="rounded-xl border border-border bg-card p-4 shadow-xs" data-testid="scan-malware-count"><div className="mono text-[9px] uppercase tracking-[.16em] text-muted-foreground">Malware indicators</div><div className="mt-2 font-serif text-3xl font-bold">{detail.riskScore == null ? <span className="text-xl text-muted-foreground">Not assessed</span> : detail.malwareIndicatorCount ?? '—'}</div></div></div>
    <div className="border-b border-border" data-testid="scan-tabs"><div className="flex gap-6 overflow-x-auto">{tabs.map(({ key, label, icon: Icon }) => <button key={key} onClick={() => setTab(key)} className={cx('flex shrink-0 items-center gap-2 border-b-2 px-1 pb-3 text-xs font-bold transition-colors', tab === key ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')} data-testid={`tab-${key}`}><Icon className="size-3.5" />{label}</button>)}</div></div>
    <div className="mt-6">
      {tab === 'overview' && <div className="grid gap-6 lg:grid-cols-[1.15fr_.85fr]"><div className="space-y-6"><section className="rounded-xl border border-border bg-card p-5 shadow-xs" data-testid="firmware-profile"><div className="mb-5 flex items-center justify-between"><h2 className="font-serif text-lg font-bold">Firmware profile</h2><span className="rounded-md bg-secondary px-2 py-1 mono text-[9px] uppercase tracking-[.14em] text-secondary-foreground">Extracted metadata</span></div><div className="grid gap-5 sm:grid-cols-2">{[['Architecture',detail.architecture,Code2],['Operating system',detail.operatingSystem,Server],['Filesystem',detail.filesystem,HardDrive],['Extraction',detail.extractionStatus,Archive]].map(([label,value,Icon]: any) => <div key={label as string} data-testid={`metadata-${String(label).toLowerCase().replaceAll(' ','-')}`}><div className="flex items-center gap-2 mono text-[9px] uppercase tracking-[.15em] text-muted-foreground"><Icon className="size-3" />{label as string}</div><div className="mt-2 text-sm font-bold">{value || 'Not identified'}</div></div>)}</div>{(detail.extractionMethod || detail.extractionNotes) && <div className="mt-6 border-t border-border/70 pt-4" data-testid="extraction-provenance"><div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Extraction provenance</div><div className="mt-2 text-xs leading-5"><span className="font-bold">{detail.extractionMethod || 'nothing unpacked'}</span>{typeof detail.extractedFileCount === 'number' && <span className="text-muted-foreground"> · {detail.extractedFileCount} files at depth {detail.extractionDepth}</span>}</div>{detail.extractionNotes && <details className="mt-3"><summary className="cursor-pointer text-[11px] font-bold text-accent">Limitations and unavailable capabilities</summary><pre className="mt-2 max-h-52 overflow-auto whitespace-pre-wrap rounded-md bg-muted/60 p-3 mono text-[10px] leading-4 text-muted-foreground">{detail.extractionNotes}</pre></details>}</div>}{detail.sha256 && <div className="mt-6 border-t border-border/70 pt-4"><div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Image SHA-256</div><div className="mt-2 break-all mono text-[11px] text-foreground/70" data-testid="text-sha256">{detail.sha256}</div></div>}</section><section><div className="mb-3 flex items-center justify-between"><h2 className="font-serif text-lg font-bold">Priority findings</h2><button onClick={() => setTab('findings')} className="text-xs font-bold text-accent hover:underline" data-testid="button-view-all-findings">View all</button></div>{vulnerabilities.isLoading ? <Skeleton className="h-24" /> : vulnerabilities.data?.length ? vulnerabilities.data.slice(0, 2).map((finding: any) => <div className="mb-3" key={finding.id}><FindingCard finding={finding} /></div>) : <div className="rounded-xl border border-dashed border-border bg-card px-6 py-10 text-center" data-testid="empty-findings"><CheckCircle2 className="mx-auto size-7 text-accent" /><p className="mt-3 text-sm font-bold">{detail.riskScore == null ? 'Scan incomplete: unassessed' : 'No findings returned'}</p><p className="mt-1 text-xs text-muted-foreground">{detail.riskScore == null ? 'The filesystem could not be extracted; absence of findings does not indicate safety.' : 'This is not a guarantee of safety; it means no supported signals were found.'}</p></div>}</section></div><aside className="space-y-4"><div className="rounded-xl border border-border bg-card p-5 shadow-xs" data-testid="interpretation-card"><div className="flex items-center gap-2"><Info className="size-4 text-accent" /><h2 className="font-serif text-lg font-bold">Interpretation</h2></div><p className="mt-4 text-sm leading-6 text-muted-foreground">{detail.riskScore == null ? 'Analysis incomplete: The firmware filesystem could not be extracted. Risk could not be assessed. The absence of findings does NOT indicate the firmware is safe.' : detail.riskLevel === 'HIGH' || detail.riskLevel === 'CRITICAL' ? 'This image contains signals that deserve analyst attention. Start with the highest-confidence findings and validate them against the device context.' : 'The available evidence does not currently indicate elevated risk. Continue with context-aware review before making a release decision.'}</p><div className="mt-5 rounded-lg bg-muted/70 p-3 text-xs leading-5 text-muted-foreground">Risk is a prioritization signal, not a verdict. Confidence describes the strength of the evidence attached to each finding.</div></div><div className="rounded-xl border border-border bg-sidebar p-5 text-sidebar-foreground" data-testid="hash-card"><div className="flex items-center gap-2 text-primary"><LockKeyhole className="size-4" /><span className="mono text-[9px] uppercase tracking-[.16em]">Chain of custody</span></div><p className="mt-3 text-xs leading-5 text-sidebar-foreground/55">The image fingerprint and retained artifacts let your team reproduce this review later.</p><div className="mt-4 flex items-center gap-2 text-xs font-bold"><Check className="size-3 text-teal-400" />Digest recorded</div></div></aside></div>}
      {tab === 'findings' && <div className="max-w-4xl space-y-3">{vulnerabilities.isLoading ? [1,2,3].map((n) => <Skeleton key={n} className="h-24" />) : vulnerabilities.isError ? <ErrorState label="Findings could not be loaded." onRetry={() => vulnerabilities.refetch()} /> : vulnerabilities.data?.length ? vulnerabilities.data.map((finding: any) => <FindingCard key={finding.id} finding={finding} />) : <div className="rounded-xl border border-dashed border-border bg-card px-6 py-16 text-center" data-testid="empty-all-findings"><CheckCircle2 className="mx-auto size-7 text-accent" /><p className="mt-3 text-sm font-bold">{detail.riskScore == null ? 'Analysis incomplete (unassessed)' : 'No evidence-backed findings'}</p><p className="mt-1 text-xs text-muted-foreground">{detail.riskScore == null ? 'The filesystem could not be extracted; absence of findings does not indicate safety.' : 'The scan completed without supported vulnerability signals.'}</p></div>}</div>}
      {tab === 'files' && <FileInventory files={files.data} loading={files.isLoading} error={files.isError} retry={() => files.refetch()} />}
      {tab === 'report' && <ReportView report={report.data} loading={report.isLoading} error={report.isError} retry={() => report.refetch()} />}
    </div>
  </div>;
}

function FileInventory({ files, loading, error, retry }: { files?: any[]; loading: boolean; error: boolean; retry: () => void }) {
  const [filter, setFilter] = useState('');
  const list = (files || []).filter((file) => file.path.toLowerCase().includes(filter.toLowerCase()));
  return <div className="rounded-xl border border-border bg-card shadow-xs" data-testid="file-inventory"><div className="flex flex-col justify-between gap-3 border-b border-border/70 p-5 sm:flex-row sm:items-center"><div><h2 className="font-serif text-lg font-bold">Retained file inventory</h2><p className="mt-1 text-xs text-muted-foreground">Paths and static signals discovered during extraction.</p></div><div className="relative w-full sm:w-64"><Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" /><input value={filter} onChange={(e) => setFilter(e.target.value)} className="h-9 w-full rounded-md border border-border bg-background pl-8 pr-3 text-xs outline-none focus:ring-2 focus:ring-accent/20" placeholder="Filter paths" data-testid="input-filter-files" /></div></div>{loading ? <div className="space-y-3 p-5">{[1,2,3,4].map((n) => <Skeleton key={n} className="h-12" />)}</div> : error ? <div className="p-5"><ErrorState label="File inventory is unavailable." onRetry={retry} /></div> : list.length ? <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left"><thead className="bg-muted/30 mono text-[9px] uppercase tracking-[.15em] text-muted-foreground"><tr><th className="px-5 py-3">Path</th><th className="px-3 py-3">Type</th><th className="px-3 py-3">Size</th><th className="px-3 py-3">Mode</th><th className="px-3 py-3">Owner</th><th className="px-3 py-3">Entropy</th><th className="px-3 py-3">Arch</th><th className="px-5 py-3">Digest</th></tr></thead><tbody>{list.map((file: any, index) => <tr key={`${file.path}-${index}`} className={cx('border-t border-border/60 text-xs hover:bg-muted/25', file.suspicious && 'bg-destructive/5')} data-testid={`row-file-${index}`}><td className="max-w-[300px] truncate px-5 py-3 font-semibold">{file.executable && <span className="mr-2 inline-flex rounded bg-primary/10 p-1 text-primary"><Zap className="size-3" /></span>}{file.suspicious && <span className="mr-2 inline-flex rounded bg-destructive/10 p-1 text-destructive" title={file.suspiciousReason || 'Flagged'}><AlertTriangle className="size-3" /></span>}{file.path}</td><td className="px-3 py-3 text-muted-foreground">{file.type}</td><td className="px-3 py-3 mono text-[10px]">{formatBytes(file.sizeBytes)}</td><td className={cx('px-3 py-3 mono text-[10px]', file.permissions && /^[42]/.test(file.permissions) && 'font-bold text-destructive')}>{file.permissions || '—'}</td><td className="px-3 py-3 mono text-[10px] text-muted-foreground">{file.owner || '—'}</td><td className="px-3 py-3 mono text-[10px]">{file.entropy == null ? '—' : file.entropy.toFixed(2)}</td><td className="max-w-[120px] truncate px-3 py-3 mono text-[10px] text-muted-foreground">{file.binaryInfo?.architecture || '—'}</td><td className="max-w-[140px] truncate px-5 py-3 mono text-[10px] text-muted-foreground">{file.sha256}</td></tr>)}</tbody></table></div> : <div className="p-14 text-center text-sm text-muted-foreground" data-testid="empty-file-inventory">No retained files match this view.</div>}</div>;
}

function ReportView({ report, loading, error, retry }: { report?: any; loading: boolean; error: boolean; retry: () => void }) {
  if (loading) return <div className="rounded-xl border border-border bg-card p-6"><Skeleton className="h-7 w-72" /><Skeleton className="mt-5 h-[480px]" /></div>;
  if (error) return <ErrorState label="The printable report is not available." onRetry={retry} />;
  if (!report) return <div className="rounded-xl border border-dashed border-border bg-card px-6 py-16 text-center" data-testid="empty-report"><FileSearch className="mx-auto size-7 text-muted-foreground/50" /><p className="mt-3 text-sm font-bold">Report not generated</p><p className="mt-1 text-xs text-muted-foreground">A report will be available after analysis completes.</p></div>;
  return <div className="rounded-xl border border-border bg-card shadow-xs" data-testid="report-view"><div className="flex flex-col justify-between gap-4 border-b border-border/70 p-5 sm:flex-row sm:items-center"><div><h2 className="font-serif text-lg font-bold">{report.title}</h2><p className="mt-1 text-xs text-muted-foreground">Generated {formatDate(report.generatedAt)} · <span className="mono">{report.sha256?.slice(0, 16)}…</span></p></div><button onClick={() => window.print()} className="flex items-center justify-center gap-2 rounded-lg border border-border px-3 py-2 text-xs font-bold hover:bg-muted" data-testid="button-print-report"><ArrowDownToLine className="size-3.5" />Print / save PDF</button></div><article className="prose prose-sm max-w-none p-6 md:p-9" dangerouslySetInnerHTML={{ __html: report.html }} /></div>;
}

function ChangePasswordForm() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);

  const submit = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch('/api/auth/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setMessage({ kind: 'error', text: data.error || 'Password could not be updated.' });
        setBusy(false);
        return;
      }
      setCurrentPassword('');
      setNewPassword('');
      setMessage({ kind: 'success', text: data.message || 'Password updated.' });
      setBusy(false);
    } catch {
      setMessage({ kind: 'error', text: 'Could not reach the server.' });
      setBusy(false);
    }
  };

  return <div className="mt-5 space-y-3 border-t border-sidebar-border pt-5">
    <div className="mono text-[9px] uppercase tracking-[.18em] text-sidebar-foreground/45">Change password</div>
    <input type="password" autoComplete="current-password" placeholder="Current password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
      className="h-9 w-full rounded-md border border-sidebar-border bg-sidebar-accent/40 px-3 text-xs text-sidebar-foreground outline-none placeholder:text-sidebar-foreground/35 focus:ring-2 focus:ring-primary/30" data-testid="input-current-password" />
    <input type="password" autoComplete="new-password" placeholder="New password (12+ chars)" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
      onKeyDown={(e) => { if (e.key === 'Enter' && !busy) void submit(); }}
      className="h-9 w-full rounded-md border border-sidebar-border bg-sidebar-accent/40 px-3 text-xs text-sidebar-foreground outline-none placeholder:text-sidebar-foreground/35 focus:ring-2 focus:ring-primary/30" data-testid="input-new-password" />
    {message && <p className={cx('text-[11px]', message.kind === 'error' ? 'text-destructive' : 'text-teal-400')} data-testid="text-password-status">{message.text}</p>}
    <button onClick={() => void submit()} disabled={busy || !currentPassword || newPassword.length < 12}
      className="w-full rounded-lg bg-primary px-3 py-2 text-xs font-extrabold text-primary-foreground shadow-xs hover:-translate-y-0.5 disabled:opacity-50 disabled:hover:translate-y-0" data-testid="button-change-password">
      {busy ? 'Updating…' : 'Update password'}
    </button>
  </div>;
}

function SettingsPage() {
  const session = useGetSession({ query: { queryKey: getGetSessionQueryKey() } });
  const [telemetry, setTelemetry] = useState(false);
  const [deepAnalysis, setDeepAnalysis] = useState(true);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch('/api/settings', { credentials: 'include' })
      .then((res) => res.json())
      .then((data) => {
        if (typeof data.telemetry === 'boolean') setTelemetry(data.telemetry);
        if (typeof data.deepAnalysis === 'boolean') setDeepAnalysis(data.deepAnalysis);
      })
      .catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const response = await fetch('/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ telemetry, deepAnalysis }),
      });
      if (response.ok) {
        setSaved(true);
        window.setTimeout(() => setSaved(false), 2200);
      }
    } catch {
      // ignore
    } finally {
      setSaving(false);
    }
  };

  return <div className="page-enter"><PageTitle eyebrow="Workspace controls" title="Settings" description="Make retention, privacy, and analysis depth explicit for everyone who uses this workspace." action={saved ? <span className="flex items-center gap-2 text-xs font-bold text-accent" data-testid="status-settings-saved"><CheckCircle2 className="size-4" />Changes saved</span> : <button onClick={() => void save()} disabled={saving} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-extrabold text-primary-foreground shadow-xs hover:-translate-y-0.5 disabled:opacity-50" data-testid="button-save-settings"><Check className="size-3.5" />{saving ? 'Saving…' : 'Save preferences'}</button>} />
     <div className="grid gap-6 lg:grid-cols-[1.2fr_.8fr]"><div className="space-y-6"><section className="rounded-xl border border-border bg-card shadow-xs" data-testid="privacy-settings"><div className="border-b border-border/70 p-5"><div className="flex items-center gap-2"><LockKeyhole className="size-4 text-accent" /><h2 className="font-serif text-lg font-bold">Privacy & retention</h2></div><p className="mt-1 text-xs text-muted-foreground">Uploaded firmware and extracted contents are temporary by design.</p></div><div className="divide-y divide-border/70"><div className="flex items-start justify-between gap-6 p-5"><div><div className="text-sm font-bold">Delete firmware after analysis</div><div className="mt-1 max-w-lg text-xs leading-5 text-muted-foreground">Original firmware and extracted contents are automatically deleted after the report is generated. Only metadata, findings, and reports remain.</div></div><span className="mt-1 inline-flex h-6 items-center rounded-full bg-accent px-3 mono text-[9px] font-bold uppercase tracking-[.12em] text-accent-foreground">Required</span></div><div className="flex items-start justify-between gap-6 p-5"><div><div className="text-sm font-bold">Share anonymous telemetry</div><div className="mt-1 max-w-lg text-xs leading-5 text-muted-foreground">Help improve detection coverage by sharing aggregate, non-content usage signals.</div></div><button onClick={() => setTelemetry(!telemetry)} role="switch" aria-checked={telemetry} className={cx('relative mt-1 h-6 w-11 shrink-0 rounded-full transition-colors', telemetry ? 'bg-accent' : 'bg-muted')} data-testid="switch-telemetry"><span className={cx('absolute left-1 top-1 size-4 rounded-full bg-white shadow-sm transition-transform', telemetry ? 'translate-x-5' : 'translate-x-0')} /></button></div></div></section>
     <section className="rounded-xl border border-border bg-card shadow-xs" data-testid="analysis-settings"><div className="border-b border-border/70 p-5"><div className="flex items-center gap-2"><SlidersHorizontal className="size-4 text-primary" /><h2 className="font-serif text-lg font-bold">Analysis capabilities</h2></div><p className="mt-1 text-xs text-muted-foreground">Choose how much context the analyzer should collect by default.</p></div><div className="flex items-start justify-between gap-6 p-5"><div><div className="text-sm font-bold">Deep static analysis</div><div className="mt-1 max-w-lg text-xs leading-5 text-muted-foreground">Inspect strings, permissions, executable metadata, and configuration artifacts beyond the first extraction layer.</div></div><button onClick={() => setDeepAnalysis(!deepAnalysis)} role="switch" aria-checked={deepAnalysis} className={cx('relative mt-1 h-6 w-11 shrink-0 rounded-full transition-colors', deepAnalysis ? 'bg-accent' : 'bg-muted')} data-testid="switch-deep-analysis"><span className={cx('absolute left-1 top-1 size-4 rounded-full bg-white shadow-sm transition-transform', deepAnalysis ? 'translate-x-5' : 'translate-x-0')} /></button></div></section></div>
      <aside className="space-y-4"><div className="rounded-xl border border-border bg-sidebar p-5 text-sidebar-foreground" data-testid="account-card"><div className="mono text-[9px] uppercase tracking-[.18em] text-sidebar-foreground/45">Current account</div><div className="mt-5 flex items-center gap-3"><div className="flex size-11 items-center justify-center rounded-full bg-primary text-sm font-extrabold text-primary-foreground">{initials(session.data?.user?.name)}</div><div><div className="text-sm font-bold">{session.data?.user?.name || 'Workspace user'}</div><div className="mt-1 text-xs text-sidebar-foreground/45">{session.data?.user?.email || 'Session details unavailable'}</div></div></div><div className="mt-5 flex items-center justify-between border-t border-sidebar-border pt-4"><span className="text-xs text-sidebar-foreground/50">Role</span><span className="rounded-full bg-sidebar-accent px-2 py-1 mono text-[9px] uppercase tracking-[.12em] text-sidebar-foreground/75">{session.data?.user?.role?.replace('_', ' ') || 'analyst'}</span></div><ChangePasswordForm /></div><div className="rounded-xl border border-border bg-secondary/55 p-5" data-testid="settings-guidance"><div className="flex items-center gap-2 text-secondary-foreground"><ShieldCheck className="size-4" /><span className="mono text-[9px] uppercase tracking-[.16em]">A note on safety</span></div><p className="mt-3 text-xs leading-5 text-secondary-foreground/75">SENTRY/OS does not execute firmware or make a malware verdict. It surfaces reviewable static signals to support a decision.</p></div></aside></div>
  </div>;
}

function useAdminFetch<T>(path: string, enabled: boolean) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState(false);
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoading(true);
    setError(false);
    fetch(path, { credentials: 'include' })
      .then((response) => { if (!response.ok) throw new Error(String(response.status)); return response.json(); })
      .then((body) => { if (!cancelled) { setData(body); setLoading(false); } })
      .catch(() => { if (!cancelled) { setError(true); setLoading(false); } });
    return () => { cancelled = true; };
  }, [path, enabled, nonce]);
  return { data, loading, error, refetch: () => setNonce((n) => n + 1) };
}

function AdminUsersPanel() {
  const users = useAdminFetch<any[]>('/api/admin/users', true);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ email: '', name: '', password: '', role: 'analyst' });
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const createUser = async () => {
    setBusy(true);
    setFormError(null);
    try {
      const response = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(form),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setFormError(body.error || 'Could not create the account.'); setBusy(false); return; }
      setForm({ email: '', name: '', password: '', role: 'analyst' });
      setCreating(false);
      setBusy(false);
      users.refetch();
    } catch {
      setFormError('Could not reach the server.');
      setBusy(false);
    }
  };

  const updateUser = async (userId: string, patch: Record<string, unknown>) => {
    setActionError(null);
    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(patch),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setActionError(body.error || 'This change could not be applied.'); return; }
      users.refetch();
    } catch {
      setActionError('Could not reach the server.');
    }
  };

  return <section className="rounded-xl border border-border bg-card shadow-xs" data-testid="admin-users-panel">
    <div className="flex items-center justify-between border-b border-border/70 p-5"><div><h2 className="font-serif text-lg font-bold">Users</h2><p className="mt-1 text-xs text-muted-foreground">Accounts that can sign in to this workspace.</p></div><button onClick={() => setCreating(!creating)} className="flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2.5 text-xs font-extrabold text-primary-foreground shadow-xs hover:-translate-y-0.5" data-testid="button-new-user"><UserRound className="size-3.5" />New user</button></div>
    {creating && <div className="space-y-3 border-b border-border/70 bg-muted/20 p-5">
      <div className="grid gap-3 sm:grid-cols-2">
        <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="h-9 rounded-md border border-border bg-background px-3 text-xs outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-new-user-email" />
        <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="h-9 rounded-md border border-border bg-background px-3 text-xs outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-new-user-name" />
        <input type="password" placeholder="Temporary password (12+ chars)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="h-9 rounded-md border border-border bg-background px-3 text-xs outline-none focus:ring-2 focus:ring-accent/20" data-testid="input-new-user-password" />
        <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className="h-9 rounded-md border border-border bg-background px-3 text-xs outline-none focus:ring-2 focus:ring-accent/20" data-testid="select-new-user-role">
          <option value="user">User</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
        </select>
      </div>
      {formError && <p className="text-xs text-destructive" data-testid="text-new-user-error">{formError}</p>}
      <button onClick={() => void createUser()} disabled={busy || !form.email || !form.name || form.password.length < 12} className="rounded-lg bg-primary px-3.5 py-2 text-xs font-extrabold text-primary-foreground disabled:opacity-50" data-testid="button-create-user">{busy ? 'Creating…' : 'Create account'}</button>
    </div>}
    {actionError && <div className="border-b border-border/70 bg-destructive/5 px-5 py-3 text-xs text-destructive" data-testid="text-admin-action-error">{actionError}</div>}
    {users.loading ? <div className="space-y-3 p-5">{[1,2,3].map((n) => <Skeleton key={n} className="h-12" />)}</div>
      : users.error ? <div className="p-5"><ErrorState label="The user list is unavailable." onRetry={users.refetch} /></div>
      : <div className="divide-y divide-border/70">{(users.data || []).map((u: any) => <div key={u.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-4" data-testid={`row-user-${u.id}`}>
          <div className="min-w-0"><div className="flex items-center gap-2 text-sm font-bold">{u.name}{u.disabled && <span className="rounded-full bg-muted px-2 py-0.5 text-[9px] font-bold uppercase text-muted-foreground">Disabled</span>}{u.locked && <span className="rounded-full bg-destructive/10 px-2 py-0.5 text-[9px] font-bold uppercase text-destructive">Locked</span>}</div><div className="truncate text-xs text-muted-foreground">{u.email}</div></div>
          <div className="flex items-center gap-2">
            <select value={u.role} onChange={(e) => void updateUser(u.id, { role: e.target.value })} className="h-8 rounded-md border border-border bg-background px-2 text-xs outline-none" data-testid={`select-role-${u.id}`}>
              <option value="user">User</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
            </select>
            <button onClick={() => void updateUser(u.id, { disabled: !u.disabled })} className={cx('rounded-md border px-2.5 py-1.5 text-[11px] font-bold', u.disabled ? 'border-accent/30 text-accent hover:bg-accent/5' : 'border-destructive/30 text-destructive hover:bg-destructive/5')} data-testid={`button-toggle-disabled-${u.id}`}>{u.disabled ? 'Enable' : 'Disable'}</button>
          </div>
        </div>)}
        {!users.data?.length && <div className="px-6 py-14 text-center text-sm text-muted-foreground">No users found.</div>}
      </div>}
  </section>;
}

function AdminAuditPanel() {
  const audit = useAdminFetch<any[]>('/api/admin/audit?limit=200', true);
  return <section className="rounded-xl border border-border bg-card shadow-xs" data-testid="admin-audit-panel">
    <div className="border-b border-border/70 p-5"><h2 className="font-serif text-lg font-bold">Audit log</h2><p className="mt-1 text-xs text-muted-foreground">Authentication, authorization, and administrative actions across the workspace.</p></div>
    {audit.loading ? <div className="space-y-3 p-5">{[1,2,3,4].map((n) => <Skeleton key={n} className="h-10" />)}</div>
      : audit.error ? <div className="p-5"><ErrorState label="The audit log is unavailable." onRetry={audit.refetch} /></div>
      : <div className="max-h-[560px] overflow-auto"><table className="w-full min-w-[720px] text-left"><thead className="sticky top-0 bg-card mono text-[9px] uppercase tracking-[.15em] text-muted-foreground"><tr><th className="px-5 py-2.5">When</th><th className="px-3 py-2.5">Actor</th><th className="px-3 py-2.5">Action</th><th className="px-3 py-2.5">Resource</th><th className="px-3 py-2.5">Outcome</th><th className="px-5 py-2.5">Detail</th></tr></thead><tbody>{(audit.data || []).map((entry: any) => <tr key={entry.id} className="border-t border-border/60 text-xs" data-testid={`row-audit-${entry.id}`}><td className="whitespace-nowrap px-5 py-2.5 mono text-[10px] text-muted-foreground">{formatDate(entry.createdAt)}</td><td className="px-3 py-2.5">{entry.userEmail || '—'}</td><td className="px-3 py-2.5 font-semibold">{entry.action}</td><td className="px-3 py-2.5 mono text-[10px] text-muted-foreground">{entry.resource || '—'}</td><td className="px-3 py-2.5"><span className={cx('rounded-full px-2 py-0.5 text-[9px] font-bold uppercase', entry.outcome === 'success' ? 'bg-teal-50 text-teal-700' : entry.outcome === 'denied' ? 'bg-destructive/10 text-destructive' : 'bg-amber-50 text-amber-700')}>{entry.outcome}</span></td><td className="max-w-[280px] truncate px-5 py-2.5 text-muted-foreground">{entry.detail || '—'}</td></tr>)}</tbody></table>{!audit.data?.length && <div className="px-6 py-14 text-center text-sm text-muted-foreground">No audit entries yet.</div>}</div>}
  </section>;
}

function AdminStatsPanel() {
  const stats = useAdminFetch<any>('/api/admin/stats', true);
  if (stats.loading) return <div className="space-y-3 p-5">{[1,2,3].map((n) => <Skeleton key={n} className="h-16" />)}</div>;
  if (stats.error || !stats.data) return <ErrorState label="System statistics are unavailable." onRetry={stats.refetch} />;

  const s = stats.data;
  return <div className="space-y-6" data-testid="admin-stats-panel">
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
        <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Total Scans</div>
        <div className="mt-2 font-serif text-3xl font-bold">{s.totalScans}</div>
        <div className="mt-1 text-xs text-muted-foreground">{s.users} registered users</div>
      </div>
      <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
        <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">High / Critical Scans</div>
        <div className="mt-2 font-serif text-3xl font-bold text-red-600">{s.highRiskScans + s.criticalScans}</div>
        <div className="mt-1 text-xs text-muted-foreground">{s.criticalScans} critical, {s.highRiskScans} high</div>
      </div>
      <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
        <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Security Findings</div>
        <div className="mt-2 font-serif text-3xl font-bold">{s.vulnerabilityFindings}</div>
        <div className="mt-1 text-xs text-muted-foreground">{s.cveFindings} matched CVEs</div>
      </div>
      <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
        <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Malware Detections</div>
        <div className="mt-2 font-serif text-3xl font-bold text-amber-600">{(s.yaraMatches || 0) + (s.mlDetections || 0)}</div>
        <div className="mt-1 text-xs text-muted-foreground">{s.yaraMatches || 0} YARA, {s.mlDetections || 0} ML</div>
      </div>
    </div>
    <div className="rounded-xl border border-border bg-card p-5 shadow-xs">
      <div className="flex items-center gap-2">
        <ShieldCheck className="size-4 text-accent" />
        <h3 className="font-serif text-base font-bold">Analysis Engine Status</h3>
      </div>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{s.capabilityNote}</p>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg bg-muted/40 p-3"><div className="text-xs font-bold">YARA Engine</div><div className="mt-1 mono text-[10px] text-teal-600">Active · Rules loaded</div></div>
        <div className="rounded-lg bg-muted/40 p-3"><div className="text-xs font-bold">ML Classifier</div><div className="mt-1 mono text-[10px] text-teal-600">Active · Calibrated model</div></div>
        <div className="rounded-lg bg-muted/40 p-3"><div className="text-xs font-bold">Local CVE Database</div><div className="mt-1 mono text-[10px] text-teal-600">Active · {s.localCveCount} records</div></div>
      </div>
    </div>
  </div>;
}

function AdminCvePanel() {
  const cve = useAdminFetch<any>('/api/admin/cve/status', true);
  const [updating, setUpdating] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const triggerUpdate = async () => {
    setUpdating(true);
    setMsg(null);
    try {
      const res = await fetch('/api/admin/cve/update', { method: 'POST', credentials: 'include' });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setMsg(data.message || 'Synchronization initiated.');
        window.setTimeout(() => cve.refetch(), 3000);
      } else {
        setMsg('Failed to trigger update.');
      }
    } catch {
      setMsg('Network error.');
    } finally {
      setUpdating(false);
    }
  };

  return <section className="rounded-xl border border-border bg-card shadow-xs" data-testid="admin-cve-panel">
    <div className="flex flex-col justify-between gap-3 border-b border-border/70 p-5 sm:flex-row sm:items-center">
      <div>
        <h2 className="font-serif text-lg font-bold">Vulnerability Database (CVE)</h2>
        <p className="mt-1 text-xs text-muted-foreground">Manage local offline CVE records and trigger upstream database synchronization.</p>
      </div>
      <button onClick={() => void triggerUpdate()} disabled={updating} className="flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2.5 text-xs font-extrabold text-primary-foreground shadow-xs hover:-translate-y-0.5 disabled:opacity-50" data-testid="button-sync-cve">
        <RefreshCw className={cx("size-3.5", updating && "animate-spin")} />
        {updating ? 'Updating…' : 'Sync CVE Database'}
      </button>
    </div>
    {msg && <div className="border-b border-border/70 bg-teal-50 px-5 py-2.5 text-xs font-semibold text-teal-800">{msg}</div>}
    {cve.loading ? <div className="space-y-3 p-5">{[1,2].map((n) => <Skeleton key={n} className="h-12" />)}</div>
      : cve.error ? <div className="p-5"><ErrorState label="CVE database status is unavailable." onRetry={cve.refetch} /></div>
      : <div className="p-5 space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg bg-muted/40 p-4">
              <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Total Local Records</div>
              <div className="mt-1 font-serif text-2xl font-bold">{cve.data?.totalCount ?? 0}</div>
            </div>
            <div className="rounded-lg bg-muted/40 p-4">
              <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Status</div>
              <div className="mt-1 text-sm font-bold capitalize text-teal-700">{cve.data?.status ?? 'idle'}</div>
            </div>
            <div className="rounded-lg bg-muted/40 p-4">
              <div className="mono text-[9px] uppercase tracking-[.15em] text-muted-foreground">Last Updated</div>
              <div className="mt-1 mono text-xs text-muted-foreground">{cve.data?.lastUpdatedAt ? formatDate(cve.data.lastUpdatedAt) : 'Never'}</div>
            </div>
          </div>
          <div className="rounded-lg border border-border/60 bg-muted/20 p-4">
            <div className="text-xs font-bold">Latest Sync Message</div>
            <p className="mt-1 text-xs text-muted-foreground">{cve.data?.lastMessage || 'Baseline initialized.'}</p>
          </div>
        </div>}
  </section>;
}

function AdminPage() {
  const session = useGetSession({ query: { queryKey: getGetSessionQueryKey() } });
  const [tab, setTab] = useState<'overview' | 'users' | 'cve' | 'audit'>('overview');
  const permissions: string[] = session.data?.permissions || [];
  if (!session.isLoading && !permissions.includes('user:manage')) {
    return <div className="page-enter"><ErrorState label="You do not have permission to view this page." /></div>;
  }
  return <div className="page-enter"><PageTitle eyebrow="Workspace administration" title="Admin" description="Manage system security engines, accounts, and review the authorization audit trail." />
    <div className="mb-6 flex flex-wrap gap-2 rounded-lg border border-border bg-card p-1 w-fit">
      <button onClick={() => setTab('overview')} className={cx('rounded-md px-3.5 py-2 text-xs font-bold', tab === 'overview' ? 'bg-sidebar text-sidebar-foreground' : 'text-muted-foreground hover:bg-muted')} data-testid="tab-admin-overview">Overview</button>
      <button onClick={() => setTab('users')} className={cx('rounded-md px-3.5 py-2 text-xs font-bold', tab === 'users' ? 'bg-sidebar text-sidebar-foreground' : 'text-muted-foreground hover:bg-muted')} data-testid="tab-admin-users">Users</button>
      <button onClick={() => setTab('cve')} className={cx('rounded-md px-3.5 py-2 text-xs font-bold', tab === 'cve' ? 'bg-sidebar text-sidebar-foreground' : 'text-muted-foreground hover:bg-muted')} data-testid="tab-admin-cve">CVE Database</button>
      <button onClick={() => setTab('audit')} className={cx('rounded-md px-3.5 py-2 text-xs font-bold', tab === 'audit' ? 'bg-sidebar text-sidebar-foreground' : 'text-muted-foreground hover:bg-muted')} data-testid="tab-admin-audit">Audit log</button>
    </div>
    {tab === 'overview' && <AdminStatsPanel />}
    {tab === 'users' && <AdminUsersPanel />}
    {tab === 'cve' && <AdminCvePanel />}
    {tab === 'audit' && <AdminAuditPanel />}
  </div>;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function Router() {
  return <RoutedErrorBoundary><Shell><Switch><Route path="/" component={Dashboard} /><Route path="/scans/:scanId" component={DetailPage} /><Route path="/history" component={HistoryPage} /><Route path="/settings" component={SettingsPage} /><Route path="/admin" component={AdminPage} /><Route component={NotFound} /></Switch></Shell></RoutedErrorBoundary>;
}

function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Router /></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider>;
}

export default App;