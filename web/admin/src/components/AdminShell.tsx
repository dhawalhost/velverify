import React, { useState } from 'react';
import { Link, useLocation, useNavigate, Outlet } from 'react-router-dom';
import {
    LayoutDashboard,
    Target,
    ShieldCheck,
    KeyRound,
    Plug,
    FileText,
    Code2,
    Activity,
    Fingerprint,
    Palette,
    Webhook,
    Smartphone,
    ShieldAlert,
    Building2,
    LogOut,
    ChevronRight,
    Search,
    Bell,
    Users as UsersIcon,
    Slack,
    Share2,
    Database,
    ClipboardList,
    ChevronDown,
    Sparkles,
    Globe,
    Lock,
    Layers,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
import { ModeToggle } from '@/components/mode-toggle';
import { Toaster } from '@/components/ui/toaster';
import CopilotWidget from './CopilotWidget';

interface NavItem {
    path: string;
    label: string;
    icon: React.ElementType;
    badge?: string;
}

interface NavSection {
    key: string;
    label: string;
    icon: React.ElementType;
    items: NavItem[];
}

const navSections: NavSection[] = [
    {
        key: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        items: [
            { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
            { path: '/copilot', label: 'AI Copilot', icon: Sparkles, badge: 'AI' },
        ],
    },
    {
        key: 'directory',
        label: 'Directory',
        icon: UsersIcon,
        items: [
            { path: '/users', label: 'Users', icon: UsersIcon },
            { path: '/groups', label: 'Groups', icon: Layers },
            { path: '/roles', label: 'Roles & Permissions', icon: ShieldCheck },
            { path: '/organizations', label: 'Organizations', icon: Building2 },
            { path: '/requests', label: 'Access Requests', icon: ClipboardList },
        ],
    },
    {
        key: 'security',
        label: 'Security',
        icon: ShieldAlert,
        items: [
            { path: '/safety', label: 'Security Alerts', icon: ShieldAlert },
            { path: '/discovery', label: 'Discovery', icon: Search },
            { path: '/policies', label: 'Security Policies', icon: Lock },
            { path: '/policies/ip', label: 'IP Access Policies', icon: Globe },
            { path: '/mfa', label: 'MFA Setup', icon: ShieldCheck },
            { path: '/devices', label: 'Devices', icon: Smartphone },
            { path: '/passkeys', label: 'Passkeys', icon: Fingerprint },
        ],
    },
    {
        key: 'applications',
        label: 'Applications',
        icon: Code2,
        items: [
            { path: '/sso', label: 'Single Sign-On', icon: KeyRound },
            { path: '/connectors', label: 'Connectors', icon: Plug },
            { path: '/apps', label: 'Applications', icon: Code2 },
            { path: '/webhooks', label: 'Webhooks', icon: Webhook },
            { path: '/integrations/slack', label: 'Slack', icon: Slack },
            { path: '/campaigns', label: 'Access Reviews', icon: Target },
            { path: '/workloads', label: 'Machine Accounts', icon: Database },
            { path: '/graph-explorer', label: 'Access Map', icon: Share2 },
        ],
    },
    {
        key: 'platform',
        label: 'Platform',
        icon: Palette,
        items: [
            { path: '/branding', label: 'Branding', icon: Palette },
            { path: '/audit', label: 'Audit Logs', icon: FileText },
        ],
    },
];

// Sections open by default
const DEFAULT_OPEN = ['overview', 'directory', 'security'];

const AdminShell: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();

    const [openSections, setOpenSections] = useState<string[]>(DEFAULT_OPEN);

    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';

    // Determine which section contains the active path and auto-expand it
    const activeSectionKey = navSections.find(s =>
        s.items.some(i => location.pathname.startsWith(i.path))
    )?.key;

    React.useEffect(() => {
        if (activeSectionKey && !openSections.includes(activeSectionKey)) {
            setOpenSections(prev => [...prev, activeSectionKey]);
        }
    }, [activeSectionKey]);

    const toggleSection = (key: string) => {
        setOpenSections(prev =>
            prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
        );
    };

    const isItemActive = (path: string) => location.pathname.startsWith(path);

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    const [userName, setUserName] = React.useState(
        localStorage.getItem('userName') || localStorage.getItem('userId') || 'User'
    );

    React.useEffect(() => {
        const fetchProfile = async () => {
            try {
                const { api } = await import('@/api');
                const res = await api.get('/api/v1/user/profile');
                if (res.data?.name) {
                    setUserName(res.data.name);
                    localStorage.setItem('userName', res.data.name);
                } else if (res.data?.email) {
                    setUserName(res.data.email);
                    localStorage.setItem('userName', res.data.email);
                }
            } catch (err) {
                console.error('Failed to fetch profile in AdminShell', err);
            }
        };
        fetchProfile();
    }, []);

    const [systemsHealthy, setSystemsHealthy] = React.useState<boolean | null>(null);

    React.useEffect(() => {
        const checkHealth = async () => {
            const isLocal = window.location.hostname.endsWith('.local') || window.location.hostname === 'localhost';
            const domain = isLocal ? 'wardseal.local' : 'wardseal.com';
            const protocol = isLocal ? 'http' : 'https';

            const authUrl = `${protocol}://auth.${domain}/healthz`;
            const apiUrl = `${protocol}://api.${domain}`;

            const endpoints = [
                authUrl,
                `${apiUrl}/gov/healthz`,
                `${apiUrl}/provisioning/healthz`,
                `${apiUrl}/policy/healthz`,
                `${apiUrl}/scim/healthz`
            ];

            try {
                const results = await Promise.all(
                    endpoints.map(async (url) => {
                        try {
                            const res = await fetch(url, { method: 'GET' });
                            return res.ok;
                        } catch {
                            return false;
                        }
                    })
                );
                const allHealthy = results.every(status => status === true);
                setSystemsHealthy(allHealthy);
            } catch (err) {
                setSystemsHealthy(false);
            }
        };

        checkHealth();
        const interval = setInterval(checkHealth, 30000);
        return () => clearInterval(interval);
    }, []);


    const userInitials = (userName || 'U').substring(0, 2).toUpperCase();
    const userId = localStorage.getItem('userId') || 'User';
    const tenantId = localStorage.getItem('tenantID') || 'Default Tenant';

    // Find active item label for breadcrumb
    const activeItem = navSections
        .flatMap(s => s.items)
        .find(i => location.pathname.startsWith(i.path));

    const activeSection = navSections.find(s =>
        s.items.some(i => location.pathname.startsWith(i.path))
    );

    return (
        <div className="flex min-h-screen font-sans bg-background selection:bg-primary/10 selection:text-primary">
            {/* ── Sidebar ───────────────────────────────────────────────── */}
            <aside className="w-64 border-r border-on-surface/5 bg-card flex flex-col fixed inset-y-0 z-50">

                {/* Logo */}
                <div className="h-16 flex items-center px-5 border-b border-on-surface/5 shrink-0">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 flex items-center justify-center rounded-lg bg-primary/10">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-5 h-5" />
                        </div>
                        <div>
                            <span className="font-bold text-sm tracking-tight text-on-surface">WardSeal</span>
                            <div className="text-[9px] font-bold text-on-surface-variant/30 tracking-widest uppercase leading-none mt-0.5">Admin Console</div>
                        </div>
                    </div>
                </div>

                {/* Nav */}
                <nav className="flex-1 overflow-y-auto py-4 custom-scrollbar">
                    {navSections.map((section) => {
                        const isOpen = openSections.includes(section.key);
                        const SectionIcon = section.icon;
                        const hasActiveChild = section.items.some(i => isItemActive(i.path));

                        return (
                            <div key={section.key} className="mb-1">
                                {/* Section header */}
                                <button
                                    onClick={() => toggleSection(section.key)}
                                    className={cn(
                                        "w-full flex items-center justify-between px-4 py-2 mx-2 rounded-lg transition-all duration-200 group",
                                        "hover:bg-surface-container/50",
                                        hasActiveChild && !isOpen && "text-primary"
                                    )}
                                    style={{ width: 'calc(100% - 16px)' }}
                                >
                                    <div className="flex items-center gap-2.5">
                                        <SectionIcon className={cn(
                                            "w-3.5 h-3.5 transition-colors",
                                            hasActiveChild ? "text-primary" : "text-on-surface-variant/40 group-hover:text-on-surface-variant"
                                        )} />
                                        <span className={cn(
                                            "text-[11px] font-bold tracking-wider uppercase transition-colors",
                                            hasActiveChild ? "text-primary" : "text-on-surface-variant/40 group-hover:text-on-surface-variant"
                                        )}>
                                            {section.label}
                                        </span>
                                    </div>
                                    <ChevronDown className={cn(
                                        "w-3 h-3 text-on-surface-variant/30 transition-transform duration-200",
                                        isOpen && "rotate-180"
                                    )} />
                                </button>

                                {/* Section items */}
                                <div className={cn(
                                    "overflow-hidden transition-all duration-200",
                                    isOpen ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0"
                                )}>
                                    <div className="px-2 pb-1 space-y-0.5">
                                        {section.items.map((item) => {
                                            const active = isItemActive(item.path);
                                            const Icon = item.icon;
                                            return (
                                                <Link
                                                    key={item.path}
                                                    to={item.path}
                                                    className={cn(
                                                        "flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150 group relative",
                                                        active
                                                            ? "bg-primary/10 text-primary"
                                                            : "text-on-surface-variant hover:bg-surface-container/60 hover:text-on-surface"
                                                    )}
                                                >
                                                    {/* Active indicator bar */}
                                                    {active && (
                                                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-primary rounded-full" />
                                                    )}
                                                    <Icon className={cn(
                                                        "w-4 h-4 shrink-0 transition-colors",
                                                        active ? "text-primary" : "opacity-40 group-hover:opacity-70"
                                                    )} />
                                                    <span className={cn(
                                                        "text-[13px] transition-colors flex-1 truncate",
                                                        active ? "font-semibold" : "font-medium"
                                                    )}>
                                                        {item.label}
                                                    </span>
                                                    {item.badge && (
                                                        <span className="text-[8px] font-bold tracking-widest bg-primary/10 text-primary px-1.5 py-0.5 rounded-md">
                                                            {item.badge}
                                                        </span>
                                                    )}
                                                </Link>
                                            );
                                        })}
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </nav>

                {/* User footer */}
                <div className="p-3 border-t border-on-surface/5 bg-surface-container-low/20 shrink-0">
                    <div
                        className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-surface-container/60 cursor-pointer group transition-all"
                        onClick={handleLogout}
                        title="Click to sign out"
                    >
                        <Avatar className="h-8 w-8 border border-on-surface/5 shadow-sm shrink-0">
                            <BoringAvatar
                                size={32}
                                name={userId}
                                variant="marble"
                                colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                            />
                        </Avatar>
                        <div className="flex-1 min-w-0">
                            <p className="text-[13px] font-semibold text-on-surface truncate leading-tight">
                                {userName}
                            </p>
                            <p className="text-[10px] text-on-surface-variant/40 truncate leading-tight mt-0.5">
                                {tenantId}
                            </p>
                        </div>
                        <LogOut className="w-3.5 h-3.5 text-on-surface-variant/30 group-hover:text-destructive transition-colors shrink-0" />
                    </div>
                </div>
            </aside>

            {/* ── Main content ──────────────────────────────────────────── */}
            <main className="flex-1 ml-64 h-screen flex flex-col bg-surface overflow-hidden">

                {/* Top bar */}
                <header className="h-16 border-b border-on-surface/5 bg-card/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-8">
                    {/* Breadcrumb */}
                    <nav className="flex items-center gap-1.5 text-sm">
                        <span className="text-on-surface-variant/30 font-medium text-[13px]">
                            {activeSection?.label || 'Overview'}
                        </span>
                        <ChevronRight className="w-3.5 h-3.5 text-on-surface-variant/20" />
                        <span className="text-on-surface font-semibold text-[13px]">
                            {activeItem?.label || 'Dashboard'}
                        </span>
                    </nav>

                    {/* Actions */}
                    <div className="flex items-center gap-3">
                        {/* Global search */}
                        <div className="relative hidden lg:block group">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                            <Input
                                type="search"
                                placeholder="Search..."
                                className="w-56 bg-surface-container border-none rounded-lg pl-9 h-9 text-[13px] focus-visible:ring-1 focus-visible:ring-primary/20 transition-all font-medium placeholder:text-on-surface-variant/30"
                            />
                            <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-[9px] font-bold text-on-surface-variant/20 bg-surface-container px-1.5 py-0.5 rounded border border-on-surface/5">
                                ⌘K
                            </kbd>
                        </div>

                        {/* User portal link */}
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                                const appUrl = window.location.hostname.endsWith('.local')
                                    ? 'http://app.wardseal.local'
                                    : 'https://app.wardseal.com';
                                window.location.assign(appUrl);
                            }}
                            className="rounded-lg font-semibold text-[12px] px-4 h-9 border-on-surface/8 hover:bg-surface-container transition-all hidden md:flex"
                        >
                            <Activity className="mr-1.5 h-3.5 w-3.5 text-primary" />
                            User Portal
                        </Button>

                        {/* Notifications */}
                        <Button variant="ghost" size="icon" className="h-9 w-9 rounded-lg relative hover:bg-surface-container">
                            <Bell className="w-4 h-4 text-on-surface-variant/60" />
                            <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-destructive rounded-full" />
                        </Button>

                        <ModeToggle />
                    </div>
                </header>

                {/* Page content — no padding here; pages own their layout */}
                <div className="flex-1 overflow-hidden flex flex-col min-h-0">
                    <Outlet />
                </div>

                {/* Footer */}
                <footer className="border-t border-on-surface/5 py-5 px-8 bg-card/50">
                    <div className="max-w-[1600px] mx-auto flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2 text-[11px] font-semibold text-on-surface-variant/40">
                                <div className={cn(
                                    "w-1.5 h-1.5 rounded-full",
                                    systemsHealthy === null ? "bg-on-surface-variant/20 animate-pulse" :
                                    systemsHealthy ? "bg-success animate-pulse" : "bg-destructive animate-ping"
                                )} />
                                {systemsHealthy === null ? "Checking system status..." :
                                 systemsHealthy ? "All systems operational" : "Degraded performance"}
                            </div>

                            <span className="text-[10px] font-bold text-on-surface-variant/20">v4.2.0</span>
                        </div>
                        <div className="flex items-center gap-6 text-[11px] font-semibold text-on-surface-variant/40">
                            <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Privacy</a>
                            <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Security</a>
                            <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Compliance</a>
                        </div>
                    </div>
                </footer>
            </main>

            <Toaster />
            <CopilotWidget />
        </div>
    );
};

export default AdminShell;
