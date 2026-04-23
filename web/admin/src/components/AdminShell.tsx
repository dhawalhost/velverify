import React from 'react';
import { Link, useLocation, useNavigate, Outlet } from 'react-router-dom';
import {
    LayoutDashboard,
    ClipboardList,
    Target,
    ShieldCheck,
    KeyRound,
    Plug,
    FileText,
    Code2,
    Settings,
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
    // UserGroupIcon,
    Share2,
    Database,
    Clock
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Separator } from '@/components/ui/separator';
import { ModeToggle } from '@/components/mode-toggle';
import { Toaster } from '@/components/ui/toaster';

const AdminShell: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';

    const menuItems = [
        { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/requests', label: 'Access Requests', icon: ClipboardList },
        { path: '/discovery', label: 'Discovery', icon: Search },
        { path: '/safety', label: 'Safety Inbox', icon: ShieldAlert },
        { path: '/users', label: 'Users', icon: UsersIcon },
        { path: '/groups', label: 'Identity Groups', icon: ShieldCheck },
        { path: '/roles', label: 'Roles & Permissions', icon: ShieldCheck },
        { path: '/campaigns', label: 'Campaigns', icon: Target },
        { path: '/graph-explorer', label: 'Identity Graph', icon: Share2 },
        { path: '/workloads', label: 'Machine Identities', icon: Database },

        { path: '/organizations', label: 'Organizations', icon: Building2 },
        { path: '/policies', label: 'Security Policies', icon: ShieldCheck },
        { path: '/policies/ip', label: 'IP Access Policies', icon: ShieldAlert },
        { path: '/sso', label: 'SSO Config', icon: KeyRound },
        { path: '/integrations/slack', label: 'Slack Integration', icon: Slack },
        { path: '/connectors', label: 'Connectors', icon: Plug },

        { path: '/mfa', label: 'MFA Setup', icon: ShieldAlert },
        { path: '/devices', label: 'Devices', icon: Smartphone },
        { path: '/passkeys', label: 'Passkeys', icon: Fingerprint },
        { path: '/apps', label: 'Applications', icon: Code2 },
        { path: '/webhooks', label: 'Webhooks', icon: Webhook },
        { path: '/branding', label: 'Branding', icon: Palette },
        { path: '/audit', label: 'Observability', icon: FileText },
    ];

    const activeItem = menuItems.find(i => location.pathname.startsWith(i.path));

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    const userInitials = (localStorage.getItem('userId') || 'U').substring(0, 2).toUpperCase();
    const userId = localStorage.getItem('userId') || 'User';
    const tenantId = localStorage.getItem('tenantID') || 'Default Tenant';

    return (
        <div className="flex min-h-screen font-sans bg-background selection:bg-primary/10 selection:text-primary">
            {/* Sidebar: Modernist */}
            <aside className="w-72 border-r bg-surface-container-lowest flex flex-col fixed inset-y-0 z-50 transition-all duration-300">
                <div className="h-20 flex items-center px-8 border-b shrink-0 bg-white">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 flex items-center justify-center bg-primary rounded-xl shadow-sm">
                            <ShieldCheck className="w-5 h-5 text-white" />
                        </div>
                        <span className="font-bold text-lg tracking-tight text-on-surface">WardSeal</span>
                    </div>
                </div>

                <nav className="flex-1 overflow-y-auto py-8 px-4 space-y-1 custom-scrollbar">
                    <div className="text-[12px] font-bold text-on-surface-variant/40 mb-4 px-4 tracking-tight">Core governance</div>
                    {menuItems.slice(0, 8).map((item) => {
                        const isActive = location.pathname.startsWith(item.path);
                        const Icon = item.icon;
                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className={cn(
                                    "flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group relative",
                                    isActive
                                        ? "bg-primary/5 text-primary"
                                        : "text-on-surface-variant hover:bg-surface-container hover:text-on-surface"
                                )}
                            >
                                <Icon className={cn("w-4.5 h-4.5 transition-colors", isActive ? "text-primary" : "opacity-50 group-hover:opacity-100")} />
                                <span className="text-sm font-medium">{item.label}</span>
                                {isActive && <div className="absolute left-0 w-1 h-5 bg-primary rounded-full -translate-x-1" />}
                            </Link>
                        );
                    })}

                    <div className="h-8" />
                    <div className="text-[12px] font-bold text-on-surface-variant/40 mb-4 px-4 tracking-tight">Infrastructure</div>
                    {menuItems.slice(8).map((item) => {
                        const isActive = location.pathname.startsWith(item.path);
                        const Icon = item.icon;
                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className={cn(
                                    "flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group relative",
                                    isActive
                                        ? "bg-primary/5 text-primary"
                                        : "text-on-surface-variant hover:bg-surface-container hover:text-on-surface"
                                )}
                            >
                                <Icon className={cn("w-4.5 h-4.5 transition-colors", isActive ? "text-primary" : "opacity-50 group-hover:opacity-100")} />
                                <span className="text-sm font-medium">{item.label}</span>
                                {isActive && <div className="absolute left-0 w-1 h-5 bg-primary rounded-full -translate-x-1" />}
                            </Link>
                        );
                    })}
                </nav>

                <div className="p-6 border-t bg-surface-container-low/30">
                    <div className="flex items-center gap-3 group cursor-pointer" onClick={handleLogout}>
                        <Avatar className="h-10 w-10 border shadow-sm transition-transform group-hover:scale-105">
                            <AvatarImage src={`https://avatar.vercel.sh/${userId}`} />
                            <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">{userInitials}</AvatarFallback>
                        </Avatar>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-semibold text-on-surface truncate group-hover:text-primary transition-colors">
                                {userId}
                            </p>
                            <p className="text-xs text-on-surface-variant truncate opacity-60">
                                {tenantId}
                            </p>
                        </div>
                        <LogOut className="w-4 h-4 text-on-surface-variant hover:text-red-500 transition-colors" />
                    </div>
                </div>
            </aside>

            {/* Main Content: Modernist */}
            <main className="flex-1 ml-72 min-h-screen flex flex-col relative bg-surface">
                <header className="h-20 border-b bg-white/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-10">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 text-sm font-medium">
                            <span className="text-on-surface-variant/40">System</span>
                            <ChevronRight className="w-4 h-4 text-on-surface-variant/20" />
                            <span className="text-primary font-semibold">{activeItem?.label || 'Dashboard'}</span>
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        <div className="relative w-72 hidden lg:block group">
                            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                            <Input
                                type="search"
                                placeholder="Universal Search..."
                                className="w-full bg-surface-container border-none rounded-xl pl-10 h-10 text-sm focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium"
                            />
                        </div>

                        <div className="flex gap-3">
                            <Button
                                variant="outline"
                                onClick={() => navigate('/portal')}
                                className="rounded-xl font-semibold text-xs px-5 h-10 border-outline/20 hover:bg-surface-container transition-all"
                            >
                                <Activity className="mr-2 h-4 w-4 text-primary" /> User Portal
                            </Button>

                            <Button variant="ghost" size="icon" className="h-10 w-10 rounded-xl relative hover:bg-surface-container">
                                <Bell className="w-5 h-5 text-on-surface-variant" />
                                <span className="absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full" />
                            </Button>

                            <ModeToggle />
                        </div>
                    </div>
                </header>

                <div className="flex-1 p-10 max-w-[1600px] mx-auto w-full">
                    <Outlet />
                </div>

                <footer className="border-t py-8 px-10 bg-white">
                    <div className="max-w-[1600px] mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
                        <div className="flex items-center gap-6">
                             <div className="py-1.5 px-3 bg-surface-container rounded-full text-on-surface-variant font-bold text-[11px] tracking-tight flex items-center gap-2">
                                <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                                Status: Operational
                            </div>
                            <span className="text-[11px] font-bold text-on-surface-variant/20 italic">v4.2.0-stable</span>
                        </div>
                        <div className="flex items-center gap-8 text-[11px] font-semibold text-on-surface-variant">
                            <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Privacy</a>
                            <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Compliance</a>
                            <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">Security</a>
                        </div>
                    </div>
                </footer>
            </main>
            <Toaster />
        </div>
    );
};

export default AdminShell;
