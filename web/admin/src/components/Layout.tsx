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
    Fingerprint,
    Palette,
    Webhook,
    Smartphone,
    ShieldAlert,
    Building2,
    LogOut,
    ChevronRight,
    Search,
    Bell
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Separator } from '@/components/ui/separator';
import { ModeToggle } from '@/components/mode-toggle';

const Layout: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();

    const menuItems = [
        { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/requests', label: 'Access Requests', icon: ClipboardList },
        { path: '/campaigns', label: 'Campaigns', icon: Target },
        { path: '/roles', label: 'Roles & Permissions', icon: ShieldCheck },
        { path: '/organizations', label: 'Organizations', icon: Building2 },
        { path: '/sso', label: 'SSO Config', icon: KeyRound },
        { path: '/connectors', label: 'Connectors', icon: Plug },
        { path: '/mfa', label: 'MFA Setup', icon: ShieldAlert },
        { path: '/devices', label: 'Devices', icon: Smartphone },
        { path: '/passkeys', label: 'Passkeys', icon: Fingerprint },
        { path: '/apps', label: 'Applications', icon: Code2 },
        { path: '/webhooks', label: 'Webhooks', icon: Webhook },
        { path: '/branding', label: 'Branding', icon: Palette },
        { path: '/audit', label: 'Audit Logs', icon: FileText },
        { path: '/developer', label: 'Developer Portal', icon: Settings },
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
        <div className="flex min-h-screen font-sans bg-muted/20 text-foreground">
            {/* Sidebar */}
            <aside className="w-72 border-r bg-card flex flex-col fixed inset-y-0 z-50 transition-all duration-300">
                <div className="h-16 flex items-center px-6 border-b shrink-0 bg-background/50 backdrop-blur-md">
                    <div className="flex items-center gap-3 font-semibold text-xl tracking-tight text-foreground">
                        <div className="w-8 h-8 flex items-center justify-center">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-8 h-8 object-contain" />
                        </div>
                        <span className="bg-gradient-to-r from-primary to-primary/70 bg-clip-text text-transparent">WardSeal</span>
                    </div>
                </div>

                <nav className="flex-1 overflow-y-auto py-6 px-4 space-y-1">
                    <div className="text-xs font-semibold text-muted-foreground mb-4 px-2 tracking-wider uppercase">Platform</div>
                    {menuItems.slice(0, 5).map((item) => {
                        const isActive = location.pathname.startsWith(item.path);
                        const Icon = item.icon;
                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className={cn(
                                    "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 group",
                                    isActive
                                        ? "bg-primary/10 text-primary shadow-sm"
                                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                )}
                            >
                                <Icon className={cn("w-4 h-4 transition-colors", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                                {item.label}
                            </Link>
                        );
                    })}

                    <Separator className="my-4 mx-2 bg-border/50" />

                    <div className="text-xs font-semibold text-muted-foreground mb-4 px-2 tracking-wider uppercase">Configuration</div>
                    {menuItems.slice(5).map((item) => {
                        const isActive = location.pathname.startsWith(item.path);
                        const Icon = item.icon;
                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className={cn(
                                    "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 group",
                                    isActive
                                        ? "bg-primary/10 text-primary shadow-sm"
                                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                )}
                            >
                                <Icon className={cn("w-4 h-4 transition-colors", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                                {item.label}
                            </Link>
                        );
                    })}
                </nav>

                <div className="p-4 border-t bg-card/50 backdrop-blur-sm">
                    <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer group">
                        <Avatar className="h-9 w-9 border border-border/50">
                            <AvatarImage src={`https://avatar.vercel.sh/${userId}`} />
                            <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">{userInitials}</AvatarFallback>
                        </Avatar>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate group-hover:text-primary transition-colors">
                                {userId}
                            </p>
                            <p className="text-xs text-muted-foreground truncate">
                                {tenantId}
                            </p>
                        </div>
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-full opacity-0 group-hover:opacity-100 transition-all"
                            onClick={(e) => { e.stopPropagation(); handleLogout(); }}
                            title="Sign Out"
                        >
                            <LogOut className="w-4 h-4" />
                        </Button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 ml-72 min-h-screen flex flex-col">
                <header className="h-16 border-b bg-background/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-8 shadow-sm">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <span className="hover:text-foreground transition-colors cursor-pointer">WardSeal</span>
                        <ChevronRight className="w-4 h-4" />
                        <span className="font-medium text-foreground bg-muted/50 px-2 py-0.5 rounded-md">
                            {activeItem?.label || 'Dashboard'}
                        </span>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="relative w-64 hidden md:block">
                            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                            <Input
                                type="search"
                                placeholder="Search resources..."
                                className="w-full bg-muted/40 pl-9 h-9 text-sm focus-visible:ring-primary/20"
                            />
                        </div>
                        <ModeToggle />
                        <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground rounded-full">
                            <Bell className="w-5 h-5" />
                        </Button>
                    </div>
                </header>
                <div className="flex-1 p-8 max-w-[1600px] mx-auto w-full animate-in fade-in duration-500">
                    <Outlet />
                </div>
            </main>
        </div>
    );
};

export default Layout;
