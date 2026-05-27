import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { ModeToggle } from "@/components/mode-toggle";
import { LayoutGrid, User, ShieldCheck, LogOut, Terminal, Activity, Globe } from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import api, { getUserRoles } from '../api';
import { useAuth } from '../hooks/useAuth';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';

const ADMIN_ROLE = 'admin';

type TokenPayload = {
    sub?: string;
    user_id?: string;
    roles?: string[];
    role?: string;
};

type RBACRole = {
    id?: string;
    name?: string;
};

const decodeTokenPayload = (token: string | null): TokenPayload | null => {
    if (!token) return null;
    try {
        const [, payload] = token.split('.');
        if (!payload) return null;

        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        return JSON.parse(atob(padded));
    } catch {
        return null;
    }
};

const getTokenUserID = (token: string | null): string => {
    const payload = decodeTokenPayload(token);
    if (!payload) return '';
    return payload.sub || payload.user_id || '';
};

const PortalLayout = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const { logout } = useAuth();
    const [canAccessAdmin, setCanAccessAdmin] = useState(false);
    const [userName, setUserName] = useState(localStorage.getItem('userName') || "Authorized User");
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';

    useEffect(() => {
        let mounted = true;

        const loadAdminAccess = async () => {
            const token = localStorage.getItem('token');
            const userID = getTokenUserID(token);
            if (!userID) {
                if (mounted) setCanAccessAdmin(false);
                return;
            }

            try {
                const profileRes = await api.get('/api/v1/user/profile');
                if (profileRes.data && profileRes.data.name) {
                    if (mounted) setUserName(profileRes.data.name);
                    localStorage.setItem('userName', profileRes.data.name);
                } else if (profileRes.data && profileRes.data.email) {
                    if (mounted) setUserName(profileRes.data.email);
                    localStorage.setItem('userName', profileRes.data.email);
                }
            } catch (e) {
                console.error("Failed to fetch profile in PortalLayout", e);
            }

            try {
                const response = await getUserRoles(userID);
                const roles = Array.isArray(response?.roles) ? response.roles : [];
                const roleNames = roles
                    .map((role: RBACRole | string) => (typeof role === 'string' ? role : role?.name))
                    .filter((name: any): name is string => typeof name === 'string');

                if (mounted) {
                    setCanAccessAdmin(roleNames.some((role: string) => role.toLowerCase() === ADMIN_ROLE));
                }
            } catch {
                if (mounted) {
                    setCanAccessAdmin(false);
                }
            }
        };

        loadAdminAccess();
        return () => {
            mounted = false;
        };
    }, [location.pathname]);

    const handleSignOut = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="min-h-screen bg-surface flex flex-col font-sans selection:bg-primary/10 selection:text-primary">
            {/* Top Navigation Bar: Modernist */}
            <header className="sticky top-0 z-50 w-full border-b bg-card/80 backdrop-blur-md">
                <div className="container mx-auto px-6 h-16 flex items-center justify-between">
                    {/* Logo Area */}
                    <div className="flex items-center gap-6">
                        <Link to="/portal" className="flex items-center gap-3 group">
                            <div className="w-10 h-10 flex items-center justify-center rounded-full transition-transform group-hover:scale-105">
                                <img src='/wardseal.svg' height={20} width={20} alt='wardseal' className="w-10 h-10" />
                            </div>
                            <div className="flex flex-col">
                                <span className="font-bold text-xl tracking-tight text-on-surface leading-none">WardSeal</span>
                                <span className="text-[10px] font-semibold tracking-tight text-on-surface-variant/50 leading-none mt-0.5">User portal</span>
                            </div>
                        </Link>
                    </div>

                    {/* Right Actions */}
                    <div className="flex items-center gap-6">
                        {canAccessAdmin && (
                            <Button
                                variant="outline"
                                onClick={() => navigate('/dashboard')}
                                className="hidden md:flex gap-2 h-9 border-outline/20 rounded-lg font-semibold text-[11px] px-4 hover:bg-surface-container transition-all"
                            >
                                <ShieldCheck className="w-4 h-4 text-primary" />
                                <span>Admin Panel</span>
                            </Button>
                        )}

                        <div className="flex items-center gap-4">
                            <ModeToggle />

                            {/* User Menu */}
                            <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" className="h-10 w-10 p-0 rounded-full hover:bg-surface-container transition-all">
                                        <Avatar className="h-8 w-8">
                                            <BoringAvatar
                                                size={32}
                                                name={getTokenUserID(localStorage.getItem('token')) || 'user'}
                                                variant="marble"
                                                colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                            />
                                        </Avatar>
                                    </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end" className="w-64 rounded-lg border p-1 shadow-lg overflow-hidden">
                                    <DropdownMenuLabel className="p-4">
                                        <div className="flex flex-col">
                                            <span className="text-[10px] font-bold uppercase tracking-wider text-on-surface-variant/50 mb-1">Authenticated Account</span>
                                            <span className="text-sm font-bold text-on-surface truncate">{userName}</span>
                                        </div>
                                    </DropdownMenuLabel>
                                    <DropdownMenuSeparator />
                                    <div className="p-1 space-y-1">
                                        <DropdownMenuItem
                                            onClick={() => navigate('/portal/profile')}
                                            className="rounded-lg focus:bg-primary/5 focus:text-primary font-medium text-sm px-3 py-2 cursor-pointer"
                                        >
                                            <User className="mr-2 h-4 w-4 opacity-50" />
                                            Profile Settings
                                        </DropdownMenuItem>
                                        {canAccessAdmin && (
                                            <DropdownMenuItem
                                                onClick={() => navigate('/dashboard')}
                                                className="rounded-lg focus:bg-primary/5 focus:text-primary font-medium text-sm px-3 py-2 cursor-pointer"
                                            >
                                                <Terminal className="mr-2 h-4 w-4 opacity-50" />
                                                Switch to Admin
                                            </DropdownMenuItem>
                                        )}
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem
                                            className="rounded-lg focus:bg-destructive/10 focus:text-destructive text-destructive font-medium text-sm px-3 py-2 cursor-pointer"
                                            onClick={handleSignOut}
                                        >
                                            <LogOut className="mr-2 h-4 w-4" />
                                            Sign Out
                                        </DropdownMenuItem>
                                    </div>
                                </DropdownMenuContent>
                            </DropdownMenu>
                        </div>
                    </div>
                </div>
            </header>

            {/* Main Content Area */}
            <main className="flex-1 container mx-auto px-6 py-8 relative">
                {/* Live Status Indicators */}
                <div className="flex items-center justify-between mb-6 border-b pb-4">
                    <div className="flex items-center gap-6">
                        <div className="flex items-center gap-3">
                            <div className="h-2 w-2 bg-success rounded-full animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.4)]" />
                            <span className="text-[11px] font-semibold tracking-tight text-on-surface">Secure connection</span>
                        </div>
                        <div className="flex items-center gap-3 opacity-40">
                            <Activity className="w-3.5 h-3.5" />
                            <span className="text-[11px] font-medium italic">End-to-end encrypted</span>
                        </div>
                    </div>
                    <div className="hidden sm:flex items-center gap-4">
                        <span className="text-[10px] font-bold text-on-surface-variant/40 tracking-tight px-4 border-l italic">WardSeal Identity Platform</span>
                    </div>
                </div>

                <Outlet />
            </main>

            <footer className="border-t py-10 bg-card">
                <div className="container mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6">
                    <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-3">
                            <img src="/wardseal.svg" alt="WardSeal" height={20} width={20} className="w-4 h-4" />
                            <p className="text-[11px] font-bold text-on-surface-variant">Secured by WardSeal</p>
                        </div>
                        <p className="text-[10px] font-medium text-on-surface-variant/40 mt-1">&copy; 2026 WardSeal Managed Security. Identity & Access Platform.</p>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-10">
                        <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-on-surface-variant hover:text-primary transition-colors">Privacy</a>
                        <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-on-surface-variant hover:text-primary transition-colors">Terms</a>
                        <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-on-surface-variant hover:text-primary transition-colors">Security Policies</a>
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default PortalLayout;


