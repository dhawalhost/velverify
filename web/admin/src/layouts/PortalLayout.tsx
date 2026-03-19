import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { ModeToggle } from "@/components/mode-toggle";
import { LayoutGrid, User, ShieldCheck, LogOut } from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getUserRoles } from '../api';
import { useAuth } from '../hooks/useAuth';

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
                const response = await getUserRoles(userID);
                const roles = Array.isArray(response?.roles) ? response.roles : [];
                const roleNames = roles
                    .map((role: RBACRole | string) => (typeof role === 'string' ? role : role?.name))
                    .filter((name): name is string => typeof name === 'string');

                if (mounted) {
                    setCanAccessAdmin(roleNames.some((role) => role.toLowerCase() === ADMIN_ROLE));
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
        <div className="min-h-screen bg-background flex flex-col font-sans">
            {/* Top Navigation Bar */}
            <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <div className="container mx-auto px-4 h-16 flex items-center justify-between">
                    {/* Logo Area */}
                    <div className="flex items-center gap-2">
                        <Link to="/portal" className="flex items-center gap-2">
                            <div className="bg-primary/10 p-1.5 rounded-lg">
                                <img src="/wardseal.svg" alt="App Logo" className="w-5 h-5" />
                            </div>
                            <span className="font-semibold text-lg tracking-tight hidden sm:inline-block">My Apps</span>
                        </Link>
                    </div>

                    {/* Right Actions */}
                    <div className="flex items-center gap-4">
                        {canAccessAdmin && (
                            <Button variant="ghost" size="sm" className="hidden md:flex gap-2" onClick={() => navigate('/dashboard')}>
                                <ShieldCheck className="w-4 h-4" />
                                <span className="text-xs">Admin Console</span>
                            </Button>
                        )}

                        <ModeToggle />

                        {/* User Menu */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="rounded-full relative">
                                    <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                                        <User className="w-4 h-4 text-primary" />
                                    </div>
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-56">
                                <DropdownMenuLabel>My Account</DropdownMenuLabel>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem onClick={() => navigate('/portal/profile')}>
                                    Profile Settings
                                </DropdownMenuItem>
                                {canAccessAdmin && (
                                    <DropdownMenuItem onClick={() => navigate('/dashboard')}>
                                        Switch to Admin
                                    </DropdownMenuItem>
                                )}
                                <DropdownMenuSeparator />
                                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={handleSignOut}>
                                    <LogOut className="mr-2 h-4 w-4" />
                                    <span>Sign out</span>
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </div>
                </div>
            </header>

            {/* Main Content Area */}
            <main className="flex-1 container mx-auto px-4 py-8">
                <Outlet />
            </main>

            <footer className="py-6 border-t border-border/40 text-center text-sm text-muted-foreground">
                <p>Powered by WardSeal Identity</p>
                <p className="mt-2 flex items-center justify-center gap-3 text-xs">
                    <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="hover:text-foreground">Privacy</a>
                    <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="hover:text-foreground">Terms</a>
                    <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="hover:text-foreground">Policies</a>
                </p>
            </footer>
        </div>
    );
};

export default PortalLayout;
