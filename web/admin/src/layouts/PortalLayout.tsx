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
import { useAuth } from '../hooks/useAuth';

const PortalLayout = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const { logout } = useAuth(); // Assuming useAuth exposes basic user info/logout

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
                        {/* Admin Switcher (If authorized - TODO: Check Role) */}
                        <Button variant="ghost" size="sm" className="hidden md:flex gap-2" onClick={() => navigate('/dashboard')}>
                            <ShieldCheck className="w-4 h-4" />
                            <span className="text-xs">Admin Console</span>
                        </Button>

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
                                <DropdownMenuItem onClick={() => navigate('/dashboard')}>
                                    Switch to Admin
                                </DropdownMenuItem>
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
            </footer>
        </div>
    );
};

export default PortalLayout;
