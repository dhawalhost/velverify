import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { logout as apiLogout } from '../api';
import { GlassCard, GlassCardContent } from '@/components/layout';
import { Loader2, LogOut } from 'lucide-react';

const Logout: React.FC = () => {
    const navigate = useNavigate();

    useEffect(() => {
        const performLogout = async () => {
            try {
                // 1. Call backend logout to clear cookies
                await apiLogout();
            } catch (err) {
                console.error("Backend logout failed", err);
            } finally {
                // 2. Clear local state
                localStorage.clear();
                sessionStorage.clear();

                // 3. Wait a bit and redirect to login
                setTimeout(() => {
                    navigate('/login');
                }, 1500);
            }
        };

        performLogout();
    }, [navigate]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-surface p-4">
            <GlassCard className="max-w-md w-full">
                <GlassCardContent className="pt-12 pb-12 flex flex-col items-center text-center">
                    <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-6">
                        <LogOut className="w-8 h-8 text-primary" />
                    </div>
                    <h1 className="text-2xl font-bold text-on-surface mb-2">Logging you out</h1>
                    <p className="text-on-surface-variant mb-8">Please wait while we secure your session...</p>
                    <Loader2 className="w-6 h-6 animate-spin text-primary/60" />
                </GlassCardContent>
            </GlassCard>
        </div>
    );
};

export default Logout;
