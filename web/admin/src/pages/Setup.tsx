import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { performSetup, getSetupStatus } from '../api';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, CheckCircle, Shield, ShieldCheck, Loader2, Key, Command, Package } from "lucide-react";
import { 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';

const Setup: React.FC = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [checking, setChecking] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const checkStatus = async () => {
            try {
                const status = await getSetupStatus();
                if (!status.setup_required) {
                    navigate('/login');
                }
            } catch (err) {
                console.error("Failed to check setup status", err);
            } finally {
                setChecking(false);
            }
        };
        checkStatus();
    }, [navigate]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError("Entropy mismatch detected.");
            return;
        }

        if (password.length < 8) {
            setError("Seed entropy must be at least 8 segments.");
            return;
        }

        setLoading(true);
        try {
            const resp = await performSetup(email, password);
            localStorage.setItem('token', resp.token);
            localStorage.setItem('tenantID', resp.tenant_id || 'admin-system');
            localStorage.setItem('tenantSlug', resp.tenant_slug || 'admin');

            navigate('/dashboard');
        } catch (err: any) {
            setError(err.response?.data?.error || "Provisioning sequence failed.");
        } finally {
            setLoading(false);
        }
    };

    if (checking) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="animate-in fade-in duration-1000 flex flex-col items-center gap-6">
                    <div className="h-16 w-16 bg-primary/5 rounded-[2rem] flex items-center justify-center border border-primary/20 animate-pulse">
                        <Command className="w-8 h-8 text-primary/40" />
                    </div>
                    <p className="text-[10px] font-black uppercase tracking-[0.4em] text-on-surface-variant/30 italic">Pinging_Logic_Core...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex items-center justify-center min-h-screen bg-background px-6 py-12 transition-all duration-700">
            <div className="w-full max-w-[420px] space-y-12 animate-in fade-in zoom-in-95 duration-700">
                <div className="text-center space-y-6">
                    <div className="flex justify-center">
                        <div className="w-16 h-16 bg-primary rounded-[2rem] flex items-center justify-center shadow-2xl shadow-primary/30">
                            <ShieldCheck className="w-8 h-8 text-white" />
                        </div>
                    </div>
                </div>

                <GlassCard className="border-none shadow-2xl bg-card overflow-hidden">
                    <GlassCardHeader className="pt-12 pb-6 px-10 text-center">
                        <GlassCardTitle className="text-4xl font-black italic tracking-tighter leading-none">SYSTEM_GENESIS</GlassCardTitle>
                        <div className="h-1 w-12 bg-primary mx-auto mt-6 mb-4 rounded-full" />
                        <GlassCardDescription className="text-[10px] font-bold uppercase tracking-[0.2em] opacity-40">Initialize Cluster Authority</GlassCardDescription>
                    </GlassCardHeader>
                    <form onSubmit={handleSubmit}>
                        <GlassCardContent className="px-10 pb-12 space-y-8">
                            {error && (
                                <div className="p-4 bg-destructive/10 text-destructive rounded-xl flex items-center gap-3 border border-destructive/20 animate-in fade-in slide-in-from-top-2">
                                    <AlertCircle className="h-5 w-5 shrink-0" />
                                    <span className="text-xs font-bold uppercase tracking-tight">{error}</span>
                                </div>
                            )}

                            <div className="space-y-4">
                                <Label htmlFor="email" className="text-[10px] font-black uppercase tracking-[0.3em] text-on-surface-variant/40 italic ml-1">01 // Root_Identifier</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="ADMIN@ARCHITECTURE"
                                    className="h-14 rounded-2xl bg-surface-container/30 border-none font-bold text-sm tracking-tight placeholder:opacity-20 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                    disabled={loading}
                                />
                            </div>
                            
                            <div className="space-y-4">
                                <Label htmlFor="password" className="text-[10px] font-black uppercase tracking-[0.3em] text-on-surface-variant/40 italic ml-1">02 // Secure_Entropy</Label>
                                <div className="relative group">
                                    <Key className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-on-surface-variant/20 group-focus-within:text-primary transition-colors" />
                                    <Input
                                        id="password"
                                        type="password"
                                        placeholder="MIN_8_SEGMENTS"
                                        className="h-14 pl-12 rounded-2xl bg-surface-container/30 border-none font-bold text-sm tracking-widest focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        disabled={loading}
                                    />
                                </div>
                            </div>

                            <div className="space-y-4">
                                <Label htmlFor="confirmPassword" className="text-[10px] font-black uppercase tracking-[0.3em] text-on-surface-variant/40 italic ml-1">03 // Verification_Seed</Label>
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    placeholder="RE-COMMIT_SEED"
                                    className="h-14 rounded-2xl bg-surface-container/30 border-none font-bold text-sm tracking-widest focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                    disabled={loading}
                                />
                            </div>

                            <div className="pt-4 space-y-6">
                                <Button type="submit" className="w-full h-14 rounded-2xl font-black text-xs uppercase tracking-widest shadow-lg shadow-on-surface/10 bg-inverse text-on-inverse hover:opacity-90 transition-all" disabled={loading}>
                                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "COMPLETE_PROVISIONING"}
                                </Button>
                                
                                <div className="flex flex-col items-center gap-4 text-center">
                                     <div className="flex items-center gap-2 px-3 py-1 bg-success-subtle rounded-full border border-success/10">
                                         <div className="w-1.5 h-1.5 bg-success rounded-full animate-pulse" />
                                         <span className="text-[9px] font-black uppercase tracking-widest text-success">PROVISION_LEVEL_0</span>
                                     </div>
                                     <p className="text-[10px] font-bold text-on-surface-variant/30 uppercase tracking-[0.2em] leading-relaxed max-w-[200px]">
                                        Full administrative authority will be committed to this node.
                                     </p>
                                </div>
                            </div>
                        </GlassCardContent>
                    </form>
                </GlassCard>
            </div>
        </div>
    );
};

export default Setup;
