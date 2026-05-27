import React, { useState, useEffect } from 'react';
import {
    PageHeader,
    GlassCard,
    GlassCardHeader,
    GlassCardTitle,
    GlassCardContent,
    GlassCardDescription, PageLayout
} from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Loader2,
    ShieldCheck,
    Smartphone,
    CheckCircle,
    XCircle,
    Trash2,
    ShieldAlert,
    Key,
    Activity,
    QrCode,
    Lock,
    Unlock,
    Info,
    Layout,
    ArrowRight,
    Badge,
    Terminal,
    Plus,
    Binary
} from 'lucide-react';
import { api } from '../api';
import { Alert, AlertDescription } from '@/components/ui/alert';

const MFASetup: React.FC = () => {
    const [enrolling, setEnrolling] = useState(false);
    const [enrolled, setEnrolled] = useState(false);
    const [verified, setVerified] = useState(false);
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [verifyCode, setVerifyCode] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [intel, setIntel] = useState<any>(null);

    const getUserId = () => {
        return localStorage.getItem('userId') || 'admin@wardseal.com';
    };

    const fetchStatus = async () => {
        try {
            const response = await api.get(`/api/v1/mfa/totp/status?user_id=${encodeURIComponent(getUserId())}`);
            setEnrolled(response.data.enrolled);
            setVerified(response.data.verified);
            setIntel(response.data);
        } catch (err) {
            console.error('Failed to fetch TOTP status', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatus();
    }, []);

    const handleEnroll = async () => {
        setEnrolling(true);
        setError('');
        try {
            const response = await api.post('/api/v1/mfa/totp/enroll', { user_id: getUserId() });
            setQrCode(response.data.qr_code);
            setSecret(response.data.secret);
            setEnrolled(true);
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setEnrolling(false);
        }
    };

    const handleVerify = async () => {
        setError('');
        try {
            await api.post('/api/v1/mfa/totp/verify', { user_id: getUserId(), code: verifyCode });
            setVerified(true);
            setQrCode('');
            setSecret('');
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const handleDisable = async () => {
        if (!window.confirm('Are you sure you want to disable TOTP MFA? This reduces your account security.')) return;
        try {
            await api.delete(`/api/v1/mfa/totp?user_id=${encodeURIComponent(getUserId())}`);
            setEnrolled(false);
            setVerified(false);
            setQrCode('');
            setSecret('');
        } catch (err) {
            console.error('Failed to disable TOTP', err);
        }
    };

    if (loading) return (
        <div className="h-[400px] flex flex-col items-center justify-center gap-6">
            <Loader2 className="h-12 w-12 animate-spin text-primary opacity-20" />
            <p className="text-[10px] font-bold uppercase tracking-[0.4em] text-on-surface-variant/20 italic">Resolving Security Profile...</p>
        </div>
    );

    return (
        <PageLayout>
        <div className="max-w-4xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700 py-12">
            <PageHeader
                icon={<Smartphone className="w-10 h-10 text-primary" />}
                title="Identity Entropy"
                description="Harden your authentication handshake with enterprise-grade TOTP multi-factor verification."
                actions={
                    verified ? (
                        <Badge className="bg-success/10 text-success border-none rounded-xl font-bold uppercase text-[9px] tracking-widest px-5 py-2 flex items-center gap-2">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            Profile Hardened
                        </Badge>
                    ) : (
                        <Badge className="bg-amber-500/10 text-amber-600 border-none rounded-xl font-bold uppercase text-[9px] tracking-widest px-5 py-2 flex items-center gap-2">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            Vulnerable State
                        </Badge>
                    )
                }
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                <div className="lg:col-span-8">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[40px]">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/5">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary/10 text-primary rounded-2xl">
                                    <Key className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Authenticator Protocol</GlassCardTitle>
                                    <p className="text-on-surface-variant/60 font-medium uppercase tracking-widest text-[10px] mt-2">Time-Based One-Time Password Implementation</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10">
                            {error && (
                                <Alert variant="destructive" className="mb-10 rounded-2xl border-none bg-destructive/10 text-destructive animate-in slide-in-from-top-2">
                                    <AlertDescription className="font-bold text-xs uppercase tracking-tight flex items-center gap-3">
                                        <XCircle className="w-4 h-4" />
                                        Verification Alert: {error}
                                    </AlertDescription>
                                </Alert>
                            )}

                            {!enrolled && (
                                <div className="text-center py-16 space-y-10">
                                    <div className="relative group mx-auto">
                                        <div className="mx-auto w-32 h-32 bg-surface-container/50 rounded-[40px] flex items-center justify-center transition-all duration-500 group-hover:scale-105">
                                            <Unlock className="h-14 w-14 text-on-surface/20" />
                                        </div>
                                        <div className="absolute -bottom-2 -right-2 w-10 h-10 bg-card border border-on-surface/5 rounded-2xl shadow-lg flex items-center justify-center">
                                            <ShieldAlert className="w-5 h-5 text-amber-500 animate-pulse" />
                                        </div>
                                    </div>
                                    <div className="space-y-4">
                                        <h3 className="text-2xl font-bold tracking-tight text-on-surface uppercase opacity-40">Status: Dormant</h3>
                                        <p className="text-on-surface-variant/60 font-medium max-w-sm mx-auto leading-relaxed italic">
                                            Multi-factor authentication is not currently enforced for this identity node. Verification frequency is reduced.
                                        </p>
                                    </div>
                                    <Button onClick={handleEnroll} disabled={enrolling} className="h-16 px-12 rounded-[24px] font-bold text-[11px] uppercase tracking-widest shadow-2xl shadow-primary/30 hover:scale-[1.02] active:scale-[0.98] transition-all">
                                        {enrolling ? <Loader2 className="mr-3 h-5 w-5 animate-spin" /> : <Plus className="mr-3 h-4 w-4" />}
                                        Initialize MFA Vector
                                    </Button>
                                </div>
                            )}

                            {enrolled && !verified && qrCode && (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-12 animate-in zoom-in-95 duration-500">
                                    <div className="space-y-8">
                                        <div className="space-y-4">
                                            <Label className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                                <QrCode className="w-3.5 h-3.5" />
                                                01 // Optical Handshake
                                            </Label>
                                            <div className="bg-card p-8 rounded-[32px] ring-1 ring-on-surface/5 flex justify-center shadow-inner overflow-hidden group">
                                                <img
                                                    src={`data:image/png;base64,${qrCode}`}
                                                    alt="TOTP QR Code"
                                                    className="w-full aspect-square mix-blend-multiply transition-transform group-hover:scale-105 duration-500"
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-4 bg-surface-container/30 p-8 rounded-3xl ring-1 ring-on-surface/5">
                                            <Label className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/40 italic flex items-center gap-2">
                                                <Terminal className="w-3.5 h-3.5" />
                                                Manual Seed Identifier
                                            </Label>
                                            <div className="font-mono text-xs font-bold tracking-widest text-center select-all bg-card py-4 rounded-xl border border-on-surface/5 shadow-sm text-primary">
                                                {secret}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex flex-col justify-center space-y-10">
                                        <div className="space-y-4">
                                            <Label className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                                <Activity className="w-3.5 h-3.5" />
                                                02 // Entropy Verification
                                            </Label>
                                            <Input
                                                value={verifyCode}
                                                onChange={(e) => setVerifyCode(e.target.value)}
                                                placeholder="000 000"
                                                className="h-20 text-center text-5xl font-bold tracking-[0.2em] border-none bg-surface-container ring-1 ring-on-surface/5 rounded-[24px] focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono"
                                                maxLength={6}
                                                autoFocus
                                            />
                                            <p className="text-[10px] text-on-surface-variant/40 italic text-center px-4 leading-relaxed mt-4 font-medium">
                                                Enter the current deterministic transient code generated by your device.
                                            </p>
                                        </div>
                                        <Button onClick={handleVerify} className="h-16 rounded-[24px] font-bold text-[11px] uppercase tracking-widest shadow-2xl shadow-primary/30 hover:scale-[1.02] active:scale-[0.98] transition-all">
                                            Commit Protocol
                                        </Button>
                                    </div>
                                </div>
                            )}

                            {enrolled && verified && (
                                <div className="text-center space-y-12 py-16 animate-in zoom-in duration-700">
                                    <div className="flex flex-col items-center gap-10">
                                        <div className="relative group">
                                            <div className="w-32 h-32 bg-success-subtle rounded-[40px] flex items-center justify-center ring-1 ring-emerald-100 shadow-xl shadow-emerald-500/10 group-hover:scale-110 transition-transform duration-500">
                                                <CheckCircle className="h-16 w-16 text-success" />
                                            </div>
                                            <div className="absolute -bottom-2 -right-2 w-10 h-10 bg-card border border-success/10 rounded-2xl shadow-lg flex items-center justify-center">
                                                <Lock className="w-5 h-5 text-success" />
                                            </div>
                                        </div>
                                        <div className="space-y-3">
                                            <h3 className="text-3xl font-bold tracking-tight text-on-surface uppercase">Profile Hardened</h3>
                                            <div className="flex items-center gap-2.5 justify-center py-1.5 px-6 bg-success-subtle rounded-full border border-success/10 w-fit mx-auto">
                                                <div className="w-2 h-2 bg-success rounded-full animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                                                <span className="text-[9px] font-bold uppercase tracking-widest text-success">Verified Identity Vector</span>
                                            </div>
                                        </div>
                                    </div>

                                    <p className="text-on-surface-variant/60 font-medium max-w-md mx-auto text-sm leading-relaxed italic">
                                        Your account node is now cryptographically hardened. Secondary entropy verification will be mandated for all future authentication cycles.
                                    </p>

                                    <div className="pt-12 border-t border-on-surface/5">
                                        <Button variant="ghost" className="h-14 px-10 rounded-2xl font-bold text-[10px] uppercase tracking-[0.2em] text-destructive hover:bg-destructive/10 hover:text-destructive transition-all" onClick={handleDisable}>
                                            <Trash2 className="mr-3 h-4 w-4" /> Revert Hardening
                                        </Button>
                                    </div>
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </div>

                <div className="lg:col-span-4 space-y-10">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-inverse text-on-inverse overflow-hidden rounded-[32px] p-10 h-fit">
                        <div className="space-y-10">
                            <div className="flex items-center gap-5">
                                <div className="p-3 bg-card/10 rounded-2xl">
                                    <Info className="w-6 h-6 text-primary" />
                                </div>
                                <h4 className="text-xl font-bold tracking-tight">Security Intel</h4>
                            </div>

                            <div className="space-y-8">
                                {[
                                    { 
                                        label: 'Risk Profile', 
                                        value: intel?.risk_level ? `${intel.risk_level.toUpperCase()} (${intel.risk_score || 0})` : 'CALCULATING...', 
                                        icon: <ShieldAlert className="w-4 h-4" /> 
                                    },
                                    { 
                                        label: 'Access Signal', 
                                        value: intel?.last_login_ip || 'PENDING_INIT', 
                                        icon: <Activity className="w-4 h-4" /> 
                                    },
                                    { 
                                        label: 'Identity Age', 
                                        value: intel?.last_login_at ? new Date(intel.last_login_at).toLocaleDateString() : 'GENESIS', 
                                        icon: <Binary className="w-4 h-4" /> 
                                    },
                                ].map((stat) => (
                                    <div key={stat.label} className="group flex items-center justify-between border-b border-on-inverse/5 pb-4 last:border-0 last:pb-0">
                                        <div className="flex items-center gap-4">
                                            <div className="text-primary group-hover:scale-110 transition-transform">
                                                {stat.icon}
                                            </div>
                                            <span className="text-[10px] font-bold uppercase tracking-widest opacity-40">{stat.label}</span>
                                        </div>
                                        <span className="text-xs font-bold font-mono text-primary">{stat.value}</span>
                                    </div>
                                ))}
                            </div>

                            <div className="bg-card/5 p-6 rounded-3xl border border-on-inverse/5">
                                <p className="text-[10px] leading-relaxed tracking-wider font-bold opacity-40 uppercase italic">
                                    Structural default: Multi-factor verification is enforced at the organizational cluster level.
                                </p>
                            </div>
                        </div>
                    </GlassCard>

                    <div className="p-8 rounded-[40px] border-2 border-dashed border-on-surface/5 bg-surface-container/10 flex flex-col items-center gap-6 group hover:border-primary/20 transition-all cursor-default">
                        <div className="p-4 bg-card rounded-2xl shadow-lg ring-1 ring-on-surface/5 group-hover:scale-110 transition-transform">
                            <ShieldCheck className="h-8 w-8 text-primary" />
                        </div>
                        <div className="text-center space-y-2">
                            <h5 className="font-bold text-xs uppercase tracking-widest text-on-surface opacity-60">Verified Node</h5>
                            <p className="text-[9px] font-medium text-on-surface-variant/40 leading-relaxed uppercase tracking-widest">Structural handshake validated by wardseal governance layer.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        </PageLayout>
    );
};

export default MFASetup;
