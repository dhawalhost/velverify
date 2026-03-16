import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button as MovingButton } from '@/components/ui/button'; // Just use Button
import { Loader2, ShieldCheck, Smartphone, CheckCircle, XCircle, Trash2 } from 'lucide-react';
import { api } from '../api';

const MFASetup: React.FC = () => {
    const [enrolling, setEnrolling] = useState(false);
    const [enrolled, setEnrolled] = useState(false);
    const [verified, setVerified] = useState(false);
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [verifyCode, setVerifyCode] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);

    const getUserId = () => {
        return localStorage.getItem('userId') || 'admin@wardseal.com';
    };

    const fetchStatus = async () => {
        try {
            const response = await api.get(`/api/v1/mfa/totp/status?user_id=${encodeURIComponent(getUserId())}`);
            setEnrolled(response.data.enrolled);
            setVerified(response.data.verified);
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

    if (loading) return <div className="p-8 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6 max-w-lg mx-auto">
            <div className="text-center space-y-2">
                <h1 className="text-3xl font-bold tracking-tight">Two-Factor Authentication</h1>
                <p className="text-muted-foreground">Enhance your account security with an authenticator app.</p>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Smartphone className="h-5 w-5" /> Authenticator App
                    </CardTitle>
                    <CardDescription>
                        Use Google Authenticator, Authy, or Microsoft Authenticator.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    {error && (
                        <div className="bg-destructive/10 text-destructive p-3 rounded-md text-sm flex items-center gap-2">
                            <XCircle className="h-4 w-4" /> {error}
                        </div>
                    )}

                    {!enrolled && (
                        <div className="text-center py-6">
                            <ShieldCheck className="h-16 w-16 mx-auto text-muted-foreground mb-4 opacity-50" />
                            <p className="mb-6">TOTP MFA is currently disabled.</p>
                            <Button onClick={handleEnroll} disabled={enrolling} className="w-full">
                                {enrolling ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                                Enable TOTP
                            </Button>
                        </div>
                    )}

                    {enrolled && !verified && qrCode && (
                        <div className="space-y-4">
                            <div className="bg-white p-4 rounded-lg border flex justify-center">
                                <img
                                    src={`data:image/png;base64,${qrCode}`}
                                    alt="TOTP QR Code"
                                    className="w-48 h-48"
                                />
                            </div>
                            <div className="text-center space-y-2">
                                <Label className="text-muted-foreground">Or enter this code manually:</Label>
                                <div className="font-mono bg-muted p-2 rounded text-center select-all border">
                                    {secret}
                                </div>
                            </div>
                            <div className="space-y-2 pt-2">
                                <Label>Verify Code</Label>
                                <div className="flex gap-2">
                                    <Input
                                        value={verifyCode}
                                        onChange={(e) => setVerifyCode(e.target.value)}
                                        placeholder="000000"
                                        className="text-center text-lg tracking-[0.5em] font-mono"
                                        maxLength={6}
                                    />
                                    <Button onClick={handleVerify}>Verify</Button>
                                </div>
                            </div>
                        </div>
                    )}

                    {enrolled && verified && (
                        <div className="text-center space-y-6 py-4">
                            <div className="flex flex-col items-center gap-2 text-green-600 dark:text-green-400">
                                <CheckCircle className="h-16 w-16" />
                                <span className="font-bold text-lg">MFA Enabled & Verified</span>
                            </div>
                            <p className="text-muted-foreground text-sm">
                                Your account is secured. You will be asked for a code when you log in.
                            </p>
                            <div className="pt-4 border-t">
                                <Button variant="outline" className="w-full border-destructive/30 text-destructive hover:bg-destructive/10" onClick={handleDisable}>
                                    <Trash2 className="mr-2 h-4 w-4" /> Disable MFA
                                </Button>
                            </div>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default MFASetup;
