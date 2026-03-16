import React, { useState } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { signup } from '../api';
import Config from '../config';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ShieldCheck, ArrowRight, Building, Lock } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const SignUp: React.FC = () => {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams(); // Need to import useSearchParams
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';
    const [companyName, setCompanyName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Default plan from URL or 'free'
    const plan = searchParams.get('plan') || 'free';

    // Check if public signup is enabled
    if (!Config.features.publicSignup) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-muted/20 p-4">
                <Card className="w-full max-w-md shadow-lg border-muted/40 text-center p-6">
                    <div className="mx-auto w-16 h-16 flex items-center justify-center bg-muted rounded-full mb-4">
                        <Lock className="w-8 h-8 text-muted-foreground" />
                    </div>
                    <CardTitle className="mb-2">Registration Restricted</CardTitle>
                    <CardDescription className="mb-6">
                        Public signup is disabled on this instance. Please contact your system administrator for access.
                    </CardDescription>
                    <Button variant="default" onClick={() => navigate('/login')}>
                        Back to Login
                    </Button>
                </Card>
            </div>
        );
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const data = await signup(email, password, companyName, plan);
            localStorage.setItem('token', data.token);
            localStorage.setItem('tenantID', data.tenant_id);
                if (data.tenant_slug) {
                    localStorage.setItem('tenantSlug', data.tenant_slug);
                }
            localStorage.setItem('userId', email);
            // SignUp success, redirect to dashboard
            navigate('/dashboard');
        } catch (err: any) {
            console.error(err);
            if (err.response?.status === 409) {
                setError("Account already exists. Please login instead.");
            } else {
                setError(err.response?.data?.error_description || err.response?.data?.error || 'Signup failed. Please try again.');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-muted/20 p-4">
            <Card className="w-full max-w-md shadow-lg border-muted/40 animate-in fade-in zoom-in duration-300">
                <CardHeader className="text-center pb-6">
                    <div className="mx-auto w-16 h-16 flex items-center justify-center mb-4">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-full h-full object-contain" />
                    </div>
                    <CardTitle className="text-2xl font-bold tracking-tight">
                        Create your account
                    </CardTitle>
                    <CardDescription>
                        Get started with WardSeal Identity Platform
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="companyName">Company Name</Label>
                            <div className="relative">
                                <Building className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                                <Input
                                    id="companyName"
                                    placeholder="Acme Inc."
                                    className="pl-9"
                                    value={companyName}
                                    onChange={(e) => setCompanyName(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="email">Work Email</Label>
                            <Input
                                id="email"
                                type="email"
                                placeholder="name@company.com"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="password">Password</Label>
                            <Input
                                id="password"
                                type="password"
                                placeholder="Min. 8 characters"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                minLength={8}
                            />
                        </div>

                        {error && (
                            <Alert variant="destructive">
                                <ShieldCheck className="h-4 w-4" />
                                <AlertTitle>Error</AlertTitle>
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        )}

                        <Button type="submit" className="w-full" disabled={loading}>
                            {loading ? 'Creating account...' : 'Create Account'}
                            {!loading && <ArrowRight className="ml-2 w-4 h-4" />}
                        </Button>
                    </form>
                </CardContent>
                <CardFooter className="flex justify-center border-t p-4 mt-2">
                    <div className="text-sm text-muted-foreground text-center">
                        <p>
                            Already have an account?{' '}
                            <Link to="/login" className="text-primary hover:underline font-medium">
                                Sign in
                            </Link>
                        </p>
                        <p className="mt-2 text-xs flex items-center justify-center gap-3">
                            <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Privacy</a>
                            <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Terms</a>
                            <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Policies</a>
                        </p>
                    </div>
                </CardFooter>
            </Card>
        </div>
    );
};

export default SignUp;
