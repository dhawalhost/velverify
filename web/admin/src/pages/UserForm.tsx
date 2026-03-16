import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { ArrowLeft, Loader2 } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { createUser, requestPasswordSetupLink } from '../api';

type CredentialMode = 'admin_password' | 'generated_password' | 'invite_link' | 'reset_link';

const generateStrongPassword = () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    let out = 'Ws!';
    for (let i = 0; i < bytes.length; i += 1) {
        out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
};

const UserForm: React.FC = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Form state
    const [userName, setUserName] = useState('');
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [active, setActive] = useState(true);
    const [credentialMode, setCredentialMode] = useState<CredentialMode>('admin_password');
    const [generatedPassword, setGeneratedPassword] = useState('');
    const [setupLink, setSetupLink] = useState('');
    const [successMessage, setSuccessMessage] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');
        setSetupLink('');
        setLoading(true);

        let passwordToUse = '';
        if (credentialMode === 'admin_password') {
            if (password.length < 8) {
                setError('Password must be at least 8 characters.');
                setLoading(false);
                return;
            }
            if (password !== confirmPassword) {
                setError('Passwords do not match.');
                setLoading(false);
                return;
            }
            passwordToUse = password;
        }

        if (credentialMode === 'generated_password') {
            if (!generatedPassword || generatedPassword.length < 8) {
                setError('Generate an initial password before creating the user.');
                setLoading(false);
                return;
            }
            passwordToUse = generatedPassword;
        }

        try {
            const created = await createUser({
                userName: userName || email,
                ...(passwordToUse ? { password: passwordToUse } : {}),
                name: {
                    givenName: firstName,
                    familyName: lastName
                },
                emails: [
                    { value: email, primary: true, type: "work" }
                ],
                active: active
            });

            const createdUserID = created?.id || created?.user_id;
            if (!createdUserID) {
                setSuccessMessage('User created successfully.');
                return;
            }

            if (credentialMode === 'invite_link' || credentialMode === 'reset_link') {
                const mode = credentialMode === 'invite_link' ? 'invite' : 'reset';
                const linkResp = await requestPasswordSetupLink(createdUserID, mode, 72);
                setSetupLink(linkResp.url || '');
                setSuccessMessage(`User created. ${mode === 'invite' ? 'Invite' : 'Reset'} link generated.`);
                return;
            }

            if (credentialMode === 'generated_password') {
                setSuccessMessage('User created with generated initial password. Copy it now and share securely.');
                return;
            }

            navigate('/users');
        } catch (err: any) {
            console.error("Failed to create user", err);
            setError(err.response?.data?.detail || "Failed to create user. Please try again.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="max-w-2xl mx-auto p-6 space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate('/users')}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">Create New User</h1>
                    <p className="text-muted-foreground">Add a new user to the organization.</p>
                </div>
            </div>

            <form onSubmit={handleSubmit}>
                <Card>
                    <CardHeader>
                        <CardTitle>User Details</CardTitle>
                        <CardDescription>Enter the basic information for the new user.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {error && (
                            <Alert variant="destructive">
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        )}
                        {successMessage && (
                            <Alert>
                                <AlertDescription>{successMessage}</AlertDescription>
                            </Alert>
                        )}

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="firstName">First Name</Label>
                                <Input
                                    id="firstName"
                                    value={firstName}
                                    onChange={(e) => setFirstName(e.target.value)}
                                    placeholder="Jane"
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="lastName">Last Name</Label>
                                <Input
                                    id="lastName"
                                    value={lastName}
                                    onChange={(e) => setLastName(e.target.value)}
                                    placeholder="Doe"
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="email">Email</Label>
                            <Input
                                id="email"
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="jane.doe@company.com"
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="username">Username</Label>
                            <Input
                                id="username"
                                value={userName}
                                onChange={(e) => setUserName(e.target.value)}
                                placeholder="jane.doe"
                            />
                            <p className="text-sm text-muted-foreground">Leave empty to use email as username</p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="credentialMode">Credential Setup Method</Label>
                            <select
                                id="credentialMode"
                                className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm"
                                value={credentialMode}
                                onChange={(e) => {
                                    const mode = e.target.value as CredentialMode;
                                    setCredentialMode(mode);
                                    setSetupLink('');
                                    setSuccessMessage('');
                                    if (mode === 'generated_password') {
                                        const generated = generateStrongPassword();
                                        setGeneratedPassword(generated);
                                        setPassword(generated);
                                        setConfirmPassword(generated);
                                    }
                                }}
                            >
                                <option value="admin_password">Create password by admin</option>
                                <option value="generated_password">Initial password generation</option>
                                <option value="invite_link">Tokenized invite link</option>
                                <option value="reset_link">Reset link</option>
                            </select>
                        </div>

                        {credentialMode === 'admin_password' && (
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="password">Initial Password</Label>
                                <Input
                                    id="password"
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="At least 8 characters"
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm Password</Label>
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Re-enter password"
                                    required
                                />
                            </div>
                        </div>
                        )}

                        {credentialMode === 'generated_password' && (
                            <div className="space-y-2">
                                <Label htmlFor="generatedPassword">Generated Initial Password</Label>
                                <div className="flex gap-2">
                                    <Input id="generatedPassword" readOnly value={generatedPassword} />
                                    <Button type="button" variant="outline" onClick={() => {
                                        const generated = generateStrongPassword();
                                        setGeneratedPassword(generated);
                                        setPassword(generated);
                                        setConfirmPassword(generated);
                                    }}>
                                        Regenerate
                                    </Button>
                                    <Button type="button" variant="outline" onClick={() => navigator.clipboard.writeText(generatedPassword)}>
                                        Copy
                                    </Button>
                                </div>
                                <p className="text-sm text-muted-foreground">Share this password securely and ask user to change it after first login.</p>
                            </div>
                        )}

                        {(credentialMode === 'invite_link' || credentialMode === 'reset_link') && setupLink && (
                            <div className="space-y-2">
                                <Label>{credentialMode === 'invite_link' ? 'Tokenized Invite Link' : 'Reset Link'}</Label>
                                <div className="flex gap-2">
                                    <Input readOnly value={setupLink} />
                                    <Button type="button" variant="outline" onClick={() => navigator.clipboard.writeText(setupLink)}>
                                        Copy
                                    </Button>
                                </div>
                            </div>
                        )}

                        <div className="flex items-center space-x-2 pt-2">
                            <Checkbox
                                id="active"
                                checked={active}
                                onCheckedChange={(c) => setActive(!!c)}
                            />
                            <Label htmlFor="active" className="cursor-pointer">Active user account</Label>
                        </div>

                    </CardContent>
                    <CardFooter className="flex justify-between">
                        <Button type="button" variant="outline" onClick={() => navigate('/users')}>
                            Cancel
                        </Button>
                        <Button type="submit" disabled={loading}>
                            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Create User
                        </Button>
                    </CardFooter>
                </Card>
            </form>
        </div>
    );
};

export default UserForm;
