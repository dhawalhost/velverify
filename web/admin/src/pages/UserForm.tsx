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
import { createUser } from '../api';

const UserForm: React.FC = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Form state
    const [userName, setUserName] = useState('');
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [email, setEmail] = useState('');
    const [active, setActive] = useState(true);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await createUser({
                userName: userName || email,
                name: {
                    givenName: firstName,
                    familyName: lastName
                },
                emails: [
                    { value: email, primary: true, type: "work" }
                ],
                active: active
            });
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
