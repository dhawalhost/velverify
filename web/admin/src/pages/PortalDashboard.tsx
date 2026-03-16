import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ExternalLink, LayoutGrid, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { getUserApps } from '../api';

interface Application {
    id: string;
    name: string;
    description: string;
    icon_url?: string;
    launch_url: string;
}

const PortalDashboard = () => {
    const [applications, setApplications] = useState<Application[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchApplications = async () => {
            setLoading(true);
            try {
                const data = await getUserApps();
                setApplications(data.apps || []);
            } catch (error) {
                console.error('Failed to fetch applications:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchApplications();
    }, []);

    const filteredApps = applications.filter(app =>
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.description.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const handleLaunch = (app: Application) => {
        window.open(app.launch_url, '_blank');
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div>
                <h1 className="text-3xl font-bold tracking-tight">My Applications</h1>
                <p className="text-muted-foreground mt-2">
                    Access your assigned applications and services
                </p>
            </div>

            {/* Search */}
            <div className="relative max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                    placeholder="Search applications..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                />
            </div>

            {/* Applications Grid */}
            {loading ? (
                <div className="flex items-center justify-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                </div>
            ) : filteredApps.length === 0 ? (
                <Card className="py-12">
                    <CardContent className="flex flex-col items-center justify-center text-center">
                        <LayoutGrid className="h-12 w-12 text-muted-foreground mb-4" />
                        <h3 className="text-lg font-semibold">No applications found</h3>
                        <p className="text-muted-foreground mt-1">
                            {searchQuery ? 'Try a different search term' : 'You have no assigned applications yet'}
                        </p>
                    </CardContent>
                </Card>
            ) : (
                <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                    {filteredApps.map((app) => (
                        <Card key={app.id} className="group hover:shadow-lg transition-shadow duration-200">
                            <CardHeader className="pb-3">
                                <div className="flex items-start justify-between">
                                    <div className="flex items-center gap-3">
                                        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                                            {app.icon_url ? (
                                                <img src={app.icon_url} alt={app.name} className="w-6 h-6" />
                                            ) : (
                                                <LayoutGrid className="w-5 h-5 text-primary" />
                                            )}
                                        </div>
                                        <div>
                                            <CardTitle className="text-base">{app.name}</CardTitle>
                                        </div>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <CardDescription className="line-clamp-2">
                                    {app.description}
                                </CardDescription>
                                <Button
                                    onClick={() => handleLaunch(app)}
                                    className="w-full gap-2"
                                    variant="outline"
                                >
                                    Launch
                                    <ExternalLink className="h-4 w-4" />
                                </Button>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )}
        </div>
    );
};

export default PortalDashboard;
