import { api } from '@/api'; // api is named export
import { ExternalLink, Globe, Lock } from 'lucide-react';
import { Skeleton } from "@/components/ui/skeleton";

interface AppClient {
    id: string;
    name: string;
    description: string;
    launch_url: string;
    icon_url: string;
}

const PortalDashboard = () => {
    const [apps, setApps] = useState<AppClient[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchApps = async () => {
            try {
                const res = await api.get('/user/apps');
                setApps(res.data.apps || []);
            } catch (err) {
                console.error("Failed to load apps:", err);
            } finally {
                setLoading(false);
            }
        };
        fetchApps();
    }, []);

    if (loading) {
        return (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {[1, 2, 3, 4].map((i) => (
                    <Card key={i} className="h-[200px] flex flex-col justify-between">
                        <CardHeader>
                            <Skeleton className="h-8 w-12 rounded-lg mb-2" />
                            <Skeleton className="h-6 w-3/4" />
                        </CardHeader>
                        <CardFooter>
                            <Skeleton className="h-10 w-full" />
                        </CardFooter>
                    </Card>
                ))}
            </div>
        )
    }

    if (apps.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[50vh] text-center">
                <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center mb-4">
                    <Lock className="w-8 h-8 text-muted-foreground" />
                </div>
                <h2 className="text-xl font-semibold mb-2">No Apps Assigned</h2>
                <p className="text-muted-foreground max-w-sm">You haven't been assigned any applications yet. Contact your administrator for access.</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold tracking-tight">My Applications</h1>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {apps.map((app) => (
                    <Card key={app.id} className="group hover:shadow-lg transition-all duration-300 border-border/50 hover:border-primary/20">
                        <CardHeader className="space-y-4">
                            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/10 to-blue-500/10 flex items-center justify-center text-primary group-hover:scale-110 transition-transform duration-300">
                                {/* Use icon_url if available, else standard fallback */}
                                <Globe className="w-6 h-6" />
                            </div>
                            <div className="space-y-1">
                                <CardTitle className="text-lg group-hover:text-primary transition-colors">{app.name}</CardTitle>
                                <CardDescription className="line-clamp-2 text-sm">{app.description || "No description provided."}</CardDescription>
                            </div>
                        </CardHeader>
                        <CardContent className="py-2" />
                        <CardFooter>
                            <Button className="w-full gap-2" variant="secondary" onClick={() => window.open(app.launch_url, '_blank')}>
                                Launch <ExternalLink className="w-4 h-4" />
                            </Button>
                        </CardFooter>
                    </Card>
                ))}
            </div>
        </div>
    );
};

export default PortalDashboard;
