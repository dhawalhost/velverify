import React, { useEffect, useState } from 'react';
import { getPolicies, createPolicy, Policy } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    ShieldCheck, 
    ShieldAlert, 
    Plus, 
    Settings2, 
    FileJson,
    Trash2,
    X,
    AlertCircle
} from 'lucide-react';
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

const Policies: React.FC = () => {
    const [policies, setPolicies] = useState<Policy[]>([]);
    const [loading, setLoading] = useState(true);
    const [isCreateOpen, setIsCreateOpen] = useState(false);
    const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);
    const [newPolicy, setNewPolicy] = useState({
        name: '',
        rule_type: 'access_control',
        rule_data: '{\n  "condition": "user.groups.contains(\'admin\')",\n  "effect": "allow"\n}'
    });

    const fetchPolicies = async () => {
        try {
            setLoading(true);
            const data = await getPolicies();
            setPolicies(data || []);
        } catch (err) {
            console.error(err);
            setMessage({ text: "Failed to load tenant security policies.", type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPolicies();
    }, []);

    const handleCreate = async () => {
        try {
            setMessage(null);
            let ruleData = {};
            try {
                ruleData = JSON.parse(newPolicy.rule_data);
            } catch (e) {
                setMessage({ text: "Rule data must be valid JSON.", type: 'error' });
                return;
            }

            await createPolicy({
                name: newPolicy.name,
                rule_type: newPolicy.rule_type,
                rule_data: ruleData,
                is_enabled: true
            });

            setMessage({ text: "The security policy has been successfully deployed.", type: 'success' });
            setIsCreateOpen(false);
            setNewPolicy({
                name: '',
                rule_type: 'access_control',
                rule_data: '{\n  "condition": "user.groups.contains(\'admin\')",\n  "effect": "allow"\n}'
            });
            fetchPolicies();
        } catch (err) {
            console.error(err);
            setMessage({ text: "Could not persist the new policy rule.", type: 'error' });
        }
    };

    if (loading && policies.length === 0) {
        return (
            <div className="h-[400px] flex items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        );
    }

    return (
        <div className="space-y-8 max-w-[1400px] mx-auto">
            <div className="flex justify-between items-end">
                <div className="space-y-1">
                    <h1 className="text-4xl font-black tracking-tighter uppercase italic">Security Policies</h1>
                    <p className="text-muted-foreground text-sm font-medium">Configure granular access control and governance constraints.</p>
                </div>
                
                {!isCreateOpen && (
                    <Button 
                        onClick={() => setIsCreateOpen(true)}
                        className="bg-foreground text-background hover:bg-foreground/90 font-bold uppercase tracking-widest text-xs px-6 py-6 rounded-none"
                    >
                        <Plus className="w-4 h-4 mr-2" /> New Policy Rule
                    </Button>
                )}
            </div>

            {message && (
                <Alert variant={message.type === 'error' ? 'destructive' : 'default'} className="bg-card/50 backdrop-blur-md border-2">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="font-bold uppercase text-[10px] tracking-widest">{message.text}</AlertDescription>
                </Alert>
            )}

            {isCreateOpen && (
                <Card className="border-4 border-foreground shadow-2xl rounded-none animate-in fade-in slide-in-from-top-4 duration-300">
                    <CardHeader className="bg-foreground text-background py-6">
                        <div className="flex justify-between items-center">
                            <div>
                                <CardTitle className="text-2xl font-black uppercase tracking-tighter italic">Deploy Security Policy</CardTitle>
                                <CardDescription className="text-background/60 font-medium">Define a new technical constraint for your enterprise tenant.</CardDescription>
                            </div>
                            <Button variant="ghost" size="icon" onClick={() => setIsCreateOpen(false)} className="text-background hover:bg-background/20">
                                <X className="w-6 h-6" />
                            </Button>
                        </div>
                    </CardHeader>
                    <CardContent className="grid gap-6 p-8">
                        <div className="grid gap-2">
                            <Label htmlFor="name" className="text-[10px] font-black uppercase tracking-widest">Policy Identifier</Label>
                            <Input 
                                id="name" 
                                placeholder="e.g. SOC2_ADMIN_RESTRICTION" 
                                className="rounded-none border-2 border-foreground/5 bg-muted/30 h-12 focus-visible:ring-foreground/20 font-bold tracking-tight"
                                value={newPolicy.name}
                                onChange={(e) => setNewPolicy({...newPolicy, name: e.target.value})}
                            />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="type" className="text-[10px] font-black uppercase tracking-widest">Rule engine context</Label>
                            <Input 
                                id="type" 
                                value={newPolicy.rule_type}
                                className="rounded-none border-2 border-foreground/5 bg-muted/10 font-mono text-xs uppercase"
                                readOnly
                            />
                        </div>
                        <div className="grid gap-2">
                            <Label htmlFor="rule" className="text-[10px] font-black uppercase tracking-widest">Rule Definition (JSON)</Label>
                            <Textarea 
                                id="rule" 
                                rows={8} 
                                className="font-mono text-xs rounded-none border-2 border-foreground/5 bg-muted/30 focus-visible:ring-foreground/20"
                                value={newPolicy.rule_data}
                                onChange={(e) => setNewPolicy({...newPolicy, rule_data: e.target.value})}
                            />
                        </div>
                    </CardContent>
                    <CardFooter className="bg-muted/30 p-6 flex justify-end gap-4 border-t-2 border-foreground/5">
                        <Button variant="ghost" onClick={() => setIsCreateOpen(false)} className="rounded-none font-black uppercase text-[10px] tracking-widest px-8">Discard</Button>
                        <Button onClick={handleCreate} className="bg-foreground text-background hover:bg-foreground/90 rounded-none font-black uppercase text-[10px] tracking-widest px-12 h-12 shadow-[4px_4px_0_0_rgba(0,0,0,0.1)]">Deploy Policy</Button>
                    </CardFooter>
                </Card>
            )}

            <Card className="border-2 border-foreground/10 shadow-xl overflow-hidden rounded-none">
                <CardHeader className="bg-muted/30 border-b-2 border-foreground/5 py-8">
                    <div className="flex items-center gap-3">
                        <ShieldCheck className="w-6 h-6 text-foreground" />
                        <div>
                            <CardTitle className="text-2xl font-black uppercase tracking-tighter italic">Policy Registry</CardTitle>
                            <CardDescription className="text-muted-foreground font-medium italic">Active governance rules governing role assumption and identity operations.</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="p-0">
                    {policies.length === 0 ? (
                        <div className="py-32 text-center text-muted-foreground flex flex-col items-center gap-6">
                            <div className="w-20 h-20 rounded-full bg-muted flex items-center justify-center border-4 border-dashed border-muted-foreground/20">
                                <Settings2 className="h-10 w-10 opacity-20" />
                            </div>
                            <div className="max-w-[300px] font-bold uppercase text-xs tracking-widest leading-relaxed"> No security policies have been defined for this tenant. </div>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader className="bg-muted/50 border-b-2 border-foreground/5">
                                <TableRow className="hover:bg-transparent">
                                    <TableHead className="py-4 font-black uppercase text-[10px] tracking-widest text-foreground">Policy Name</TableHead>
                                    <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Engine Type</TableHead>
                                    <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground text-center">Enforcement</TableHead>
                                    <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Last Adjusted</TableHead>
                                    <TableHead className="text-right font-black uppercase text-[10px] tracking-widest text-foreground pr-8">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {policies.map(policy => (
                                    <TableRow key={policy.id} className="hover:bg-muted/30 transition-all border-b border-foreground/5 group">
                                        <TableCell className="py-6 pr-4">
                                            <div className="flex items-center gap-3">
                                                <div className="w-8 h-8 rounded-sm bg-foreground/5 flex items-center justify-center border border-foreground/10 group-hover:bg-foreground group-hover:text-background transition-colors">
                                                    <FileJson className="w-4 h-4" />
                                                </div>
                                                <div className="flex flex-col">
                                                    <span className="text-sm font-black tracking-tight uppercase leading-none">{policy.name}</span>
                                                    <span className="text-[9px] font-mono text-muted-foreground tracking-tighter mt-1 uppercase italic">{policy.id}</span>
                                                </div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="secondary" className="bg-foreground/5 text-foreground hover:bg-foreground/10 rounded-sm font-black text-[9px] uppercase tracking-widest border-none">
                                                {policy.rule_type}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-center">
                                            {policy.is_enabled ? 
                                                <Badge className="bg-green-600/10 text-green-600 border-green-600/20 gap-1 rounded-sm"><ShieldCheck className="w-3 h-3" /> ACTIVE</Badge> : 
                                                <Badge variant="secondary" className="bg-muted text-muted-foreground gap-1 rounded-sm"><ShieldAlert className="w-3 h-3" /> INACTIVE</Badge>
                                            }
                                        </TableCell>
                                        <TableCell className="text-muted-foreground font-mono text-[10px] uppercase italic">
                                            {new Date(policy.updated_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell className="text-right pr-8">
                                            <div className="flex justify-end gap-2">
                                                <Button size="icon" variant="ghost" className="h-8 w-8 hover:bg-foreground hover:text-background border border-foreground/5 transition-colors">
                                                    <Settings2 className="w-4 h-4" />
                                                </Button>
                                                <Button size="icon" variant="ghost" className="h-8 w-8 hover:bg-destructive/10 hover:text-destructive border border-foreground/5 transition-colors">
                                                    <Trash2 className="w-4 h-4" />
                                                </Button>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default Policies;
