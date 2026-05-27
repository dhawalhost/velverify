import * as React from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface ConfirmDialogProps {
    /** Controls visibility */
    open: boolean;
    /** Called when the dialog should close (cancel or after confirm) */
    onClose: () => void;
    /** Called when the user confirms the action */
    onConfirm: () => void | Promise<void>;
    /** Dialog title */
    title?: string;
    /** Description / warning message */
    description?: string;
    /** Label for the confirm button */
    confirmLabel?: string;
    /** Label for the cancel button */
    cancelLabel?: string;
    /** Visual severity of the action */
    variant?: "danger" | "warning" | "default";
    /** Whether the confirm action is in progress */
    loading?: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────────
/**
 * Accessible confirmation dialog — replaces `window.confirm()` throughout the app.
 *
 * @example
 * <ConfirmDialog
 *   open={deleteOpen}
 *   onClose={() => setDeleteOpen(false)}
 *   onConfirm={handleDelete}
 *   title="Delete provider"
 *   description="This will permanently remove the SSO configuration."
 *   variant="danger"
 *   confirmLabel="Delete"
 * />
 */
export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
    open,
    onClose,
    onConfirm,
    title = "Confirm action",
    description = "Are you sure you want to proceed? This action cannot be undone.",
    confirmLabel = "Confirm",
    cancelLabel = "Cancel",
    variant = "danger",
    loading = false,
}) => {
    const handleConfirm = async () => {
        await onConfirm();
        onClose();
    };

    const confirmButtonClass = {
        danger:  "bg-destructive hover:bg-red-700 text-white shadow-lg shadow-destructive/20",
        warning: "bg-amber-500 hover:bg-amber-600 text-white shadow-lg shadow-amber-500/20",
        default: "bg-primary hover:bg-primary/90 text-primary-foreground shadow-lg shadow-primary/20",
    }[variant];

    const iconColor = {
        danger:  "text-destructive",
        warning: "text-amber-500",
        default: "text-primary",
    }[variant];

    return (
        <Dialog open={open} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-[480px] rounded-[32px] border-none p-0 overflow-hidden shadow-overlay">
                <DialogHeader className="bg-surface-container/10 p-10 border-b border-on-surface/5">
                    <div className="flex items-center gap-5">
                        <div className={`p-3.5 rounded-2xl bg-current/10 ${iconColor}`}>
                            <AlertTriangle className={`w-7 h-7 ${iconColor}`} />
                        </div>
                        <div>
                            <DialogTitle className="text-2xl font-bold tracking-tight text-on-surface">
                                {title}
                            </DialogTitle>
                            <DialogDescription className="text-on-surface-variant/60 font-medium text-[11px] mt-2 italic">
                                This action may be irreversible.
                            </DialogDescription>
                        </div>
                    </div>
                </DialogHeader>

                <div className="p-10 bg-card space-y-8">
                    <p className="text-sm font-medium text-on-surface-variant/70 leading-relaxed">
                        {description}
                    </p>

                    <DialogFooter className="gap-3">
                        <Button
                            type="button"
                            variant="ghost"
                            onClick={onClose}
                            disabled={loading}
                            className="h-12 px-8 rounded-xl font-bold text-[12px] tracking-tight hover:bg-surface-container/20"
                        >
                            {cancelLabel}
                        </Button>
                        <Button
                            type="button"
                            onClick={handleConfirm}
                            disabled={loading}
                            className={`flex-1 h-12 rounded-xl font-bold tracking-tight text-[12px] transition-all ${confirmButtonClass}`}
                        >
                            {loading ? (
                                <span className="flex items-center gap-2">
                                    <span className="h-4 w-4 border-2 border-on-inverse/30 border-t-white rounded-full animate-spin" />
                                    Processing…
                                </span>
                            ) : confirmLabel}
                        </Button>
                    </DialogFooter>
                </div>
            </DialogContent>
        </Dialog>
    );
};
ConfirmDialog.displayName = "ConfirmDialog";
