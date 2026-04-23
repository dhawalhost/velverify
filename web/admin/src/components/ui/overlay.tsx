import * as React from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface OverlayProps {
    /** Controls visibility */
    open: boolean;
    /** Called when the overlay should close */
    onClose: () => void;
    /** Content rendered inside the overlay card */
    children: React.ReactNode;
    /** Additional classes on the card container */
    className?: string;
    /** Show a close button in the top-right corner of the backdrop */
    showCloseButton?: boolean;
    /** Close when clicking the backdrop */
    closeOnBackdrop?: boolean;
    /** Max width of the card */
    maxWidth?: string;
}

// ── Component ─────────────────────────────────────────────────────────────────
/**
 * Full-screen overlay with blurred backdrop.
 * Used for detail panels, edit forms, and log viewers.
 *
 * @example
 * <Overlay open={editOpen} onClose={() => setEditOpen(false)}>
 *   <EditForm />
 * </Overlay>
 */
export const Overlay: React.FC<OverlayProps> = ({
    open,
    onClose,
    children,
    className,
    showCloseButton = true,
    closeOnBackdrop = true,
    maxWidth = "max-w-6xl",
}) => {
    // Close on Escape key
    React.useEffect(() => {
        if (!open) return;
        const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
        window.addEventListener("keydown", handler);
        return () => window.removeEventListener("keydown", handler);
    }, [open, onClose]);

    // Lock body scroll while open
    React.useEffect(() => {
        document.body.style.overflow = open ? "hidden" : "";
        return () => { document.body.style.overflow = ""; };
    }, [open]);

    if (!open) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center p-6 animate-fade-in"
            aria-modal="true"
            role="dialog"
        >
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-on-surface/20 backdrop-blur-md"
                onClick={closeOnBackdrop ? onClose : undefined}
            />

            {/* Card */}
            <div
                className={cn(
                    "relative w-full bg-white rounded-[32px] shadow-overlay overflow-hidden flex flex-col animate-scale-in",
                    maxWidth,
                    className
                )}
            >
                {showCloseButton && (
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={onClose}
                        className="absolute top-5 right-5 z-10 h-9 w-9 rounded-xl hover:bg-surface-container transition-all"
                        aria-label="Close"
                    >
                        <X className="h-4 w-4" />
                    </Button>
                )}
                {children}
            </div>
        </div>
    );
};
Overlay.displayName = "Overlay";
