import * as React from "react";
import { Dialog, DialogContent } from "../Dialog/Dialog";
import { Search, CornerDownLeft } from "lucide-react";
import { cn } from "../../lib/utils";

export interface CommandItem {
  id: string;
  label: string;
  category: string;
  icon?: React.ReactNode;
  shortcut?: string;
  onClick?: () => void;
}

export interface CommandMenuProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  items: CommandItem[];
  placeholder?: string;
}

export function CommandMenu({
  open,
  onOpenChange,
  items,
  placeholder = "Search console commands (⌘K)...",
}: CommandMenuProps) {
  const [query, setQuery] = React.useState("");
  const [selectedIndex, setSelectedIndex] = React.useState(0);

  // Filter items based on search query
  const filteredItems = React.useMemo(() => {
    if (!query) return items;
    const lower = query.toLowerCase();
    return items.filter((item) =>
      item.label.toLowerCase().includes(lower) ||
      item.category.toLowerCase().includes(lower)
    );
  }, [items, query]);

  // Reset selected index when query changes
  React.useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Handle arrow key navigation and execution
  const handleKeyDown = React.useCallback(
    (e: React.KeyboardEvent) => {
      if (filteredItems.length === 0) return;

      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % filteredItems.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % filteredItems.length);
      } else if (e.key === "Enter") {
        e.preventDefault();
        const activeItem = filteredItems[selectedIndex];
        if (activeItem && activeItem.onClick) {
          activeItem.onClick();
          onOpenChange(false);
        }
      }
    },
    [filteredItems, selectedIndex, onOpenChange]
  );

  // Keyboard listener for ⌘K
  React.useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, [open, onOpenChange]);

  // Group filtered items by category
  const categories = React.useMemo(() => {
    const groups: { [key: string]: CommandItem[] } = {};
    filteredItems.forEach((item) => {
      if (!groups[item.category]) {
        groups[item.category] = [];
      }
      groups[item.category].push(item);
    });
    return groups;
  }, [filteredItems]);

  // Linear index calculation for grouped items
  let itemCounter = 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg p-0 overflow-hidden border border-white/10 bg-card/95 backdrop-blur-2xl shadow-2xl rounded-xl">
        {/* Search Input */}
        <div className="flex items-center border-b border-on-surface/5 px-4 h-12 gap-3 shrink-0">
          <Search className="w-4 h-4 text-on-surface-variant/40 shrink-0" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            className="flex-1 bg-transparent border-0 outline-none text-xs font-semibold text-on-surface placeholder:text-on-surface-variant/30 h-full w-full"
            autoFocus
          />
        </div>

        {/* Command List Viewport */}
        <div className="max-h-72 overflow-y-auto custom-scrollbar p-2 space-y-3">
          {filteredItems.length === 0 ? (
            <div className="py-6 text-center text-xs font-semibold text-on-surface-variant/30 uppercase tracking-widest italic">
              No telemetry matches found
            </div>
          ) : (
            Object.entries(categories).map(([cat, catItems]) => (
              <div key={cat} className="space-y-1">
                <h4 className="px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-on-surface-variant/30">
                  {cat}
                </h4>
                <ul className="space-y-0.5">
                  {catItems.map((item) => {
                    const currentIndex = itemCounter++;
                    const isActive = currentIndex === selectedIndex;

                    return (
                      <li key={item.id}>
                        <button
                          onClick={() => {
                            if (item.onClick) item.onClick();
                            onOpenChange(false);
                          }}
                          className={cn(
                            "w-full flex items-center justify-between px-3 py-2 rounded-lg text-left text-xs font-semibold transition-all duration-150 group/cmd border border-transparent",
                            isActive
                              ? "bg-primary/5 text-primary border-primary/10"
                              : "text-on-surface-variant/70 hover:bg-white/5 hover:text-on-surface"
                          )}
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            {item.icon && (
                              <span
                                className={cn(
                                  "w-4 h-4 shrink-0 transition-colors",
                                  isActive
                                    ? "text-primary"
                                    : "text-on-surface-variant/40 group-hover/cmd:text-on-surface-variant/75"
                                )}
                              >
                                {item.icon}
                              </span>
                            )}
                            <span className="truncate">{item.label}</span>
                          </div>
                          <div className="flex items-center gap-2 shrink-0 ml-4">
                            {item.shortcut && (
                              <kbd className="text-[9px] font-bold bg-surface-container-highest/80 border border-outline/10 px-1 rounded font-mono text-on-surface-variant/40 uppercase tracking-wide">
                                {item.shortcut}
                              </kbd>
                            )}
                            {isActive && (
                              <CornerDownLeft className="w-3 h-3 text-primary/60 shrink-0" />
                            )}
                          </div>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))
          )}
        </div>

        {/* Footer controls instruction */}
        <div className="h-9 px-4 border-t border-on-surface/5 flex items-center gap-4 text-[9px] font-bold text-on-surface-variant/30 uppercase tracking-wider bg-surface-container-low/40 shrink-0">
          <span className="flex items-center gap-1.5">
            <kbd className="bg-surface-container border border-outline/10 px-1 rounded">↑↓</kbd>
            <span>Navigate</span>
          </span>
          <span className="flex items-center gap-1.5">
            <kbd className="bg-surface-container border border-outline/10 px-1 rounded">Enter</kbd>
            <span>Select</span>
          </span>
          <span className="flex items-center gap-1.5 ml-auto">
            <kbd className="bg-surface-container border border-outline/10 px-1 rounded">Esc</kbd>
            <span>Close</span>
          </span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
