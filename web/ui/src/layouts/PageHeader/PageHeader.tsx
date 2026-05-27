import * as React from "react";
import { cn } from "../../lib/utils";
import { ChevronRight } from "lucide-react";

export interface BreadcrumbItem {
  label: string;
  href?: string;
  onClick?: (e: React.MouseEvent<HTMLAnchorElement>) => void;
}

export interface PageHeaderProps extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  title: React.ReactNode;
  description?: React.ReactNode;
  breadcrumbs?: BreadcrumbItem[];
  actions?: React.ReactNode;
  search?: React.ReactNode;
}

const PageHeader = React.forwardRef<HTMLDivElement, PageHeaderProps>(
  ({ className, title, description, breadcrumbs, actions, search, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "flex flex-col space-y-4 md:space-y-0 md:flex-row md:items-center md:justify-between border-b border-border bg-background/50 backdrop-blur-sm py-5 px-6 shrink-0 transition-all",
          className
        )}
        {...props}
      >
        {/* Title & Navigation */}
        <div className="flex flex-col space-y-1.5 flex-1 min-w-0">
          {/* Breadcrumbs */}
          {breadcrumbs && breadcrumbs.length > 0 && (
            <nav className="flex items-center space-x-1.5 text-xs text-on-surface-variant/40 font-bold uppercase tracking-wider mb-1 flex-wrap">
              {breadcrumbs.map((crumb, idx) => {
                const isLast = idx === breadcrumbs.length - 1;
                return (
                  <React.Fragment key={crumb.label + idx}>
                    {idx > 0 && <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-40" />}
                    {crumb.href && !isLast ? (
                      <a
                        href={crumb.href}
                        onClick={crumb.onClick}
                        className="hover:text-primary transition-colors cursor-pointer"
                      >
                        {crumb.label}
                      </a>
                    ) : (
                      <span className={isLast ? "text-on-surface-variant/75" : ""}>{crumb.label}</span>
                    )}
                  </React.Fragment>
                );
              })}
            </nav>
          )}

          {/* Title */}
          <h1 className="text-xl md:text-2xl font-bold tracking-tight text-on-surface truncate">
            {title}
          </h1>

          {/* Description */}
          {description && (
            <p className="text-xs md:text-sm text-on-surface-variant/60 font-medium">
              {description}
            </p>
          )}
        </div>

        {/* Actions & Filters */}
        <div className="flex items-center space-x-3 shrink-0">
          {search && <div className="w-full md:w-64">{search}</div>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      </div>
    );
  }
);
PageHeader.displayName = "PageHeader";

export { PageHeader };
