import * as React from "react";
import { cn } from "../../lib/utils";

export interface FormFieldProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

const FormField = React.forwardRef<HTMLDivElement, FormFieldProps>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("space-y-2 w-full", className)} {...props} />
  )
);
FormField.displayName = "FormField";

const FormGroup = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("space-y-4 w-full", className)} {...props} />
  )
);
FormGroup.displayName = "FormGroup";

export interface FormSectionProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  description?: string;
}

const FormSection = React.forwardRef<HTMLDivElement, FormSectionProps>(
  ({ className, title, description, children, ...props }, ref) => (
    <div ref={ref} className={cn("space-y-4 border-b border-border/50 pb-6 mb-6 last:border-0 last:pb-0 last:mb-0", className)} {...props}>
      <div className="space-y-1">
        <h4 className="text-sm font-bold text-on-surface leading-none">{title}</h4>
        {description && (
          <p className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant/40 mt-0.5">{description}</p>
        )}
      </div>
      <div className="pt-2">{children}</div>
    </div>
  )
);
FormSection.displayName = "FormSection";

export { FormField, FormGroup, FormSection };
