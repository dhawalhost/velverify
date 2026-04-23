import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const typographyVariants = cva(
  "text-foreground transition-colors",
  {
    variants: {
      variant: {
        h1: "scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl",
        h2: "scroll-m-20 border-b pb-2 text-3xl font-semibold tracking-tight first:mt-0",
        h3: "scroll-m-20 text-2xl font-semibold tracking-tight",
        h4: "scroll-m-20 text-xl font-semibold tracking-tight",
        p: "leading-7 [&:not(:first-child)]:mt-6",
        blockquote: "mt-6 border-l-2 pl-6 italic",
        list: "my-6 ml-6 list-disc [&>li]:mt-2",
        lead: "text-xl text-muted-foreground",
        large: "text-lg font-semibold",
        small: "text-sm font-medium leading-none",
        muted: "text-sm text-muted-foreground",
        label: "text-[11px] font-bold tracking-tight text-on-surface-variant/40",
        detail: "text-[10px] font-medium tracking-tight text-on-surface-variant/60",
        code: "relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm font-semibold",
      },
      textTransform: {
        normal: "normal-case",
        none: "",
      },
    },
    defaultVariants: {
      variant: "p",
      textTransform: "normal",
    },
  }
)

export interface TypographyProps
  extends React.HTMLAttributes<HTMLHeadingElement | HTMLParagraphElement | HTMLSpanElement>,
    VariantProps<typeof typographyVariants> {
  as?: "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "p" | "span" | "div" | "label"
}

const Typography = React.forwardRef<HTMLHeadingElement | HTMLParagraphElement | HTMLSpanElement, TypographyProps>(
  ({ className, variant, textTransform, as, ...props }, ref) => {
    const Component = as || (variant ? (["h1", "h2", "h3", "h4", "p", "label"].includes(variant) ? variant as any : "p") : "p")
    
    return (
      <Component
        ref={ref}
        className={cn(typographyVariants({ variant, textTransform, className }))}
        {...props}
      />
    )
  }
)
Typography.displayName = "Typography"

export { Typography, typographyVariants }
