import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import { Badge } from "./badge"

const statusBadgeVariants = cva(
  "font-bold text-[11px] tracking-tight px-3 py-1 shadow-none border-none rounded-xl",
  {
    variants: {
      status: {
        active: "bg-emerald-50 text-emerald-600",
        suspended: "bg-red-50 text-red-600",
        pending: "bg-amber-50 text-amber-600",
        inactive: "bg-gray-100 text-gray-600",
        premium: "bg-primary/5 text-primary",
      },
    },
    defaultVariants: {
      status: "active",
    },
  }
)

export interface StatusBadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof statusBadgeVariants> {
  children: React.ReactNode
}

function StatusBadge({ className, status, children, ...props }: StatusBadgeProps) {
  return (
    <Badge className={cn(statusBadgeVariants({ status, className }))} {...props}>
      {children}
    </Badge>
  )
}

export { StatusBadge, statusBadgeVariants }
