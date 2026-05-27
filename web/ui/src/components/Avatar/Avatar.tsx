import * as React from "react";
import BoringAvatar from "boring-avatars";
import { cn } from "../../lib/utils";

export interface AvatarProps extends React.HTMLAttributes<HTMLDivElement> {
  name: string;
  size?: number;
  variant?: "marble" | "beam" | "pixel" | "sunset" | "ring" | "bauhaus";
}

const Avatar = React.forwardRef<HTMLDivElement, AvatarProps>(
  ({ className, name, size = 32, variant = "marble", ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "relative flex shrink-0 items-center justify-center overflow-hidden rounded-lg bg-surface-container border border-on-surface/5 shadow-sm transition-transform hover:scale-105 duration-200",
          className
        )}
        style={{ width: size, height: size }}
        {...props}
      >
        <BoringAvatar
          size={size}
          name={name}
          variant={variant}
          colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
        />
      </div>
    );
  }
);
Avatar.displayName = "Avatar";

export { Avatar };
