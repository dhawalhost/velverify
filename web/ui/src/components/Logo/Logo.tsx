import * as React from "react";
import { cn } from "../../lib/utils";

export interface LogoProps extends React.SVGAttributes<SVGSVGElement> {
  variant?: "icon" | "full";
  logoColor?: "brand" | "mono"; // 'brand' uses primary HSL color, 'mono' inherits currentColor
  textColor?: "white" | "mono";  // 'white' uses Zinc-50 white, 'mono' inherits currentColor
}

export const Logo = React.forwardRef<SVGSVGElement, LogoProps>(
  (
    {
      variant = "full",
      logoColor = "brand",
      textColor = "white",
      className,
      width,
      height,
      ...props
    },
    ref
  ) => {
    // Resolve colors to hook dynamically into Tailwind custom presets
    const brandColor = "hsl(var(--primary))";
    const logoFill = logoColor === "brand" ? brandColor : "currentColor";
    const textFill = textColor === "white" ? "#fafafa" : "currentColor";

    if (variant === "icon") {
      return (
        <svg
          ref={ref}
          width={width || "349"}
          height={height || "408"}
          viewBox="-4 -4 349 408"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className={cn("select-none flex-shrink-0", className)}
          {...props}
        >
          <path
            d="M171.642 0L0 45V194.776C8.35821 317.164 118.408 382.587 172.388 400C227.281 378.705 265.311 349.284 291.113 318.657C330.416 272.005 340.298 222.388 340.298 194.776V45.5224L171.642 0Z"
            fill="none"
            stroke={logoFill}
            strokeWidth="4"
          />
          <path
            d="M45 200.205V33.1992L76.1836 25.0195V166.387L172.704 45.3927L246.761 134.823L217.995 147.599L172.704 91.9868L85.0931 211.359L45 200.205Z"
            fill={logoFill}
          />
          <path
            d="M85.0931 231.769L45 222.579C47.7224 248.131 80.6384 306.32 172.704 346C270.71 306.32 301.854 246.494 298.923 194.155L262.396 211.359C264.623 270.729 205.373 298.654 172.704 312.182C118.653 288.133 91.7753 248.553 85.0931 231.769Z"
            fill={logoFill}
          />
          <path
            d="M316 134.823C237.299 135.981 179.386 202.46 129.641 253.563L154.885 273.103C243.238 180.666 276.649 171.648 311.545 166.387L316 134.823Z"
            fill={logoFill}
          />
          <path
            d="M269.225 122.799V37.126L298.923 45.3927V115.284L269.225 122.799Z"
            fill={logoFill}
          />
        </svg>
      );
    }

    return (
      <svg
        ref={ref}
        width={width || "1800"}
        height={height || "408"}
        viewBox="0 0 1800 408"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className={cn("select-none flex-shrink-0", className)}
        {...props}
      >
        <g transform="translate(4, 4)">
          <path
            d="M171.642 0L0 45V194.776C8.35821 317.164 118.408 382.587 172.388 400C227.281 378.705 265.311 349.284 291.113 318.657C330.416 272.005 340.298 222.388 340.298 194.776V45.5224L171.642 0Z"
            fill="none"
            stroke={logoFill}
            strokeWidth="4"
          />
          <path
            d="M45 200.205V33.1992L76.1836 25.0195V166.387L172.704 45.3927L246.761 134.823L217.995 147.599L172.704 91.9868L85.0931 211.359L45 200.205Z"
            fill={logoFill}
          />
          <path
            d="M85.0931 231.769L45 222.579C47.7224 248.131 80.6384 306.32 172.704 346C270.71 306.32 301.854 246.494 298.923 194.155L262.396 211.359C264.623 270.729 205.373 298.654 172.704 312.182C118.653 288.133 91.7753 248.553 85.0931 231.769Z"
            fill={logoFill}
          />
          <path
            d="M316 134.823C237.299 135.981 179.386 202.46 129.641 253.563L154.885 273.103C243.238 180.666 276.649 171.648 311.545 166.387L316 134.823Z"
            fill={logoFill}
          />
          <path
            d="M269.225 122.799V37.126L298.923 45.3927V115.284L269.225 122.799Z"
            fill={logoFill}
          />
        </g>
        <text
          x="420"
          y="300"
          fontFamily="Inter, system-ui, sans-serif"
          fontWeight="800"
          fontSize="280"
          fill={textFill}
          letterSpacing="-0.03em"
        >
          WardSeal
        </text>
      </svg>
    );
  }
);

Logo.displayName = "Logo";
