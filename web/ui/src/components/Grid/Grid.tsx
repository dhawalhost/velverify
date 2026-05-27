import * as React from "react";
import { cn } from "../../lib/utils";

export type ResponsiveValue<T> =
  | T
  | {
      base?: T;
      sm?: T;
      md?: T;
      lg?: T;
      xl?: T;
      "2xl"?: T;
    };

export type GridCols = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;
export type GridSpans = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | "full" | "auto";
export type GridOffsets = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | "auto";
export type GridGaps = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 10 | 12 | 16 | "page" | "section" | "card" | "none";

// Static mapping tables so Tailwind JIT compiler detects and bundles the utility classes
const colsMap = {
  1: "grid-cols-1",
  2: "grid-cols-2",
  3: "grid-cols-3",
  4: "grid-cols-4",
  5: "grid-cols-5",
  6: "grid-cols-6",
  7: "grid-cols-7",
  8: "grid-cols-8",
  9: "grid-cols-9",
  10: "grid-cols-10",
  11: "grid-cols-11",
  12: "grid-cols-12",
} as const;

const smColsMap = {
  1: "sm:grid-cols-1",
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-3",
  4: "sm:grid-cols-4",
  5: "sm:grid-cols-5",
  6: "sm:grid-cols-6",
  7: "sm:grid-cols-7",
  8: "sm:grid-cols-8",
  9: "sm:grid-cols-9",
  10: "sm:grid-cols-10",
  11: "sm:grid-cols-11",
  12: "sm:grid-cols-12",
} as const;

const mdColsMap = {
  1: "md:grid-cols-1",
  2: "md:grid-cols-2",
  3: "md:grid-cols-3",
  4: "md:grid-cols-4",
  5: "md:grid-cols-5",
  6: "md:grid-cols-6",
  7: "md:grid-cols-7",
  8: "md:grid-cols-8",
  9: "md:grid-cols-9",
  10: "md:grid-cols-10",
  11: "md:grid-cols-11",
  12: "md:grid-cols-12",
} as const;

const lgColsMap = {
  1: "lg:grid-cols-1",
  2: "lg:grid-cols-2",
  3: "lg:grid-cols-3",
  4: "lg:grid-cols-4",
  5: "lg:grid-cols-5",
  6: "lg:grid-cols-6",
  7: "lg:grid-cols-7",
  8: "lg:grid-cols-8",
  9: "lg:grid-cols-9",
  10: "lg:grid-cols-10",
  11: "lg:grid-cols-11",
  12: "lg:grid-cols-12",
} as const;

const xlColsMap = {
  1: "xl:grid-cols-1",
  2: "xl:grid-cols-2",
  3: "xl:grid-cols-3",
  4: "xl:grid-cols-4",
  5: "xl:grid-cols-5",
  6: "xl:grid-cols-6",
  7: "xl:grid-cols-7",
  8: "xl:grid-cols-8",
  9: "xl:grid-cols-9",
  10: "xl:grid-cols-10",
  11: "xl:grid-cols-11",
  12: "xl:grid-cols-12",
} as const;

const xxlColsMap = {
  1: "2xl:grid-cols-1",
  2: "2xl:grid-cols-2",
  3: "2xl:grid-cols-3",
  4: "2xl:grid-cols-4",
  5: "2xl:grid-cols-5",
  6: "2xl:grid-cols-6",
  7: "2xl:grid-cols-7",
  8: "2xl:grid-cols-8",
  9: "2xl:grid-cols-9",
  10: "2xl:grid-cols-10",
  11: "2xl:grid-cols-11",
  12: "2xl:grid-cols-12",
} as const;

const gapMap = {
  0: "gap-0",
  1: "gap-1",
  2: "gap-2",
  3: "gap-3",
  4: "gap-4",
  5: "gap-5",
  6: "gap-6",
  8: "gap-8",
  10: "gap-10",
  12: "gap-12",
  16: "gap-16",
  page: "gap-page",
  section: "gap-section",
  card: "gap-card",
  none: "gap-0",
} as const;

const smGapMap = {
  0: "sm:gap-0",
  1: "sm:gap-1",
  2: "sm:gap-2",
  3: "sm:gap-3",
  4: "sm:gap-4",
  5: "sm:gap-5",
  6: "sm:gap-6",
  8: "sm:gap-8",
  10: "sm:gap-10",
  12: "sm:gap-12",
  16: "sm:gap-16",
  page: "sm:gap-page",
  section: "sm:gap-section",
  card: "sm:gap-card",
  none: "sm:gap-0",
} as const;

const mdGapMap = {
  0: "md:gap-0",
  1: "md:gap-1",
  2: "md:gap-2",
  3: "md:gap-3",
  4: "md:gap-4",
  5: "md:gap-5",
  6: "md:gap-6",
  8: "md:gap-8",
  10: "md:gap-10",
  12: "md:gap-12",
  16: "md:gap-16",
  page: "md:gap-page",
  section: "md:gap-section",
  card: "md:gap-card",
  none: "md:gap-0",
} as const;

const lgGapMap = {
  0: "lg:gap-0",
  1: "lg:gap-1",
  2: "lg:gap-2",
  3: "lg:gap-3",
  4: "lg:gap-4",
  5: "lg:gap-5",
  6: "lg:gap-6",
  8: "lg:gap-8",
  10: "lg:gap-10",
  12: "lg:gap-12",
  16: "lg:gap-16",
  page: "lg:gap-page",
  section: "lg:gap-section",
  card: "lg:gap-card",
  none: "lg:gap-0",
} as const;

const xlGapMap = {
  0: "xl:gap-0",
  1: "xl:gap-1",
  2: "xl:gap-2",
  3: "xl:gap-3",
  4: "xl:gap-4",
  5: "xl:gap-5",
  6: "xl:gap-6",
  8: "xl:gap-8",
  10: "xl:gap-10",
  12: "xl:gap-12",
  16: "xl:gap-16",
  page: "xl:gap-page",
  section: "xl:gap-section",
  card: "xl:gap-card",
  none: "xl:gap-0",
} as const;

const xxlGapMap = {
  0: "2xl:gap-0",
  1: "2xl:gap-1",
  2: "2xl:gap-2",
  3: "2xl:gap-3",
  4: "2xl:gap-4",
  5: "2xl:gap-5",
  6: "2xl:gap-6",
  8: "2xl:gap-8",
  10: "2xl:gap-10",
  12: "2xl:gap-12",
  16: "2xl:gap-16",
  page: "2xl:gap-page",
  section: "2xl:gap-section",
  card: "2xl:gap-card",
  none: "2xl:gap-0",
} as const;

const spanMap = {
  1: "col-span-1",
  2: "col-span-2",
  3: "col-span-3",
  4: "col-span-4",
  5: "col-span-5",
  6: "col-span-6",
  7: "col-span-7",
  8: "col-span-8",
  9: "col-span-9",
  10: "col-span-10",
  11: "col-span-11",
  12: "col-span-12",
  full: "col-span-full",
  auto: "col-span-auto",
} as const;

const smSpanMap = {
  1: "sm:col-span-1",
  2: "sm:col-span-2",
  3: "sm:col-span-3",
  4: "sm:col-span-4",
  5: "sm:col-span-5",
  6: "sm:col-span-6",
  7: "sm:col-span-7",
  8: "sm:col-span-8",
  9: "sm:col-span-9",
  10: "sm:col-span-10",
  11: "sm:col-span-11",
  12: "sm:col-span-12",
  full: "sm:col-span-full",
  auto: "sm:col-span-auto",
} as const;

const mdSpanMap = {
  1: "md:col-span-1",
  2: "md:col-span-2",
  3: "md:col-span-3",
  4: "md:col-span-4",
  5: "md:col-span-5",
  6: "md:col-span-6",
  7: "md:col-span-7",
  8: "md:col-span-8",
  9: "md:col-span-9",
  10: "md:col-span-10",
  11: "md:col-span-11",
  12: "md:col-span-12",
  full: "md:col-span-full",
  auto: "md:col-span-auto",
} as const;

const lgSpanMap = {
  1: "lg:col-span-1",
  2: "lg:col-span-2",
  3: "lg:col-span-3",
  4: "lg:col-span-4",
  5: "lg:col-span-5",
  6: "lg:col-span-6",
  7: "lg:col-span-7",
  8: "lg:col-span-8",
  9: "lg:col-span-9",
  10: "lg:col-span-10",
  11: "lg:col-span-11",
  12: "lg:col-span-12",
  full: "lg:col-span-full",
  auto: "lg:col-span-auto",
} as const;

const xlSpanMap = {
  1: "xl:col-span-1",
  2: "xl:col-span-2",
  3: "xl:col-span-3",
  4: "xl:col-span-4",
  5: "xl:col-span-5",
  6: "xl:col-span-6",
  7: "xl:col-span-7",
  8: "xl:col-span-8",
  9: "xl:col-span-9",
  10: "xl:col-span-10",
  11: "xl:col-span-11",
  12: "xl:col-span-12",
  full: "xl:col-span-full",
  auto: "xl:col-span-auto",
} as const;

const xxlSpanMap = {
  1: "2xl:col-span-1",
  2: "2xl:col-span-2",
  3: "2xl:col-span-3",
  4: "2xl:col-span-4",
  5: "2xl:col-span-5",
  6: "2xl:col-span-6",
  7: "2xl:col-span-7",
  8: "2xl:col-span-8",
  9: "2xl:col-span-9",
  10: "2xl:col-span-10",
  11: "2xl:col-span-11",
  12: "2xl:col-span-12",
  full: "2xl:col-span-full",
  auto: "2xl:col-span-auto",
} as const;

const offsetMap = {
  1: "col-start-1",
  2: "col-start-2",
  3: "col-start-3",
  4: "col-start-4",
  5: "col-start-5",
  6: "col-start-6",
  7: "col-start-7",
  8: "col-start-8",
  9: "col-start-9",
  10: "col-start-10",
  11: "col-start-11",
  12: "col-start-12",
  auto: "col-start-auto",
} as const;

const smOffsetMap = {
  1: "sm:col-start-1",
  2: "sm:col-start-2",
  3: "sm:col-start-3",
  4: "sm:col-start-4",
  5: "sm:col-start-5",
  6: "sm:col-start-6",
  7: "sm:col-start-7",
  8: "sm:col-start-8",
  9: "sm:col-start-9",
  10: "sm:col-start-10",
  11: "sm:col-start-11",
  12: "sm:col-start-12",
  auto: "sm:col-start-auto",
} as const;

const mdOffsetMap = {
  1: "md:col-start-1",
  2: "md:col-start-2",
  3: "md:col-start-3",
  4: "md:col-start-4",
  5: "md:col-start-5",
  6: "md:col-start-6",
  7: "md:col-start-7",
  8: "md:col-start-8",
  9: "md:col-start-9",
  10: "md:col-start-10",
  11: "md:col-start-11",
  12: "md:col-start-12",
  auto: "md:col-start-auto",
} as const;

const lgOffsetMap = {
  1: "lg:col-start-1",
  2: "lg:col-start-2",
  3: "lg:col-start-3",
  4: "lg:col-start-4",
  5: "lg:col-start-5",
  6: "lg:col-start-6",
  7: "lg:col-start-7",
  8: "lg:col-start-8",
  9: "lg:col-start-9",
  10: "lg:col-start-10",
  11: "lg:col-start-11",
  12: "lg:col-start-12",
  auto: "lg:col-start-auto",
} as const;

const xlOffsetMap = {
  1: "xl:col-start-1",
  2: "xl:col-start-2",
  3: "xl:col-start-3",
  4: "xl:col-start-4",
  5: "xl:col-start-5",
  6: "xl:col-start-6",
  7: "xl:col-start-7",
  8: "xl:col-start-8",
  9: "xl:col-start-9",
  10: "xl:col-start-10",
  11: "xl:col-start-11",
  12: "xl:col-start-12",
  auto: "xl:col-start-auto",
} as const;

const xxlOffsetMap = {
  1: "2xl:col-start-1",
  2: "2xl:col-start-2",
  3: "2xl:col-start-3",
  4: "2xl:col-start-4",
  5: "2xl:col-start-5",
  6: "2xl:col-start-6",
  7: "2xl:col-start-7",
  8: "2xl:col-start-8",
  9: "2xl:col-start-9",
  10: "2xl:col-start-10",
  11: "2xl:col-start-11",
  12: "2xl:col-start-12",
  auto: "2xl:col-start-auto",
} as const;

function getResponsiveClasses<T extends string | number>(
  value: ResponsiveValue<T> | undefined,
  baseMap: Record<T, string>,
  smMap: Record<T, string>,
  mdMap: Record<T, string>,
  lgMap: Record<T, string>,
  xlMap: Record<T, string>,
  xxlMap: Record<T, string>
): string[] {
  if (value === undefined) return [];
  if (typeof value !== "object") {
    const val = value as T;
    return [baseMap[val] || ""];
  }

  const classes: string[] = [];
  const obj = value as {
    base?: T;
    sm?: T;
    md?: T;
    lg?: T;
    xl?: T;
    "2xl"?: T;
  };

  if (obj.base !== undefined) classes.push(baseMap[obj.base] || "");
  if (obj.sm !== undefined) classes.push(smMap[obj.sm] || "");
  if (obj.md !== undefined) classes.push(mdMap[obj.md] || "");
  if (obj.lg !== undefined) classes.push(lgMap[obj.lg] || "");
  if (obj.xl !== undefined) classes.push(xlMap[obj.xl] || "");
  if (obj["2xl"] !== undefined) classes.push(xxlMap[obj["2xl"]] || "");

  return classes.filter(Boolean);
}

export interface GridProps extends React.HTMLAttributes<HTMLElement> {
  cols?: ResponsiveValue<GridCols>;
  gap?: ResponsiveValue<GridGaps>;
  as?: React.ElementType;
}

export const Grid = React.forwardRef<HTMLElement, GridProps>(
  ({ children, className, cols = 1, gap, as: Component = "div", ...props }, ref) => {
    const colsClasses = getResponsiveClasses(
      cols,
      colsMap,
      smColsMap,
      mdColsMap,
      lgColsMap,
      xlColsMap,
      xxlColsMap
    );

    const gapClasses = gap
      ? getResponsiveClasses(
          gap,
          gapMap,
          smGapMap,
          mdGapMap,
          lgGapMap,
          xlGapMap,
          xxlGapMap
        )
      : [];

    return (
      <Component
        ref={ref as any}
        className={cn("grid", colsClasses, gapClasses, className)}
        {...props}
      >
        {children}
      </Component>
    );
  }
);
Grid.displayName = "Grid";

export interface GridItemProps extends React.HTMLAttributes<HTMLElement> {
  span?: ResponsiveValue<GridSpans>;
  offset?: ResponsiveValue<GridOffsets>;
  as?: React.ElementType;
}

export const GridItem = React.forwardRef<HTMLElement, GridItemProps>(
  ({ children, className, span, offset, as: Component = "div", ...props }, ref) => {
    const spanClasses = span
      ? getResponsiveClasses(
          span,
          spanMap,
          smSpanMap,
          mdSpanMap,
          lgSpanMap,
          xlSpanMap,
          xxlSpanMap
        )
      : [];

    const offsetClasses = offset
      ? getResponsiveClasses(
          offset,
          offsetMap,
          smOffsetMap,
          mdOffsetMap,
          lgOffsetMap,
          xlOffsetMap,
          xxlOffsetMap
        )
      : [];

    return (
      <Component
        ref={ref as any}
        className={cn(spanClasses, offsetClasses, className)}
        {...props}
      >
        {children}
      </Component>
    );
  }
);
GridItem.displayName = "GridItem";
