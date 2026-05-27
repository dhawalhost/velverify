// ── CSS STYLES (Design tokens) ──
import "./styles/global.css";

// ── UTILITIES ──
export { cn } from "./lib/utils";

// ── CORE COMPONENTS ──

// Button
export { Button, buttonVariants } from "./components/Button/Button";
export type { ButtonProps } from "./components/Button/Button";

// Input
export { Input } from "./components/Input/Input";
export type { InputProps } from "./components/Input/Input";

// Avatar
export { Avatar } from "./components/Avatar/Avatar";
export type { AvatarProps } from "./components/Avatar/Avatar";

// Badge
export { Badge, badgeVariants } from "./components/Badge/Badge";
export type { BadgeProps } from "./components/Badge/Badge";

// Card
export {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "./components/Card/Card";

// Dropdown
export {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuGroup,
  DropdownMenuPortal,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuRadioGroup,
} from "./components/Dropdown/Dropdown";

// Table
export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
  GlassTable,
  GlassTableHeader,
  GlassTableRow,
  GlassTableHead,
} from "./components/Table/Table";

// Label
export { Label } from "./components/Label/Label";

// Checkbox
export { Checkbox } from "./components/Checkbox/Checkbox";

// Select
export {
  Select,
  SelectGroup,
  SelectValue,
  SelectTrigger,
  SelectContent,
  SelectLabel,
  SelectItem,
  SelectSeparator,
} from "./components/Select/Select";

// Switch
export { Switch } from "./components/Switch/Switch";

// Dialog
export {
  Dialog,
  DialogPortal,
  DialogOverlay,
  DialogClose,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
} from "./components/Dialog/Dialog";

// Sheet
export {
  Sheet,
  SheetPortal,
  SheetOverlay,
  SheetTrigger,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetFooter,
  SheetTitle,
  SheetDescription,
} from "./components/Sheet/Sheet";

// Toast
export {
  ToastProvider,
  ToastViewport,
  Toast,
  ToastTitle,
  ToastDescription,
  ToastClose,
  ToastAction,
} from "./components/Toast/Toast";

// Tabs
export { Tabs, TabsList, TabsTrigger, TabsContent } from "./components/Tabs/Tabs";

// ScrollArea
export { ScrollArea, ScrollBar } from "./components/ScrollArea/ScrollArea";

// Separator
export { Separator } from "./components/Separator/Separator";

// Skeleton
export { Skeleton } from "./components/Skeleton/Skeleton";

// Progress
export { Progress } from "./components/Progress/Progress";
export type { ProgressProps } from "./components/Progress/Progress";

// Tooltip
export {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from "./components/Tooltip/Tooltip";

// Popover
export { Popover, PopoverTrigger, PopoverContent } from "./components/Popover/Popover";

// Accordion
export {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "./components/Accordion/Accordion";

// CommandMenu
export { CommandMenu } from "./components/CommandMenu/CommandMenu";
export type { CommandItem, CommandMenuProps } from "./components/CommandMenu/CommandMenu";

// Form
export { FormField, FormGroup, FormSection } from "./components/Form/Form";
export type { FormFieldProps, FormSectionProps } from "./components/Form/Form";

// Logo
export { Logo } from "./components/Logo/Logo";
export type { LogoProps } from "./components/Logo/Logo";

// Tailwind Preset
export { tailwindPreset } from "./tailwind-preset";

// ── LAYOUT SHELLS ──

// Grid
export { Grid, GridItem } from "./components/Grid/Grid";
export type {
  GridProps,
  GridItemProps,
  ResponsiveValue,
  GridCols,
  GridSpans,
  GridOffsets,
  GridGaps,
} from "./components/Grid/Grid";

// PageHeader
export { PageHeader } from "./layouts/PageHeader/PageHeader";
export type { PageHeaderProps, BreadcrumbItem } from "./layouts/PageHeader/PageHeader";

// AdminShell
export { AdminShell } from "./layouts/AdminShell/AdminShell";
export type {
  AdminShellProps,
  NavigationItem,
  NavigationGroup,
} from "./layouts/AdminShell/AdminShell";

// PortalLayout
export { PortalLayout } from "./layouts/PortalLayout/PortalLayout";
export type { PortalLayoutProps, PortalLink } from "./layouts/PortalLayout/PortalLayout";

// ── THEME SYSTEM ──
export { ThemeProvider, useTheme } from "./components/ThemeProvider/ThemeProvider";
export type { ThemeProviderProps, Theme } from "./components/ThemeProvider/ThemeProvider";
