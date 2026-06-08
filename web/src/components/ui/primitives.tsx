/** Minimal accessible design-system primitives (Radix-style API, Tailwind-styled). */
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

export const cn = (...parts: Array<string | undefined | false>) => twMerge(clsx(parts));

export function Card({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("rounded-lg border border-border bg-bg-surface p-4", className)} {...rest}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className }: { children: ReactNode; className?: string }) {
  return <h3 className={cn("text-sm font-medium text-fg-muted", className)}>{children}</h3>;
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
}
export function Button({ variant = "primary", className, ...rest }: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
        "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variant === "primary" && "bg-accent text-accent-fg hover:bg-accent/90",
        variant === "ghost" && "border border-border text-fg hover:bg-bg-raised",
        className,
      )}
      {...rest}
    />
  );
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium", className)}>
      {children}
    </span>
  );
}
