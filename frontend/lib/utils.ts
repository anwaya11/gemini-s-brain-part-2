import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Standard utility function for combining class names with Tailwind CSS support.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
