/**
 * Sentinel's mark — minimal geometric shield. Tesla-flavored:
 * weighty, no flourishes, single stroke, scales by font-size.
 */
import { type SVGProps } from "react";

interface Props extends SVGProps<SVGSVGElement> {
  size?: number;
}

export function ShieldGlyph({ size = 20, ...rest }: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...rest}
    >
      <path d="M10 2L3 4v5.5c0 4.2 2.9 7.4 7 8.5 4.1-1.1 7-4.3 7-8.5V4L10 2z" />
    </svg>
  );
}
