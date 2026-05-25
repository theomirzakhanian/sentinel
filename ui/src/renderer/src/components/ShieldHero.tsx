/**
 * Hero shield-in-circle mark for the Overview page.
 * Matches the reference AV-style hero: one prominent violet-stroked ring, a
 * fainter outer pulse ring, and a shield-with-check glyph centered inside.
 */
import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";

interface Props {
  size?: number;
}

export function ShieldHero({ size = 300 }: Props) {
  return (
    <div
      className="relative"
      style={{ width: size, height: size }}
      aria-hidden
    >
      {/* Soft halo behind the main ring — slow breathing */}
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(155,130,245,0.22) 0%, rgba(155,130,245,0) 60%)",
        }}
        animate={{ opacity: [0.7, 1, 0.7] }}
        transition={{ duration: 5.5, ease: "easeInOut", repeat: Infinity }}
      />

      {/* MAIN RING — gentle ambient scale breath */}
      <motion.div
        className="absolute inset-[8%] rounded-full border-[1.5px]"
        style={{
          borderColor: "rgba(155, 130, 245, 0.55)",
          background:
            "radial-gradient(circle at 50% 25%, rgba(155,130,245,0.14) 0%, rgba(155,130,245,0.02) 60%, transparent 100%)",
          boxShadow:
            "0 0 50px rgba(155,130,245,0.25), inset 0 0 60px rgba(155,130,245,0.06)",
        }}
        animate={{ scale: [1, 1.012, 1] }}
        transition={{ duration: 5.5, ease: "easeInOut", repeat: Infinity }}
      >
        <div className="flex h-full w-full items-center justify-center">
          <ShieldCheckMark size={Math.round(size * 0.38)} />
        </div>
      </motion.div>
    </div>
  );
}

function ShieldCheckMark({ size }: { size: number }) {
  return (
    <ShieldCheck
      size={size}
      strokeWidth={1.5}
      style={{ color: "var(--color-accent)" }}
    />
  );
}
