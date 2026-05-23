import { useCallback, useState } from "react";
import { motion } from "framer-motion";
import { Upload } from "lucide-react";

interface Props {
  onFile: (path: string) => void;
}

export function DropZone({ onFile }: Props) {
  const [over, setOver] = useState(false);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setOver(false);
      const file = e.dataTransfer.files?.[0];
      if (!file) return;
      const p = window.sentinel.pathForFile(file);
      if (p) onFile(p);
    },
    [onFile],
  );

  const onPick = useCallback(async () => {
    const p = await window.sentinel.pickFile();
    if (p) onFile(p);
  }, [onFile]);

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      className={[
        "card-dark relative flex h-full w-full flex-col items-center justify-center gap-6 rounded-xl",
        "transition-all duration-base ease-tesla",
        over ? "border-accent/40 bg-surface-2" : "border-line",
      ].join(" ")}
    >
      <motion.div
        animate={{ opacity: over ? 1 : 0.92, scale: over ? 1.02 : 1 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col items-center gap-4"
      >
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-accent-tint text-accent">
          <Upload size={28} strokeWidth={1.75} />
        </div>
        <div className="text-center">
          <p className="text-base font-medium tracking-tight text-ink">
            Drop a binary to scan
          </p>
          <p className="mt-1 text-sm text-ink-muted">
            .exe, .dll, .elf, Mach-O — any file
          </p>
        </div>
        <button
          type="button"
          onClick={onPick}
          data-no-drag
          className="focus-ring rounded-md border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink-body transition-colors hover:bg-surface-3 hover:text-ink"
        >
          Choose file…
        </button>
      </motion.div>

      <p className="absolute bottom-6 text-xs text-ink-muted">
        Sentinel scans statically. Files are never executed.
      </p>
    </div>
  );
}
