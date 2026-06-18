import { useRef } from "react";

interface Props {
  loading: boolean;
  onFilePicked: (file: File) => void;
}

export default function FileDropzone({ loading, onFilePicked }: Props) {
  const inputRef = useRef<HTMLInputElement | null>(null);

  const openPicker = () => inputRef.current?.click();

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (loading) return;
    const file = event.dataTransfer.files?.[0];
    if (file) onFilePicked(file);
  };

  return (
    <div
      onDragOver={(event) => event.preventDefault()}
      onDrop={onDrop}
      onClick={openPicker}
      className="group cursor-pointer rounded-2xl border-2 border-dashed border-edge bg-panel/70 p-8 shadow-panel transition hover:border-accent"
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) onFilePicked(file);
        }}
      />

      <div className="mx-auto max-w-xl text-center">
        <p className="font-display text-2xl font-bold text-ink">Drop capture file here</p>
        <p className="mt-2 text-sm text-ink/70">Supports .pcap and .pcapng. Click to browse.</p>
        <p className="mt-4 font-mono text-xs uppercase tracking-wide text-ink/60">
          {loading ? "Analyzing packets..." : "Asynchronous upload + 10-minute auto-delete"}
        </p>
      </div>
    </div>
  );
}
