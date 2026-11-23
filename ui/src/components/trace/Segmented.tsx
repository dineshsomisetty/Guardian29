import "../../styles/trace.css";

export interface SegOption<T extends string> {
  id: T;
  label: string;
  count?: number;
}

/** Square segmented control: one hairline box, the selected segment printed in custody ink. */
export default function Segmented<T extends string>({
  options, value, onChange, label,
}: {
  options: SegOption<T>[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="seg" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          role="radio"
          aria-checked={value === o.id}
          className="seg-opt"
          onClick={() => onChange(o.id)}
        >
          <span className="seg-name">{o.label}</span>
          {o.count !== undefined && <span className="seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
