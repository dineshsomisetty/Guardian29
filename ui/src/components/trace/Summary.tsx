import { ArrowRight } from "lucide-react";
import { Fragment } from "react";

/** Prints a trace summary, drawing the pipeline's "->" as a real arrow instead of ASCII. */
export default function Summary({ text }: { text: string }) {
  const parts = text.split(/\s*->\s*/);
  if (parts.length === 1) return <>{text}</>;
  return (
    <>
      {parts.map((p, i) => (
        <Fragment key={i}>
          {i > 0 && <ArrowRight className="sum-arrow" size={13} strokeWidth={2} aria-label="to" />}
          {p}
        </Fragment>
      ))}
    </>
  );
}
