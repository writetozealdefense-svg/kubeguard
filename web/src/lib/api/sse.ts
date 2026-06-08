/** Server-Sent Events frame parser (pure). The dashboard reads /v1/stream via
 * fetch streaming — not EventSource — so it can carry the bearer token. */
import { StreamEventSchema, type StreamEvent } from "./types";

export interface SSEParseResult {
  events: StreamEvent[];
  rest: string; // unparsed tail (incomplete frame) to prepend to the next chunk
}

/** Parse a buffer of SSE text into complete events, returning the leftover tail. */
export function parseSSE(buffer: string): SSEParseResult {
  const events: StreamEvent[] = [];
  const frames = buffer.split("\n\n");
  const rest = frames.pop() ?? ""; // last segment may be incomplete
  for (const frame of frames) {
    const dataLines = frame
      .split("\n")
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim());
    if (dataLines.length === 0) continue;
    try {
      const parsed = StreamEventSchema.parse(JSON.parse(dataLines.join("\n")));
      events.push(parsed);
    } catch {
      // ignore malformed frames (keepalives/comments)
    }
  }
  return { events, rest };
}
