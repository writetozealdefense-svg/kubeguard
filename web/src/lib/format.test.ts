import { describe, expect, it } from "vitest";
import { breachLabel, passRateLabel, pct } from "./format";

describe("honest-metric formatters", () => {
  it("passRateLabel always shows the assessed denominator", () => {
    expect(passRateLabel(1, 9)).toBe("1 of 9 passed (11%)");
  });
  it("passRateLabel handles zero assessed without dividing by zero", () => {
    expect(passRateLabel(0, 0)).toBe("no controls assessed");
  });
  it("breachLabel shows breached of assessed", () => {
    expect(breachLabel(8, 9)).toBe("8 breached of 9 assessed");
  });
  it("pct rounds", () => {
    expect(pct(0.114)).toBe("11%");
  });
});
