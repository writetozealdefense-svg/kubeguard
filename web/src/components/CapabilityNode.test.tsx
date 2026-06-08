import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { CapabilityNode } from "./CapabilityNode";
import type { FlowNodeData } from "@/lib/attackGraph";

const data: FlowNodeData = {
  label: "ContainerEscape",
  hop: { order: 2, from: "NetworkReachable", to: "ContainerEscape", enabledBy: "KG-001", technique: ["T1611"], narrative: "Privileged container allows breakout." },
};

describe("CapabilityNode (keyboard-accessible attack-graph node)", () => {
  it("is a focusable button with a descriptive aria-label", async () => {
    render(<CapabilityNode data={data} />);
    const btn = screen.getByRole("button", { name: /Capability ContainerEscape.*enabled by KG-001/ });
    btn.focus();
    expect(btn).toHaveFocus();
  });

  it("invokes onSelect on click and on keyboard activation", async () => {
    const onSelect = vi.fn();
    render(<CapabilityNode data={data} onSelect={onSelect} />);
    const btn = screen.getByRole("button");
    await userEvent.click(btn);
    btn.focus();
    await userEvent.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledTimes(2);
    expect(onSelect).toHaveBeenCalledWith(data);
  });
});
