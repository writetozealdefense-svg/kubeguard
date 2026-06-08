import { describe, expect, it } from "vitest";
import { pathToFlow } from "./attackGraph";
import { mockAttackPaths } from "./api/mock";

describe("pathToFlow", () => {
  it("builds one node per capability and one edge per hop", () => {
    const path = mockAttackPaths.paths[0];
    const { nodes, edges } = pathToFlow(path);
    // 6 hops → 7 capability nodes, 6 edges.
    expect(nodes).toHaveLength(path.hops.length + 1);
    expect(edges).toHaveLength(path.hops.length);
  });

  it("the entry node has no arriving hop; later nodes carry their enabling hop", () => {
    const { nodes } = pathToFlow(mockAttackPaths.paths[0]);
    expect(nodes[0].data.hop).toBeNull();
    expect(nodes[0].data.entryResource).toContain("checkout-lb");
    // node 1 is reached via the first hop (KG-018), node 2 via the second (KG-001).
    expect(nodes[1].data.hop?.enabledBy).toBe("KG-018");
    expect(nodes[2].data.hop?.enabledBy).toBe("KG-001");
  });

  it("labels edges with the enabling finding and ATT&CK technique", () => {
    const { edges } = pathToFlow(mockAttackPaths.paths[0]);
    expect(edges[0].label).toContain("KG-018");
    expect(edges[0].label).toContain("T1190");
    expect(edges[0].source).toBe("n0");
    expect(edges[0].target).toBe("n1");
  });
});
