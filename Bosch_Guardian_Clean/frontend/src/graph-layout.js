const COLUMN_WIDTH = 240;
const ROW_HEIGHT = 64;
const edgeKey = e => `${e.parent_id}>${e.child_id}`;

function adjacency(edges) {
  const children = new Map();
  const parents = new Map();
  for (const e of edges) {
    if (!children.has(e.parent_id)) children.set(e.parent_id, []);
    if (!parents.has(e.child_id)) parents.set(e.child_id, []);
    children.get(e.parent_id).push(e);
    parents.get(e.child_id).push(e);
  }
  return {children, parents};
}

// Restarts from any unvisited node so cycles unreachable from a root still get a depth.
function breadthFirst(ids, edges) {
  const {children, parents} = adjacency(edges);
  const depth = new Map();
  const via = new Map();
  const starts = [...ids.filter(id => !parents.has(id)), ...ids];
  for (const start of starts) {
    if (depth.has(start)) continue;
    depth.set(start, 0);
    const queue = [start];
    while (queue.length) {
      const current = queue.shift();
      for (const e of children.get(current) || []) {
        if (depth.has(e.child_id)) continue;
        depth.set(e.child_id, depth.get(current) + 1);
        via.set(e.child_id, e);
        queue.push(e.child_id);
      }
    }
  }
  return {depth, via};
}

function routeTo(id, via) {
  const route = [];
  for (let current = id; via.has(current); current = via.get(current).parent_id) {
    route.unshift(via.get(current));
  }
  return route;
}

export function selectSubgraph(graph, {all = false, path = [], focus = null, vulnerable}) {
  const known = new Set(graph.nodes.map(n => n.component_id));
  if (all) return {ids: known, edges: graph.edges};
  if (path.length) {
    const edges = path.slice(1).map((child, i) => graph.edges.find(e => e.parent_id === path[i] && e.child_id === child)
      ?? {parent_id: path[i], child_id: child, edge_source: 'path'});
    return {ids: new Set(path.filter(id => known.has(id))), edges};
  }
  const {via} = breadthFirst([...known], graph.edges);
  const ids = new Set();
  const chosen = new Map();
  const add = e => { chosen.set(edgeKey(e), e); ids.add(e.parent_id); ids.add(e.child_id); };
  const addRoute = id => { ids.add(id); routeTo(id, via).forEach(add); };
  if (focus) {
    addRoute(focus);
    const {children, parents} = adjacency(graph.edges);
    [...(parents.get(focus) || []), ...(children.get(focus) || [])].forEach(add);
  } else {
    [...vulnerable].filter(id => known.has(id)).forEach(addRoute);
  }
  return {ids, edges: [...chosen.values()]};
}

export function layoutSubgraph({ids, edges}) {
  const {depth} = breadthFirst([...ids].sort(), edges);
  const {parents} = adjacency(edges);
  const columns = [];
  for (const [id, d] of depth) (columns[d] ||= []).push(id);
  const row = new Map();
  const positions = new Map();
  columns.forEach((column, d) => {
    const weight = id => {
      const placed = (parents.get(id) || []).map(e => row.get(e.parent_id)).filter(r => r !== undefined);
      return placed.length ? placed.reduce((a, b) => a + b, 0) / placed.length : Infinity;
    };
    column.sort((a, b) => weight(a) - weight(b) || a.localeCompare(b));
    column.forEach((id, i) => {
      row.set(id, i);
      positions.set(id, {x: d * COLUMN_WIDTH, y: (i - (column.length - 1) / 2) * ROW_HEIGHT});
    });
  });
  return positions;
}
