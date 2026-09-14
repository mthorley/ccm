/* CSF sunburst (static, plain SVG) and shared lookups. The SP 800-53 wheel lives in sunburst-zoom.js (d3).
   A hierarchy of {id, children, weight?, fill, label, labelClass, status?} is laid out as concentric rings
   (depth 0 innermost); leaves get equal angular weight unless a node sets `weight`. A thin outer evidence
   ring is painted from the status of nodes at `statusDepth`. */

const STATUS = {
  pass: { label: 'Pass', icon: '✓', color: 'var(--status-good)' },
  warn: { label: 'Warn', icon: '!', color: 'var(--status-warning)' },
  fail: { label: 'Fail', icon: '✕', color: 'var(--status-critical)' },
  unknown: { label: 'No scan data', icon: '?', color: 'var(--status-none)' },
  unmapped: { label: 'No TLS policy mapped', icon: '·', color: 'var(--status-none)' },
};

const SIZE = 640;
const CENTER = SIZE / 2;
const TAU = Math.PI * 2;
const START = -Math.PI / 2; // 12 o'clock, clockwise like csf.tools

function polar(r, angle) {
  return [CENTER + r * Math.cos(angle), CENTER + r * Math.sin(angle)];
}

function arcPath(r0, r1, a0, a1) {
  const large = a1 - a0 > Math.PI ? 1 : 0;
  const [x0, y0] = polar(r1, a0), [x1, y1] = polar(r1, a1), [x2, y2] = polar(r0, a1), [x3, y3] = polar(r0, a0);
  return `M${x0.toFixed(2)},${y0.toFixed(2)}A${r1},${r1},0,${large},1,${x1.toFixed(2)},${y1.toFixed(2)}` +
         `L${x2.toFixed(2)},${y2.toFixed(2)}A${r0},${r0},0,${large},0,${x3.toFixed(2)},${y3.toFixed(2)}Z`;
}

function esc(text) {
  return String(text ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* Radial label: text runs along the radius, flipped on the left half so it never reads upside down. */
function radialLabel(text, r, angle, cls) {
  const deg = (angle * 180) / Math.PI;
  const left = deg > 90 && deg < 270;
  const [x, y] = polar(r, angle);
  const rotate = left ? deg + 180 : deg;
  const anchor = left ? 'end' : 'start';
  return `<text class="arc-label ${cls}" x="${x.toFixed(2)}" y="${y.toFixed(2)}" text-anchor="${anchor}" dominant-baseline="middle" transform="rotate(${rotate.toFixed(2)},${x.toFixed(2)},${y.toFixed(2)})">${esc(text)}</text>`;
}

function weightOf(node) {
  if (node.weight != null) return node.weight;
  if (!node.children || !node.children.length) return 1;
  return node.children.reduce((sum, child) => sum + weightOf(child), 0);
}

function renderSunburst(root, options) {
  const { rings, statusRing, statusDepth, centerLines } = options;
  const total = weightOf(root);
  const paths = [], labels = [], statusArcs = [];

  function layout(node, depth, a0, a1) {
    const [r0, r1] = rings[depth];
    const mid = (a0 + a1) / 2;
    paths.push(`<path data-id="${esc(node.id)}" tabindex="0" role="button" aria-label="${esc(node.aria || node.id)}" d="${arcPath(r0, r1, a0, a1)}" fill="${node.fill}"${node.emphasis ? ' class="emphasis"' : ''}><title>${esc(node.aria || node.id)}</title></path>`);
    if (node.label) {
      if (node.labelMode === 'upright') {
        const [lx, ly] = polar((r0 + r1) / 2, mid);
        labels.push(`<text class="arc-label ${node.labelClass || ''}" x="${lx.toFixed(2)}" y="${ly.toFixed(2)}" text-anchor="middle" dominant-baseline="middle">${esc(node.label)}</text>`);
      } else {
        labels.push(radialLabel(node.label, r0 + 6, mid, node.labelClass || ''));
      }
    }
    if (depth === statusDepth) {
      const status = STATUS[node.status] || STATUS.unmapped;
      statusArcs.push(`<path class="status-arc" d="${arcPath(statusRing[0], statusRing[1], a0, a1)}" fill="${status.color}" opacity="${node.status === 'unmapped' ? 0.5 : 1}"></path>`);
    }
    let angle = a0;
    for (const child of node.children || []) {
      const span = ((a1 - a0) * weightOf(child)) / weightOf(node);
      layout(child, depth + 1, angle, angle + span);
      angle += span;
    }
  }
  let angle = START;
  for (const child of root.children) {
    const span = (TAU * weightOf(child)) / total;
    layout(child, 0, angle, angle + span);
    angle += span;
  }

  const center = centerLines.map((line, i) =>
    `<text class="center" x="${CENTER}" y="${CENTER + (i - (centerLines.length - 1) / 2) * 16}" text-anchor="middle" dominant-baseline="middle">${esc(line)}</text>`).join('');
  return `<svg viewBox="0 0 ${SIZE} ${SIZE}" role="img" aria-label="${esc(root.aria || root.id)}">
    <g>${paths.join('')}</g><g>${statusArcs.join('')}</g><g>${labels.join('')}</g>${center}</svg>`;
}

/* ---- NIST CSF: functions -> categories -> subcategories, coloured by function -------------------- */

function csfHierarchy(csf) {
  const fnColor = id => `var(--csf-${id.toLowerCase()})`;
  const covered = csf.summary.pass + csf.summary.warn + csf.summary.fail;
  return {
    root: {
      id: 'csf', aria: `NIST CSF ${csf.version} sunburst`,
      children: csf.functions.map(fn => ({
        id: fn.id, aria: `${fn.id}: ${fn.title}`, fill: fnColor(fn.id), label: fn.id, labelClass: 'fn', labelMode: 'upright',
        children: fn.categories.map(cat => ({
          id: cat.id, aria: `${cat.id}: ${cat.title}`, fill: `color-mix(in oklab, ${fnColor(fn.id)} 68%, var(--panel))`, label: cat.id, labelClass: 'cat',
          children: cat.subcategories.map(sub => ({
            id: sub.id, aria: `${sub.id}: ${sub.statement}`, fill: `color-mix(in oklab, ${fnColor(fn.id)} 42%, var(--panel))`,
            label: sub.id, labelClass: 'sub', status: sub.status,
          })),
        })),
      })),
    },
    options: { rings: [[72, 130], [134, 200], [204, 300]], statusRing: [304, 314], statusDepth: 2, centerLines: [`CSF ${csf.version}`, `${covered}/${csf.summary.subcategories} evidenced`] },
  };
}

/* ---- hierarchies for the zoomable renderer (sunburst-zoom.js) -------------------------------- */

function csfZoomHierarchy(csf) {
  const fnColor = id => `var(--csf-${id.toLowerCase()})`;
  const covered = csf.summary.pass + csf.summary.warn + csf.summary.fail;
  return {
    data: {
      id: 'csf', title: `NIST CSF ${csf.version}`, kind: 'root',
      children: csf.functions.map(fn => ({
        id: fn.id, title: fn.title, kind: 'function', fill: fnColor(fn.id), labelClass: 'fn', alwaysLabel: true,
        children: fn.categories.map(cat => ({
          id: cat.id, title: cat.title, kind: 'category', fill: `color-mix(in oklab, ${fnColor(fn.id)} 68%, var(--panel))`, labelClass: 'cat', alwaysLabel: true,
          children: cat.subcategories.map(sub => ({
            id: sub.id, title: sub.statement, kind: 'subcategory', fill: `color-mix(in oklab, ${fnColor(fn.id)} 42%, var(--panel))`,
            labelClass: 'sub', status: sub.status, value: 1,
          })),
        })),
      })),
    },
    options: {
      levels: 3, ariaLabel: `NIST CSF ${csf.version} zoomable sunburst`,
      centre: (node, depth) => node ? [node.id, depth === 1 ? titleCaseText(node.title) : (depth === 2 ? node.title : 'click centre to go up')] : [`CSF ${csf.version}`, `${covered}/${csf.summary.subcategories} evidenced`],
    },
  };
}

function sp80053ZoomHierarchy(data) {
  const covered = data.summary.pass + data.summary.warn + data.summary.fail;
  return {
    data: {
      id: 'sp800-53', title: `SP 800-53 r${data.version}`, kind: 'root',
      children: data.families.map((family, i) => ({
        id: family.id, title: family.title, kind: 'family', labelClass: 'fn', alwaysLabel: true,
        fill: i % 2 ? 'var(--ring-neutral-a)' : 'var(--ring-neutral-b)',
        children: family.controls.map(control => ({
          id: control.id, title: control.title, kind: 'control', status: control.status, evidenced: control.evidenced, labelClass: 'cat', alwaysLabel: control.evidenced,
          fill: control.evidenced ? 'var(--accent)' : (i % 2 ? 'var(--ring-neutral-a-dim)' : 'var(--ring-neutral-b-dim)'),
          children: control.enhancements.length ? control.enhancements.map(e => ({
            id: e.id, title: e.title, kind: 'enhancement', status: e.status, evidenced: e.policies.length > 0, labelClass: 'cat', alwaysLabel: e.policies.length > 0,
            fill: e.policies.length ? 'var(--accent)' : (i % 2 ? 'var(--ring-neutral-a-dim)' : 'var(--ring-neutral-b-dim)'),
            value: 1 / control.enhancements.length,
          })) : undefined,
          value: control.enhancements.length ? undefined : 1,
        })),
      })),
    },
    options: {
      levels: 2, ariaLabel: `NIST SP 800-53 r${data.version} zoomable sunburst`,
      centre: (node, depth) => node ? [node.id, depth === 1 ? node.title : 'click centre to go up'] : [`SP 800-53 r${data.version}`, `${covered}/${data.summary.controls} controls evidenced`],
    },
  };
}

function titleCaseText(text) {
  return (text || '').toLowerCase().replace(/(^|\s)\S/g, m => m.toUpperCase());
}

/* ---- lookups for the details panel ------------------------------------------------------------- */

function findCsfNode(csf, id) {
  for (const fn of csf.functions) {
    if (fn.id === id) return { ...fn, kind: 'function', path: 'CSF function', text: fn.description };
    for (const cat of fn.categories) {
      if (cat.id === id) return { ...cat, kind: 'category', path: `${fn.id} › category`, text: cat.description };
      for (const sub of cat.subcategories) {
        if (sub.id === id) return { ...sub, kind: 'subcategory', path: `${fn.id} › ${cat.id} › subcategory`, title: '', text: sub.statement };
      }
    }
  }
  return null;
}

function findSp80053Node(data, id) {
  for (const family of data.families) {
    if (family.id === id) return { ...family, kind: 'family', path: 'SP 800-53 family', text: '' };
    for (const control of family.controls) {
      if (control.id === id) return { ...control, kind: 'control', path: `${family.id} › ${family.title}`, text: control.statement };
      for (const e of control.enhancements) {
        if (e.id === id) return { ...e, kind: 'control', enhancements: [], csf: control.csf, path: `${family.id} › ${control.id} › enhancement`, text: e.statement };
      }
    }
  }
  return null;
}

function rollupRows(subs) {
  const counts = {};
  for (const s of subs) counts[s.status] = (counts[s.status] || 0) + 1;
  return summaryRows(counts);
}

function summaryRows(summary) {
  return ['pass', 'warn', 'fail', 'unknown', 'unmapped']
    .filter(status => summary[status])
    .map(status => ({ status, count: summary[status], icon: STATUS[status].icon, label: STATUS[status].label }));
}
