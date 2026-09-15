/* Zoomable sunburst after d3's zoomable sunburst, generic over a framework hierarchy.
   `data` is a nested tree of {id, title, kind, fill, children?, value?, status?, evidenced?, labelClass?, alwaysLabel?}
   (built by csfZoomHierarchy / sp80053ZoomHierarchy in sunburst.js). `options.levels` rings are visible at any
   depth; click an arc to make it the centre and reveal the ring beneath, click the centre to go back up.
   A thin status ring outside the wheel shows status for the outermost visible nodes plus leaves on inner
   rings, so every angle has exactly one status. Requires d3 v7. */

function renderZoomableSunburst(container, data, options, callbacks) {
  const { size, gap } = LAYOUT;  // shared with the static wheel so both line up exactly
  const duration = 750;
  const levels = options.levels || 2;
  // Partition depth y (0 = centre, levels+1 = outer edge) maps piecewise-linearly onto the layout's ring boundaries,
  // so rings keep the static wheel's proportions and still tween smoothly while zooming.
  const points = [0, ...LAYOUT.edges[levels]];
  const radiusAt = y => {
    const t = Math.max(0, Math.min(points.length - 1, y)), k = Math.min(Math.floor(t), points.length - 2);
    return points[k] + (points[k + 1] - points[k]) * (t - k);
  };
  const radius = points[1];  // centre hole
  const status = STATUS;

  const root = d3.hierarchy(data).sum(d => d.value || 0).sort(() => 0);  // keep catalog order
  d3.partition().size([2 * Math.PI, root.height + 1])(root);
  root.each(d => { d.current = d; });

  // Gaps come from the same 2px panel-coloured stroke the static wheel uses (no padAngle), so spacing is identical.
  const arc = d3.arc()
    .startAngle(d => d.x0).endAngle(d => d.x1)
    .innerRadius(d => radiusAt(d.y0)).outerRadius(d => Math.max(radiusAt(d.y0), radiusAt(d.y1) - gap));
  // The status ring hugs the deepest ring that has content at the current zoom (fewer rings remain below a deep node).
  let ringLevels = Math.min(levels, root.height);
  const statusArc = d3.arc()
    .startAngle(d => d.x0).endAngle(d => d.x1)
    .innerRadius(() => radiusAt(ringLevels + 1) + (LAYOUT.statusRing[0] - points[points.length - 1]))
    .outerRadius(() => radiusAt(ringLevels + 1) + (LAYOUT.statusRing[1] - points[points.length - 1]));

  // Visibility predicates take the node (for data/children) and a coordinate set (current or target),
  // because after a zoom the coordinates are plain {x0,x1,y0,y1} objects, not hierarchy nodes.
  const arcVisible = (d, c) => c.y1 <= levels + 1 && c.y0 >= 1 && c.x1 > c.x0;
  let outerLevel = ringLevels;  // ring index whose nodes carry the status ring (updated per zoom)
  const statusVisible = (d, c) => c.x1 > c.x0 && !!d.data.status && c.y0 >= 1 && c.y1 <= levels + 1 && (c.y0 === outerLevel || !d.children);
  const labelVisible = (d, c) => arcVisible(d, c) && (d.data.alwaysLabel ? (c.x1 - c.x0) > 0.012 : (c.y1 - c.y0) * (c.x1 - c.x0) > 0.04);
  // Same placement as the static wheel: upright labels sit at the arc's centre; radial labels start 6px inside the
  // ring's inner edge and read outward, flipped on the left half so they never read upside down.
  const labelTransform = (d, c) => {
    const mid = (c.x0 + c.x1) / 2;
    if (d.data.labelMode === 'upright') {
      const y = (radiusAt(c.y0) + radiusAt(c.y1)) / 2;
      return `translate(${(y * Math.sin(mid)).toFixed(2)},${(-y * Math.cos(mid)).toFixed(2)})`;
    }
    const x = mid * 180 / Math.PI, y = radiusAt(c.y0) + 6;
    return `rotate(${x - 90}) translate(${y},0) rotate(${x < 180 ? 0 : 180})`;
  };
  const labelAnchor = (d, c) => d.data.labelMode === 'upright' ? 'middle' : (((c.x0 + c.x1) / 2) * 180 / Math.PI < 180 ? 'start' : 'end');
  const labelClass = d => `arc-label ${d.data.labelClass || ''}${d.data.evidenced ? ' emphasis' : ''}`;
  const statusOpacity = d => d.data.status === 'unmapped' ? 0.5 : 1;

  container.innerHTML = '';
  const svg = d3.select(container).append('svg')
    .attr('viewBox', [-size / 2, -size / 2, size, size]).attr('role', 'img').attr('aria-label', options.ariaLabel || data.title);

  const path = svg.append('g').selectAll('path').data(root.descendants().slice(1)).join('path')
    .attr('fill', d => d.data.fill).attr('data-id', d => d.data.id).attr('tabindex', 0).attr('role', 'button')
    .attr('aria-label', d => `${d.data.label ?? d.data.id}: ${d.data.title}`)
    .attr('class', d => d.data.evidenced ? 'emphasis' : null)
    .attr('fill-opacity', d => arcVisible(d, d.current) ? 1 : 0)
    .attr('visibility', d => arcVisible(d, d.current) ? 'visible' : 'hidden')
    .attr('pointer-events', d => arcVisible(d, d.current) ? 'auto' : 'none')
    .attr('d', d => arc(d.current));
  path.append('title').text(d => `${d.data.label ?? d.data.id} — ${d.data.title}`);

  const statusPath = svg.append('g').attr('class', 'status-ring').selectAll('path').data(root.descendants().slice(1)).join('path')
    .attr('class', 'status-arc')
    .attr('fill', d => (status[d.data.status] || status.unmapped).color)
    .attr('fill-opacity', d => statusVisible(d, d.current) ? statusOpacity(d) : 0)
    .attr('visibility', d => statusVisible(d, d.current) ? 'visible' : 'hidden')
    .attr('d', d => statusArc(d.current));

  const label = svg.append('g').attr('pointer-events', 'none').selectAll('text')
    .data(root.descendants().slice(1)).join('text')
    .attr('class', labelClass).attr('dy', '0.35em').attr('text-anchor', d => labelAnchor(d, d.current))
    .attr('fill-opacity', d => +labelVisible(d, d.current))
    .attr('visibility', d => labelVisible(d, d.current) ? 'visible' : 'hidden')
    .attr('transform', d => labelTransform(d, d.current))
    .text(d => d.data.label ?? d.data.id);

  const centre = svg.append('g').attr('class', 'centre');
  const parent = centre.append('circle').datum(root).attr('r', radius).attr('fill', 'none').attr('pointer-events', 'all')
    .attr('cursor', 'pointer').on('click', (event, p) => zoomTo(p.parent || root));
  const centreTitle = centre.append('text').attr('class', 'center').attr('text-anchor', 'middle').attr('dy', '-0.3em');
  const centreHint = centre.append('text').attr('class', 'center').attr('text-anchor', 'middle').attr('dy', '1.1em');
  const setCentre = p => {
    const [title, hint] = options.centre(p === root ? null : p.data, p === root ? null : p.depth);
    centreTitle.text(title); centreHint.text(hint);
  };
  setCentre(root);

  path.filter(d => d.children).attr('cursor', 'pointer');
  path.on('click', (event, p) => { if (p.children) zoomTo(p); else callbacks.onPin?.(p.data.id); })
      .on('keydown', (event, p) => { if (event.key === 'Enter') { event.preventDefault(); p.children ? zoomTo(p) : callbacks.onPin?.(p.data.id); } })
      .on('mouseover', (event, d) => callbacks.onHover?.(d.data.id))
      .on('focus', (event, d) => callbacks.onHover?.(d.data.id));
  svg.on('mouseleave', () => callbacks.onLeave?.());

  function zoomTo(p, instant = false) {
    parent.datum(p);
    setCentre(p);
    callbacks.onZoom?.(p === root ? null : p.data.id);
    root.each(d => { d.target = {
      x0: Math.max(0, Math.min(1, (d.x0 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
      x1: Math.max(0, Math.min(1, (d.x1 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
      y0: Math.max(0, d.y0 - p.depth),
      y1: Math.max(0, d.y1 - p.depth),
    }; });
    outerLevel = Math.min(levels, root.height - p.depth);
    if (instant) {  // deep links land directly: no transition, no rAF dependency
      ringLevels = outerLevel;
      root.each(d => { d.current = d.target; });
      path.attr('fill-opacity', d => arcVisible(d, d.current) ? 1 : 0).attr('visibility', d => arcVisible(d, d.current) ? 'visible' : 'hidden')
          .attr('pointer-events', d => arcVisible(d, d.current) ? 'auto' : 'none').attr('d', d => arc(d.current));
      statusPath.attr('fill-opacity', d => statusVisible(d, d.current) ? statusOpacity(d) : 0)
          .attr('visibility', d => statusVisible(d, d.current) ? 'visible' : 'hidden').attr('d', d => statusArc(d.current));
      label.attr('fill-opacity', d => +labelVisible(d, d.current)).attr('visibility', d => labelVisible(d, d.current) ? 'visible' : 'hidden')
          .attr('text-anchor', d => labelAnchor(d, d.current)).attr('transform', d => labelTransform(d, d.current));
      return;
    }
    const t = svg.transition().duration(duration)
      .tween('status-radius', () => { const i = d3.interpolate(ringLevels, outerLevel); return time => { ringLevels = i(time); }; });
    const reveal = visible => function (d) { if (visible(d, d.target)) this.setAttribute('visibility', 'visible'); };
    const settle = visible => function (d) { this.setAttribute('visibility', visible(d, d.target) ? 'visible' : 'hidden'); };
    path.transition(t)
      .tween('data', d => { const i = d3.interpolate(d.current, d.target); return time => { d.current = i(time); }; })
      .filter(function (d) { return +this.getAttribute('fill-opacity') || arcVisible(d, d.target); })
      .on('start', reveal(arcVisible)).on('end', settle(arcVisible))
      .attr('fill-opacity', d => arcVisible(d, d.target) ? 1 : 0)
      .attr('pointer-events', d => arcVisible(d, d.target) ? 'auto' : 'none')
      .attrTween('d', d => () => arc(d.current));
    statusPath.transition(t)
      .filter(function (d) { return +this.getAttribute('fill-opacity') || statusVisible(d, d.target); })
      .on('start', reveal(statusVisible)).on('end', settle(statusVisible))
      .attr('fill-opacity', d => statusVisible(d, d.target) ? statusOpacity(d) : 0)
      .attrTween('d', d => () => statusArc(d.current));
    label.filter(function (d) { return +this.getAttribute('fill-opacity') || labelVisible(d, d.target); }).transition(t)
      .on('start', reveal(labelVisible)).on('end', settle(labelVisible))
      .attr('fill-opacity', d => +labelVisible(d, d.target))
      .attr('text-anchor', d => labelAnchor(d, d.target))
      .attrTween('transform', d => () => labelTransform(d, d.current));
  }

  return { zoomTo, root };
}
