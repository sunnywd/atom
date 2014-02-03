(function () {

  'use strict';

  var Graph = require('./graph');
  var Zoom = require('./zoom');
  var d3 = require('d3');
  var dagreD3 = require('dagre-d3');
  var jQuery = require('jquery');
  var EventEmitter = require('wolfy87-eventemitter');

  function ContextBrowser (container, options) {
    options = options || {};

    this.container = container;

    this.events = new EventEmitter();
  }

  ContextBrowser.prototype.init = function (data) {
    // SVG layout
    this.rootSVG = d3.select(this.container.get(0)).append('svg');
    this.graphSVG = this.rootSVG.append('svg').attr({ 'class': 'graph-attach' });
    this.g = this.graphSVG.append('g');

    this.graph = new Graph(data);
    this.renderer = new dagreD3.Renderer();

    // Customize rendering, maybe class-inheritance later?
    var _drawNodes = this.renderer.drawNodes();
    this.renderer.drawNodes(function (graph, root) {
      var svgNodes = _drawNodes(graph, root);
      svgNodes.each(function (u) {
        var r = d3.select(this).select('rect').attr('class', 'content');

        // Background effect
        d3.select(this)
          .insert('rect', 'rect.content')
          .attr({
            'class': 'background',
            'x': r.attr('x'),
            'y': r.attr('y'),
            'rx': r.attr('rx'),
            'ry': r.attr('ry'),
            'width': r.attr('width'),
            'height': r.attr('height'),
            'style': 'fill: #eee;'
          });

        console.log(u);

      });
      return svgNodes;
    });

    this.draw();

    // Configure zoom
    this.zoom = new Zoom(this.rootSVG);
    this.expand();
    this.setupEvents();
  };

  ContextBrowser.prototype.draw = function () {
    var behavior = dagreD3.layout().nodeSep(20).rankSep(80).rankDir('RL');
    this.layout = this.renderer.layout(behavior).run(this.graph, this.g);
  };

  ContextBrowser.prototype.expand = function () {
    this.rootSVG.attr({
      'width': this.container.width(),
      'height': this.container.height()
    });
  };

  ContextBrowser.prototype.minimizeAfterFullscreen = function () {

  };

  ContextBrowser.prototype.maximizeForFullscreen = function () {

  };

  ContextBrowser.prototype.center = function () {
    this.zoom.reset();
  };

  ContextBrowser.prototype.setupEvents = function () {
    var nodes = this.graphSVG.selectAll('g.node');

    nodes
      .on('click', jQuery.proxy(this.clickNode, null, this));
  };

  ContextBrowser.prototype.showRelationships = function () {
    this.graphSVG.select('.edgePaths, .edgeLabels').style('display', 'inline');
  };

  ContextBrowser.prototype.hideRelationships = function () {
    this.graphSVG.select('.edgePaths, .edgeLabels').style('display', 'none');
  };

  ContextBrowser.prototype.clickNode = function (context, datum, index) {
    var n = d3.select(this);
    if (n.classed('active')) {
      n.classed('active', false);
      context.events.emitEvent('unpin-node', [{ id: datum, index: index }]);
    } else {
      n.classed('active', true);
      context.events.emitEvent('pin-node', [{ id: datum, index: index }]);
    }
  };

  module.exports = ContextBrowser;

})();
