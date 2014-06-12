'use strict';

var ContextBrowser = require('../lib/cbd');

module.exports = function ($scope, $element, $document, $modal, ModalAssociativeRelationship, InformationObjectService, FullscreenService) {

  // Aliases (not needed, just avoiding the refactor now)
  var scope = $scope;
  var element = $element;


  /**
   * cbd initialization
   */

  var container = element.find('.svg-container');
  var cb = new ContextBrowser(container);
  scope.cb = cb; // So I can share it with the link function...


  /**
   * Fetcher
   */

  var firstPull = true;
  scope.pull = function () {
    var self = this;
    InformationObjectService.getTree(scope.id)
      .then(function (tree) {
        // Empty container
        container.empty();

        // Init context browser
        cb.init(tree, function (u) {
          var node = self.cb.graph.node(u);
          // Hide AIPs
          if (node.level === 'aip') {
            node.hidden = true;
          }
        });

        // Define ranking direction
        scope.rankDir = cb.renderer.rankDir;

        if (firstPull) {
          firstPull = false;
          cb.selectRootNode();
          scope.selectNode(scope.id);
        } else {
          scope.unselectAll();
        }

      }, function (reason) {
        console.error('Error loading tree:', reason);
      });
  };

  scope.$watch('id', function (value) {
    if (value.length < 1) {
      return;
    }
    scope.pull();
  });

  scope.$on('reload', function () {
    scope.pull();
  });


  /**
   * cbd events
   */

  cb.events.on('pin-node', function (attrs) {
    scope.$apply(function (scope) {
      scope.selectNode(attrs.id);
    });
  });

  cb.events.on('unpin-node', function (attrs) {
    scope.$apply(function () {
      scope.unselectNode(attrs.id);
    });
  });

  // TODO: this is not working, see ContextBrowser.prototype.clickSVG
  cb.events.on('click-background', function () {
    scope.$apply(function () {
      scope.unselectAll();
    });
  });

  cb.events.on('click-path', function (attrs) {
    var type;
    try {
      type = attrs.edge.type;
    } catch (e) {}
    if (!angular.isDefined(type)) {
      return false;
    }
    console.log('Edge clicked', type);
  });


  /**
   * cbd rank directions
   */

  scope.rankingDirections = {
    'LR': 'Left-to-right',
    'RL': 'Right-to-left',
    'TB': 'Top-to-bottom',
    'BT': 'Bottom-to-top'
  };

  scope.changeRankingDirection = function (rankDir) {
    cb.changeRankingDirection(rankDir);
    scope.rankDir = rankDir;
  };


  /**
   * cbd misc
   */

  scope.center = function () {
    cb.center();
  };


  /**
   * Node generic actions
   */

  scope.collapseAll = function () {
    cb.graph.predecessors(scope.id).forEach(function (u) {
      cb.collapse(u, true);
    });
  };


  /**
   * Selection
   */

  // TODO: Should I stop using a dictionary? The idea was to use the key to hold
  // the Id, but js won't let me store integers just strings, which is
  // unfortunate for direct access.
  scope.activeNodes = {};

  scope.hasNodeSelected = function () {
    return Object.keys(scope.activeNodes).length === 1;
  };

  scope.hasNodesSelected = function () {
    return Object.keys(scope.activeNodes).length > 1;
  };

  scope.getNumberOfSelectedNodes = function () {
    return Object.keys(scope.activeNodes).length;
  };

  scope.unselectNode = function (id) {
    delete scope.currentNode;
    delete scope.activeNodes[id];
  };

  scope.unselectAll = function () {
    delete scope.currentNode;
    scope.activeNodes = {};
    cb.unselectAll();
  };

  scope.cancelBulkEdit = function () {
    scope.unselectAll();
  };


  /**
   * Dublin Core metadata
   */

  scope.dcCollapsed = true;

  scope.dcFields = [
    'identifier',
    'title',
    'description',
    'names',
    'dates',
    'types',
    'format',
    'source',
    'rights'
  ];

  scope.hasDcField = function (field) {
    return typeof scope.currentNode.data[field] !== 'undefined';
  };

  // TODO: this should be a filter
  scope.renderMetadataValue = function (value) {
    if (angular.isArray(value)) {
      if (value.length && angular.isObject(value[0])) {
        var items = [];
        for (var i in value) {
          items.push(scope.renderMetadataValue(value[i]));
        }
        return items.join(' | ');
      }
      return value.join(', ');
    } else if (angular.isString(value)) {
      return value;
    } else {
      return String(value);
    }
  };


  /**
   * Legend
   */

  scope.showLegend = false;
  scope.toggleLegend = function () {
    scope.showLegend = !scope.showLegend;
  };


  /**
   * Fullscreen mode
   */

  scope.isFullscreen = false;

  scope.toggleFullscreenMode = function () {
    if (scope.isFullscreen) {
      FullscreenService.cancel();
    } else {
      FullscreenService.enable(element.get(0));
    }
    scope.isFullscreen = !scope.isFullscreen;
    cb.center();
  };

  scope.$on('fullscreenchange', function (event, args) {
    scope.$apply(function () {
      if (args.type === 'enter') {
        scope.isFullscreen = true;
      } else {
        scope.isFullscreen = false;
      }
    });
    cb.center();
  });


  /**
   * Maximized mode
   */

  scope.isMaximized = false;

  scope.toggleMaximizedMode = function () {
    scope.isMaximized = !scope.isMaximized;
  };

  scope.$watch('isMaximized', function (oldValue, newValue) {
    if (oldValue !== newValue) {
      cb.center();
    }
  });


  /**
   * Relationships
   */

  scope.showRelationships = true;
  scope.hideRelationships = function () {
    scope.showRelationships = !scope.showRelationships;
    if (scope.showRelationships) {
      cb.showRelationships();
    } else {
      cb.hideRelationships();
    }
  };


  /**
   * Node action
   */

  scope.linkNodes = function (ids) {
    var source = [];
    if (typeof ids === 'number') {
      source.push(ids);
    } else if (typeof ids === 'string' && ids === 'selected') {
      source = source.concat(Object.keys(scope.activeNodes));
    } else {
      throw 'I don\'t know what you are trying to do!';
    }
    // Prompt the user
    scope.cb.promptNodeSelection({
      exclude: source,
      action: function (target) {
        var s = [];
        for (var i = 0; i < source.length; i++) {
          s.push({
            id: source[i],
            label: scope.cb.graph.node(source[i]).label
          });
        }
        var t = { id: target, label: scope.cb.graph.node(target).label };
        ModalAssociativeRelationship.create(s, t).result.then(function (type) {
          scope.cb.createAssociativeRelationship(source, target, type);
        }, function () {
          scope.cb.cancelNodeSelection();
        });
      }
    });
  };

  scope.moveNodes = function (ids) {
    var source = [];
    if (typeof ids === 'number') {
      source.push(ids);
    } else if (typeof ids === 'string' && ids === 'selected') {
      source = source.concat(Object.keys(scope.activeNodes));
    } else {
      throw 'I don\'t know what you are trying to do!';
    }
    // Build a list of descendants
    var exclusionList = [];
    source.forEach(function (v) {
      var descendants = scope.cb.graph.descendants(v, { onlyId: true, andSelf: true });
      for (var i = 0; i < descendants.length; i++) {
        // Remember that we are dealing with strings here (see activeNodes) :(
        var nv = String(descendants[i]);
        // Avoid to add the same id twice
        if (exclusionList.indexOf(nv) === -1) {
          exclusionList.push(nv);
        }
      }
    });
    // Prompt
    scope.cb.promptNodeSelection({
      exclude: exclusionList,
      action: function (target) {
        InformationObjectService.move(source, target).then(function () {
          scope.cb.moveNodes(source, target);
        }, function () {
          scope.cb.cancelNodeSelection();
        });
      }
    });
  };

  scope.deleteNodes = function (ids) {
    var candidates = [];
    if (typeof ids === 'number') {
      candidates.push(ids);
    } else if (typeof ids === 'string' && ids === 'selected') {
      candidates = candidates.concat(Object.keys(scope.activeNodes));
    } else {
      throw 'I don\'t know what you are trying to do!';
    }

    if (candidates.length > 1) {
      throw 'Not supported yet!';
    }

    InformationObjectService.delete(candidates[0]).then(function () {
      scope.cb.deleteNodes(candidates);
      scope.activeNodes = {};
    }, function () {
      throw 'Error deleting ' + candidates[0];
    });
  };


  /**
   * Keyboard shortcuts
   * TODO: I should destroy this when $destroy is triggered and limit its focus
   */

  var onKeyUp = function (event) {
    // Escape shortcut
    if (event.which === 27 && scope.isMaximized) {
      console.log('escape');
      scope.$apply(function () {
        scope.toggleMaximizedMode();
      });
    // Maximized mode (ctrl+f)
    } else if (event.which === 70 && event.ctrlKey && !scope.isFullscreen) {
      scope.$apply(function () {
        scope.toggleMaximizedMode();
      });
    }
  };

  $document.on('keyup', onKeyUp);


  /**
   * Destroy: remove DOM events
   */

  scope.$on('$destroy', function () {
    $document.off('keyup', onKeyUp);
  });

};
